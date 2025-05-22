#!/usr/bin/env python3
import argparse
import atexit
import collections.abc
import datetime
import logging
import os
import sys
import github3
import urllib.parse

import ci.log
import cnudie.retrieve
import delivery.client
import delivery.client
import odg.model
import secret_mgmt

import ctx_util
import k8s.util
import k8s.logging
import lookups
import odg.extensions_cfg
import odg.findings
import paths


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()

own_dir = os.path.abspath(os.path.dirname(__file__))
default_cache_dir = os.path.join(own_dir, '.cache')

ready_to_terminate = True
wants_to_terminate = False


def handle_termination_signal(*args):
    global wants_to_terminate

    # also terminate if > 1 termination signals were received
    if ready_to_terminate or wants_to_terminate:
        sys.exit(0)

    # grace period to finish current scan is defined in the replica set
    # after this period, the scan will be terminated anyways by k8s means
    logger.info('termination signal received, will try to finish current scan and then exit')
    wants_to_terminate = True


def get_secret_alerts(
    github_client: github3.GitHub,
    org: str
) -> collections.abc.Iterable[dict]:
    """Fetch open secret scanning alerts using authenticated GitHub client."""
    try:
        org_obj = github_client.organization(org)
        response = org_obj._session.get(f"{org_obj.url}/secret-scanning/alerts?state=open")
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"Failed to fetch GitHub secret scanning alerts: {e}")
        return []

def get_secret_location(
    github_client: github3.GitHub, 
    location_url: str,
) -> dict:
    """Fetch location details (path, line) for a secret alert using GitHub client."""
    try:
        response = github_client._session.get(location_url)
        response.raise_for_status()
        locations = response.json()

        if not locations or not isinstance(locations, list):
            return {"path": "", "line": 0}

        location = locations[0]
        loc_type = location.get("type", "")
        details = location.get("details", {})

        if loc_type in {"commit", "wiki_commit"}:
            return {
                "path": details.get("path", loc_type),
                "line": details.get("start_line", 0),
            }

    except Exception as e:
        logger.error(f"Failed to fetch alert locations: {e}")
        return {"path": "", "line": 0}


def as_artefact_metadata(
    artefact: odg.model.ComponentArtefactId,
    ghas_finding: collections.abc.Iterable[odg.model.GitHubSecretFinding],
) -> collections.abc.Generator[odg.model.ArtefactMetadata, None, None]:
    """Transform GitHub secret scanning findings into ArtefactMetadata."""
    today = datetime.date.today()
    now = datetime.datetime.now(tz=datetime.timezone.utc)

    # Yield scan info metadata
    yield odg.model.ArtefactMetadata(
        artefact=artefact,
        meta=odg.model.Metadata(
            datasource=odg.model.Datasource.GHAS,
            type=odg.model.Datatype.ARTEFACT_SCAN_INFO,
            creation_date=now,
            last_update=now,
        ),
        data={},
    )

    # Yield findings metadata
    meta = odg.model.Metadata(
        datasource=odg.model.Datasource.GHAS,
        type=odg.findings.FindingType.GHAS,
        creation_date=now,
        last_update=now,
    )

    yield odg.model.ArtefactMetadata(
        artefact=artefact,
        meta=meta,
        data=ghas_finding,
        discovery_date=today,
    )

def create_ghas_findings(
    ghas_config: odg.extensions_cfg.GHASConfig,
    secret_factory: ctx_util.SecretFactory,
) -> list[odg.model.GitHubSecretFinding]:
    ghas_findings = []

    for github in ghas_config.githubs:
        for org in github.orgs:
            org_url = f'{github.github}/{org}'
            logger.info(f"Fetching GHAS alerts for org '{org}' from {org_url}...")

            github_api = lookups.github_api_lookup(secret_factory)
            github_client = github_api(org_url)

            if not github_client:
                logger.error(f"Could not authenticate Github API for {github}")
                continue

            try:
                alerts = get_secret_alerts(github_client, org)
                for alert in alerts:
                    locations = get_secret_location(github_client, alert.get("locations_url", ""))
                    ghas_findings.append(
                        odg.model.GitHubSecretFinding(
                            html_url=alert.get("html_url"),
                            secret_type=alert.get("secret_type", ""),
                            secret="REDACTED",
                            secret_type_display_name=alert.get("secret_type_display_name", ""),
                            path=locations["path"],
                            line=locations["line"],
                        )
                    )
            except Exception as e:
                logger.error(f"Error fetching GHAS alerts for org '{org}': {str(e)}")
    return ghas_findings
    
def build_artefact_from_finding(
    finding: odg.model.GitHubSecretFinding,
) -> odg.model.ComponentArtefactId:
    """Extract component info from finding and return a ComponentArtefactId."""
    try:
        parsed = urllib.parse.urlparse(finding.html_url)
        path_parts = parsed.path.strip("/").split("/")
        if len(path_parts) < 2:
            raise ValueError(f"Invalid HTML URL format: {finding.html_url}")

        org, repo = path_parts[0], path_parts[1]
        component_name = f"github.com/{org}/{repo}"

        return odg.model.ComponentArtefactId(
            component_name=component_name,
            component_version="main",  # Use real version if available
            artefact=odg.model.Artefact(
                artefact_name="main-source",
                artefact_type="git",
                artefact_version="main",
                artefact_extra_id={},
            ),
            artefact_kind=odg.model.ArtefactKind.SOURCE,
            references=[],
        )
    except Exception as e:
        logger.warning(f"Failed to extract artefact from finding URL '{finding.html_url}': {e}")
        raise

def scan(
    ghas_config: odg.extensions_cfg.GHASConfig,
    ghas_finding_cfg: odg.findings.Finding,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
    secret_factory: secret_mgmt.SecretFactory,
):
    logger.info('Starting GHAS scan...')

    retrieve_ghas_findings = ghas_finding_cfg and ghas_finding_cfg.matches(artefact)

    if not retrieve_ghas_findings:
        logger.info('ghas findings are filtered out for this artefact, skipping...')
        return

    if not ghas_config.is_supported(artefact_kind=artefact.artefact_kind):
        if ghas_config.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(
                f'{artefact.artefact_kind} is not supported by the GHAS extension, maybe the filter '
                'configurations have to be adjusted to filter out this artefact kind'
            )
        return

    resource_node = k8s.util.get_ocm_node(
        component_descriptor_lookup=component_descriptor_lookup,
        artefact=artefact,
    )
    access_type = resource_node.resource.access.type
    resource_type = resource_node.resource.type

    if not ghas_config.is_supported(
        access_type=access_type,
        artefact_type=resource_type,
    ):
        if ghas_config.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(
                f'{access_type=} with {resource_type=} is not supported by the ghas extension, '
                'maybe the filter configurations have to be adjusted to filter out these types'
            )
        return

    ghas_findings = create_ghas_findings(ghas_config, secret_factory)

    artefact_metadata = []

    for finding in ghas_findings:
        try:
            artefact = build_artefact_from_finding(finding)
            artefact_metadata.extend(as_artefact_metadata(artefact, finding))
        except Exception:
            continue  # Already logged in helper

    delivery_client.update_metadata(data=artefact_metadata)
    logger.info("Finished GHAS scan.")

def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--k8s-cfg-name',
        help='kubernetes cluster to use',
        default=os.environ.get('K8S_CFG_NAME'),
    )
    parser.add_argument(
        '--kubeconfig',
        help='''
            specify kubernetes cluster to interact with extensions (and logs); if both
            `k8s-cfg-name` and `kubeconfig` are set, `k8s-cfg-name` takes precedence
        ''',
    )
    parser.add_argument(
        '--k8s-namespace',
        help='specify kubernetes cluster namespace to interact with',
        default=os.environ.get('K8S_TARGET_NAMESPACE'),
    )
    parser.add_argument(
        '--extensions-cfg-path',
        help='path to the `extensions_cfg.yaml` file that should be used',
    )
    parser.add_argument(
        '--findings-cfg-path',
        help='path to the `findings.yaml` file that should be used',
    )
    parser.add_argument(
        '--delivery-service-url',
        help='''
            specify the url of the delivery service to use instead of the one configured in the
            respective extensions configuration
        ''',
    )
    parser.add_argument('--cache-dir', default=default_cache_dir)

    parsed_arguments = parser.parse_args()

    if not parsed_arguments.k8s_namespace:
        raise ValueError(
            'k8s namespace must be set, either via argument "--k8s-namespace" '
            'or via environment variable "K8S_TARGET_NAMESPACE"'
        )

    return parsed_arguments


def main():

    parsed_arguments = parse_args()
    namespace = parsed_arguments.k8s_namespace
    delivery_service_url = parsed_arguments.delivery_service_url

    secret_factory = ctx_util.secret_factory()

    if parsed_arguments.k8s_cfg_name:
        kubernetes_cfg = secret_factory.kubernetes(parsed_arguments.k8s_cfg_name)
        kubernetes_api = k8s.util.kubernetes_api(kubernetes_cfg=kubernetes_cfg)
    else:
        kubernetes_api = k8s.util.kubernetes_api(
            kubeconfig_path=parsed_arguments.kubeconfig,
        )

    k8s.logging.init_logging_thread(
        service=odg.extensions_cfg.Services.GHAS,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )
    atexit.register(
        k8s.logging.log_to_crd,
        service=odg.extensions_cfg.Services.GHAS,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    if not (extensions_cfg_path := parsed_arguments.extensions_cfg_path):
        extensions_cfg_path = paths.extensions_cfg_path()

    extensions_cfg = odg.extensions_cfg.ExtensionsConfiguration.from_file(extensions_cfg_path)
    ghas_config = extensions_cfg.ghas

    if not (findings_cfg_path := parsed_arguments.findings_cfg_path):
        findings_cfg_path = paths.findings_cfg_path()

    ghas_finding_config = odg.findings.Finding.from_file(
        path=findings_cfg_path,
        finding_type=odg.findings.FindingType.GHAS,
    )

    if not ghas_finding_config:
        logger.info('GHAS findings are disabled, exiting...')
        return

    if not delivery_service_url:
        delivery_service_url = ghas_config.delivery_service_url

    delivery_client = delivery.client.DeliveryServiceClient(
        routes=delivery.client.DeliveryServiceRoutes(
            base_url=delivery_service_url,
        ),
        auth_token_lookup=lookups.github_auth_token_lookup,
    )

    component_descriptor_lookup = lookups.init_component_descriptor_lookup(
        cache_dir=parsed_arguments.cache_dir,
        delivery_client=delivery_client,
    )

    scan(
        ghas_config=ghas_config,
        ghas_finding_cfg=ghas_finding_config,
        component_descriptor_lookup=component_descriptor_lookup,
        delivery_client=delivery_client,
        secret_factory=secret_factory,
    )

if __name__ == '__main__':
    main()
