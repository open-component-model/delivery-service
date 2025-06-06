#!/usr/bin/env python3
import atexit
import collections.abc
import dataclasses
import datetime
import enum
import logging
import os
import requests

import ci.log
import cnudie.retrieve
import delivery.client
import ocm

import k8s.logging
import lookups
import odg.extensions_cfg
import odg.findings
import odg.model
import paths
import odg.util
import util

logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()

own_dir = os.path.abspath(os.path.dirname(__file__))
default_cache_dir = os.path.join(own_dir, '.cache')


class GitHubSecretLocationType(enum.StrEnum):
    COMMIT = 'commit'
    WIKI_COMMIT = 'wiki_commit'
    UNKNOWN = 'unknown'


@dataclasses.dataclass
class SecretLocation:
    location_type: GitHubSecretLocationType
    path: str | None = None
    line: int | None = None


def github_api_request(
    url: str,
) -> list | dict | None:
    hostname = util.urlparse(url).hostname
    path_parts = util.urlparse(url).path.strip('/').split('/')
    if len(path_parts) < 2:
        logger.error(f'Cannot determine repo/org from URL: {url}')
        return None

    org = path_parts[3]
    repo_url = f'{hostname}/{org}'

    token = lookups.github_auth_token_lookup(repo_url)
    if not token:
        logger.error(f'No GitHub token found for {repo_url}')
        return None

    try:
        response = requests.get(
            url,
            headers={
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github+json',
            },
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f'GitHub API request failed for {url}: {e}')
        return None


def get_secret_alerts(
    github_hostname: str,
    org: str,
) -> list[dict]:
    '''
    Fetch open secret scanning alerts using authenticated GitHub client.
    '''
    url = f'https://{github_hostname}/api/v3/orgs/{org}/secret-scanning/alerts?state=open'
    result = github_api_request(url)
    return result if isinstance(result, list) else []


def get_secret_location(
    location_url: str,
) -> SecretLocation:
    result = github_api_request(location_url)
    if not result or not isinstance(result, list):
        return SecretLocation(location_type=GitHubSecretLocationType.UNKNOWN)

    for loc in result:
        loc_type = loc.get('type', '')
        if loc_type not in (GitHubSecretLocationType.COMMIT, GitHubSecretLocationType.WIKI_COMMIT):
            continue
        details = loc.get('details', {})
        return SecretLocation(
            path=details.get('path'),
            line=details.get('start_line'),
            location_type=GitHubSecretLocationType(loc_type),
        )

    return SecretLocation(location_type=GitHubSecretLocationType.UNKNOWN)


def categorise_ghas_finding(
    finding_cfg: odg.findings.Finding,
    html_url: str,
) -> odg.findings.FindingCategorisation | None:
    '''
    Categorise a GHAS finding based on its HTML URL and the configured finding rules.
    Returns the categorisation or None if no match is found.
    '''
    return odg.findings.categorise_finding(
        finding_cfg=finding_cfg,
        finding_property=html_url,
    )


def as_artefact_metadata(
    artefact: odg.model.ComponentArtefactId,
    ghas_finding: odg.model.GitHubSecretFinding,
    ghas_finding_cfg: odg.findings.Finding,
) -> collections.abc.Generator[odg.model.ArtefactMetadata, None, None]:
    '''
    Transform GitHub secret scanning findings into ArtefactMetadata.
    '''
    today = datetime.date.today()
    now = datetime.datetime.now(tz=datetime.timezone.utc)

    categorisation = categorise_ghas_finding(
        finding_cfg=ghas_finding_cfg,
        html_url=ghas_finding.html_url,
    )

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

    # Yield finding metadata
    yield odg.model.ArtefactMetadata(
        artefact=artefact,
        meta=odg.model.Metadata(
            datasource=odg.model.Datasource.GHAS,
            type=odg.model.Datatype.GHAS_FINDING,
            creation_date=now,
            last_update=now,
            ),
        data=ghas_finding,
        discovery_date=today,
        allowed_processing_time=categorisation.allowed_processing_time_raw,
    )


def create_ghas_findings(
    ghas_config: odg.extensions_cfg.GHASConfig,
    ghas_finding_cfg: odg.findings.Finding,
) -> collections.abc.Generator[odg.model.GitHubSecretFinding, None, None]:
    for github_instance in ghas_config.github_instances:
        for org in github_instance.orgs:
            try:
                alerts = get_secret_alerts(github_hostname=github_instance.hostname, org=org)
                for alert in alerts:
                    location_url = alert.get('locations_url', '')
                    locations = get_secret_location(location_url=location_url)

                    categorisation = categorise_ghas_finding(
                        finding_cfg=ghas_finding_cfg,
                        html_url=alert.get('html_url', '')
                    )
                    if not categorisation:
                        continue

                    yield odg.model.GitHubSecretFinding(
                        severity=categorisation.id,
                        html_url=alert.get('html_url'),
                        secret_type=alert.get('secret_type', ''),
                        secret=alert.get('secret', ''),
                        secret_type_display_name=alert.get('secret_type_display_name', ''),
                        path=locations.path,
                        line=locations.line,
                        location_type=locations.location_type.value,
                    )
            except Exception as e:
                logger.error(f"Error fetching GHAS alerts for org '{org}': {str(e)}")


def build_artefact_from_finding(
    finding: odg.model.GitHubSecretFinding,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_service_client: delivery.client.DeliveryServiceClient,
) -> odg.model.ComponentArtefactId:
    '''
    Extract component info from finding and return a ComponentArtefactId.
    '''
    parsed_url = util.urlparse(finding.html_url)

    org, repo = parsed_url.path.strip('/').split('/')[:2]
    possible_component_name = f'{parsed_url.hostname}/{org}/{repo}'

    component_versions = delivery_service_client.greatest_component_versions(
        component_name=possible_component_name,
        max_versions=1,
    )

    # if there is at least one version detected, it is a 'real' OCM component
    if component_versions:
        component_version = component_versions[0]
        component_descriptor = component_descriptor_lookup(ocm.ComponentIdentity(
            name=possible_component_name,
            version=component_version,
        ))

        source = ocm.util.main_source(
            component=component_descriptor,
            no_source_ok=False,
        )

        return odg.model.ComponentArtefactId(
            component_name=possible_component_name,
            artefact_kind=odg.model.ArtefactKind.SOURCE,
            artefact=odg.model.LocalArtefactId(
                artefact_name=source.name,
                artefact_type=source.type,
            )
        )

    # we still need to discuss this fallback case
    return odg.model.ComponentArtefactId(
        component_name='my-umbrella-component-name',
        artefact_kind=odg.model.ArtefactKind.SOURCE,
        artefact=odg.model.LocalArtefactId(
            artefact_name='main-source',
            artefact_type='git',
        ),
    )


def scan(
    ghas_config: odg.extensions_cfg.GHASConfig,
    ghas_finding_cfg: odg.findings.Finding,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
):
    logger.info('Starting GHAS scan...')

    all_metadata = []
    all_metadata_keys = set()
    all_existing_metadata = []

    for finding in create_ghas_findings(ghas_config=ghas_config, ghas_finding_cfg=ghas_finding_cfg):
        artefact = build_artefact_from_finding(
            finding=finding,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_service_client=delivery_client,
        )

        if not ghas_finding_cfg.matches(artefact):
            continue

        if not ghas_config.is_supported(artefact_kind=artefact.artefact_kind):
            if ghas_config.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
                raise TypeError(
                    f'{artefact.artefact_kind} is not supported, maybe the filter '
                    'configurations have to be adjusted to filter out this artefact kind'
                )
            continue

        metadata = list(as_artefact_metadata(
            artefact=artefact,
            ghas_finding=finding,
            ghas_finding_cfg=ghas_finding_cfg))

        all_metadata.extend(metadata)
        all_metadata_keys.update([metadatum.key for metadatum in metadata])

        all_existing_metadata.extend((
            odg.model.ArtefactMetadata.from_dict(raw)
            for raw in delivery_client.query_metadata(
                artefacts=(artefact,),
                type=odg.model.Datatype.GHAS_FINDING,
            )
            if raw['meta']['datasource'] == odg.model.Datasource.GHAS
        ))

    # Delete stale metadata (if there is any)
    all_stale_metadata = [
        metadatum for metadatum in all_existing_metadata
        if metadatum.key not in all_metadata_keys
    ]
    if all_stale_metadata:
        delivery_client.delete_metadata(data=all_stale_metadata)
        logger.info(f'Deleted {len(all_stale_metadata)} obsolete GHAS metadata entries.')

    # Deliver new metadata
    if all_metadata:
        delivery_client.update_metadata(data=all_metadata)
        logger.info(f'GHAS metadata successfully delivered: {len(all_metadata)} entries.')
    else:
        logger.info('No artefact metadata was created from findings.')

    logger.info('Finished GHAS scan.')


def main():

    parsed_arguments = odg.util.parse_args()

    namespace = parsed_arguments.k8s_namespace
    delivery_service_url = parsed_arguments.delivery_service_url
    kubernetes_api = odg.util.kubernetes_api(parsed_arguments)

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
        finding_type=odg.model.Datatype.GHAS_FINDING,
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
    )


if __name__ == '__main__':
    main()
