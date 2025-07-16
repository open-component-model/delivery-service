#!/usr/bin/env python3

import atexit
import collections.abc
import dataclasses
import datetime
import enum
import logging

import dacite
import requests
import requests.adapters
import urllib3.util.retry

import ci.log
import cnudie.retrieve
import delivery.client
import ocm

import k8s.logging
import lookups
import odg.extensions_cfg
import odg.findings
import odg.model
import odg.util
import paths
import util


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()


class GitHubSecretLocationType(enum.StrEnum):
    COMMIT = 'commit'
    WIKI_COMMIT = 'wiki_commit'
    UNKNOWN = 'unknown'


@dataclasses.dataclass
class SecretLocation:
    location_type: GitHubSecretLocationType
    path: str | None = None
    line: int | None = None

    @classmethod
    def from_dict(cls, location: dict) -> 'SecretLocation':
        try:
            location_type = GitHubSecretLocationType(location.get('type'))
        except ValueError:
            location_type = GitHubSecretLocationType.UNKNOWN

        details = location.get('details', {})
        return cls(
            location_type=location_type,
            path=details.get('path'),
            line=details.get('start_line'),
        )


@dataclasses.dataclass
class SecretAlert:
    html_url: str | None
    secret_type: str | None
    secret: str | None
    secret_type_display_name: str | None
    resolution: str | None
    locations_url: str | None
    url: str | None


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
    # setup session with retry configuration
    session = requests.Session()
    retries = urllib3.util.retry.Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=['GET'],
    )
    session.mount('https://', requests.adapters.HTTPAdapter(max_retries=retries))

    try:
        response = session.get(
            url,
            headers={
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github+json',
            },
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f'GitHub API request failed for {url}: {e}')
        return None


def get_secret_alerts(
    github_hostname: str,
    org: str,
) -> collections.abc.Generator[SecretAlert]:
    '''
    Fetch open secret scanning alerts using authenticated GitHub client.
    '''
    url = f'https://{github_hostname}/api/v3/orgs/{org}/secret-scanning/alerts?state=open'
    result = github_api_request(url)
    alerts_raw = result if isinstance(result, list) else []

    return (
        dacite.from_dict(SecretAlert, alert)
        for alert in alerts_raw
    )


def get_secret_location(
    location_url: str,
) -> SecretLocation:
    result = github_api_request(location_url)
    if not result or not isinstance(result, list):
        return SecretLocation(
            location_type=GitHubSecretLocationType.UNKNOWN,
        )

    for loc in result:
        secret_location = SecretLocation.from_dict(loc)
        if secret_location.location_type in (
            GitHubSecretLocationType.COMMIT,
            GitHubSecretLocationType.WIKI_COMMIT,
        ):
            return secret_location

    return SecretLocation(
        location_type=GitHubSecretLocationType.UNKNOWN,
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

    categorisation = odg.findings.categorise_finding(
        finding_cfg=ghas_finding_cfg,
        finding_property=ghas_finding.resolution,
    )

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
                alerts = get_secret_alerts(
                    github_hostname=github_instance.hostname,
                    org=org,
                )

                for alert in alerts:
                    location = get_secret_location(
                        location_url=alert.locations_url,
                    )

                    categorisation = odg.findings.categorise_finding(
                        finding_cfg=ghas_finding_cfg,
                        finding_property=alert.resolution
                    )
                    if not categorisation:
                        continue

                    yield odg.model.GitHubSecretFinding(
                        severity=categorisation.id,
                        html_url=alert.html_url,
                        secret_type=alert.secret_type,
                        secret=alert.secret,
                        secret_type_display_name=alert.secret_type_display_name,
                        resolution=alert.resolution,
                        path=location.path,
                        line=location.line,
                        location_type=location.location_type.value,
                        url=alert.url,
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

    # XXX we still need to discuss this fallback case
    return odg.model.ComponentArtefactId(
        component_name='ghas-fallback-component',
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

    now = datetime.datetime.now(tz=datetime.timezone.utc)

    all_existing_metadata = [
        odg.model.ArtefactMetadata.from_dict(raw)
        for raw in delivery_client.query_metadata(
            type=odg.model.Datatype.GHAS_FINDING,
        )
    ]

    for finding in create_ghas_findings(
        ghas_config=ghas_config,
        ghas_finding_cfg=ghas_finding_cfg
    ):
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
            ghas_finding_cfg=ghas_finding_cfg,
        ))

        all_metadata.extend(metadata)
        all_metadata_keys.update([metadatum.key for metadatum in metadata])

    all_stale_metadata = [
        metadatum for metadatum in all_existing_metadata
        if metadatum.key not in all_metadata_keys
    ]

    for stale_finding in all_stale_metadata:
        html_url = stale_finding.data.get('html_url')
        api_url = stale_finding.data.get('url')

        stale_alert_data = github_api_request(url=api_url)
        resolution =  stale_alert_data.get('resolution')

        rescore_categorisation = odg.findings.categorise_finding(
            finding_cfg=ghas_finding_cfg,
            finding_property=resolution,
        )

        rescored_metadata = odg.model.ArtefactMetadata(
            artefact=stale_finding.artefact,
            meta=odg.model.Metadata(
                datasource=stale_finding.meta.datasource,
                type=odg.model.Datatype.RESCORING,
                creation_date=now,
                last_update=now,
            ),
            data=odg.model.CustomRescoring(
                finding=odg.model.RescoreGitHubSecretFinding(
                    html_url=html_url,
                    resolution=resolution,
                ),
                referenced_type=odg.model.Datatype.GHAS_FINDING,
                severity=rescore_categorisation.id,
                user=odg.model.User(
                    username='ghas-extension-auto-rescoring',
                    type='ghas-extension-user',
                ),
                comment='Automatically rescored due to closed GitHub alert.',
                allowed_processing_time=rescore_categorisation.allowed_processing_time_raw,
            ),
        )
        all_metadata.append(rescored_metadata)

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
