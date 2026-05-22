import collections.abc
import datetime

import cnudie.retrieve
import ocm
import ocm.iter

import lookups
import odg.extensions_cfg
import odg.model
import odg.util
import odg_client
import paths
import rescore.utility
import util


def filter_rescorings_before_release_date(
    finding: odg.model.ArtefactMetadata,
    rescorings: list[odg.model.ArtefactMetadata],
    release_date: datetime.datetime,
) -> list[odg.model.ArtefactMetadata]:
    filtered_rescorings = []
    for rescoring in rescore.utility.rescorings_for_finding_by_specificity(
        finding=finding,
        rescorings=rescorings,
    ):
        if rescoring.meta.creation_date < release_date:
            filtered_rescorings.append(rescoring)

    return sorted(
        filtered_rescorings,
        key=lambda rescoring: rescoring.meta.creation_date,
    )


def iter_policy_violations(
    finding: odg.model.ArtefactMetadata,
    sorted_rescorings: list[odg.model.ArtefactMetadata],
    release_date: datetime.datetime,
) -> collections.abc.Generator[odg.model.SlaViolation, None, None]:
    allowed_time = util.convert_to_timedelta(finding.allowed_processing_time)
    deadline = finding.discovery_date + allowed_time

    for rescoring in sorted_rescorings:
        if deadline and rescoring.meta.creation_date.date() > deadline:
            yield odg.model.SlaViolation(
                finding=odg.model.RescoringVulnerabilityFinding(
                    package_name=finding.data.package_name,
                    cve=finding.data.cve,
                ),
                referenced_type=odg.model.Datatype.VULNERABILITY_FINDING,
                artefact=finding.artefact,
            )
        if rescoring.data.due_date:
            deadline = rescoring.data.due_date
        elif rescoring.data.allowed_processing_time is None:
            deadline = None
        else:
            allowed_time = util.convert_to_timedelta(rescoring.data.allowed_processing_time)
            deadline = finding.discovery_date + allowed_time

    if deadline and deadline < release_date.date():
        yield odg.model.SlaViolation(
            finding=odg.model.RescoringVulnerabilityFinding(
                package_name=finding.data.package_name,
                cve=finding.data.cve,
            ),
            referenced_type=odg.model.Datatype.VULNERABILITY_FINDING,
            artefact=finding.artefact,
        )


def iter_version_sla_violations(
    findings: list[odg.model.ArtefactMetadata],
    rescorings: list[odg.model.ArtefactMetadata],
    release_date: datetime.datetime,
) -> collections.abc.Generator[odg.model.SlaViolation, None, None]:
    for finding in findings:
        if finding.meta.creation_date > release_date:
            continue

        if not finding.discovery_date:
            raise ValueError(f'finding is missing discovery_date: {finding}')

        if not finding.allowed_processing_time:
            continue

        sorted_rescorings = filter_rescorings_before_release_date(finding, rescorings, release_date)
        violations = iter_policy_violations(finding, sorted_rescorings, release_date)
        yield from violations


def main():
    parsed_arguments = odg.util.parse_args(
        arguments=(
            odg.util.Arguments.EXTENSIONS_CFG_PATH,
            odg.util.Arguments.DELIVERY_SERVICE_URL,
        ),
    )

    if not (extensions_cfg_path := parsed_arguments.extensions_cfg_path):
        extensions_cfg_path = paths.extensions_cfg_path()

    extensions_cfg = odg.extensions_cfg.ExtensionsConfiguration.from_file(extensions_cfg_path)
    cfg = extensions_cfg.sla_violations

    # Guard: skip when the extension is missing or disabled in extensions_cfg.yaml.
    # Commented out for now since the deployment story for toggling enabled=True is not finalised.
    # if not cfg or not cfg.enabled:
    #     return

    if not (delivery_service_url := parsed_arguments.delivery_service_url):
        delivery_service_url = cfg.delivery_service_url

    delivery_service_client = odg_client.DeliveryServiceClient(
        routes=odg_client.DeliveryServiceRoutes(
            base_url=delivery_service_url,
        ),
        auth_token_lookup=lookups.github_auth_token_lookup,
    )

    ocm_repository_lookup = lookups.init_ocm_repository_lookup()

    ocm_lookup = cnudie.retrieve.composite_component_descriptor_lookup(
        lookups=[
            cnudie.retrieve.in_memory_cache_component_descriptor_lookup(
                ocm_repository_lookup=ocm_repository_lookup,
            ),
            cnudie.retrieve.delivery_service_component_descriptor_lookup(
                ocm_repository_lookup=ocm_repository_lookup,
                delivery_client=delivery_service_client,
            ),
        ],
        ocm_repository_lookup=ocm_repository_lookup,
    )

    versions_by_component: list[tuple[str, str, ocm.OcmRepository | None]] = []
    for component in cfg.components:
        if resolved_version := component.resolved_version:
            versions = [resolved_version]
        else:
            time_range = component.time_range
            versions = delivery_service_client.greatest_component_versions(
                component_name=component.component_name,
                max_versions=component.max_versions_limit,
                ocm_repo=component.ocm_repo,
                start_date=time_range.start_date if time_range else None,
                end_date=time_range.end_date if time_range else None,
            )
        for version in versions:
            versions_by_component.append((component.component_name, version, component.ocm_repo))

    root_component_identities = [
        ocm.ComponentIdentity(name, version) for name, version, _ in versions_by_component
    ]
    existing_sla_raw = delivery_service_client.query_metadata(
        components=root_component_identities,
        type=odg.model.Datatype.SLA_VIOLATION,
    )
    already_processed = {
        (md['artefact']['component_name'], md['artefact']['component_version'])
        for md in existing_sla_raw
    }

    sla_violations = []

    for component_name, version, ocm_repo in versions_by_component:
        if (component_name, version) in already_processed:
            continue

        component_ocm_repository_lookup = lookups.extended_ocm_repository_lookup(ocm_repo)

        root_descriptor = ocm_lookup(
            f'{component_name}:{version}',
            ocm_repository_lookup=component_ocm_repository_lookup,
        )
        if not root_descriptor:
            continue

        all_component_identities = []
        for ocm_node in ocm.iter.iter(
            component=root_descriptor,
            lookup=ocm_lookup,
            node_filter=ocm.iter.Filter.components,
        ):
            all_component_identities.append(
                ocm.ComponentIdentity(ocm_node.component.name, ocm_node.component.version),
            )

        findings_raw = delivery_service_client.query_metadata(
            components=all_component_identities,
            type=odg.model.Datatype.VULNERABILITY_FINDING,
        )
        rescorings_raw = delivery_service_client.query_metadata(
            components=all_component_identities,
            type=odg.model.Datatype.RESCORING,
            referenced_type=odg.model.Datatype.VULNERABILITY_FINDING,
        )

        findings = [odg.model.ArtefactMetadata.from_dict(raw) for raw in findings_raw]
        rescorings = [odg.model.ArtefactMetadata.from_dict(raw) for raw in rescorings_raw]
        release_date = util.get_creation_date(root_descriptor.component)

        version_sla_violations = iter_version_sla_violations(
            findings,
            rescorings,
            release_date,
        )

        sla_violations.append(
            odg.model.ArtefactMetadata(
                artefact=odg.model.ComponentArtefactId(
                    component_name=root_descriptor.component.name,
                    component_version=root_descriptor.component.version,
                    artefact=odg.model.LocalArtefactId(),
                ),
                meta=odg.model.Metadata(
                    datasource=odg.model.Datasource.SLA_CHECKER,
                    type=odg.model.Datatype.SLA_VIOLATION,
                    creation_date=datetime.datetime.now(),
                ),
                data=odg.model.SlaViolations(
                    sla_violations=list(version_sla_violations),
                ),
            ),
        )
    delivery_service_client.update_metadata(data=sla_violations)


if __name__ == '__main__':
    main()
