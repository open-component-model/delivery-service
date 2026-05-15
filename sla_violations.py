import datetime
import os

import cnudie.retrieve
import ocm
import ocm.iter

import lookups
import odg.model
import odg_client
import rescore.utility
import util


def filter_rescorings_for_finding(
    finding: odg.model.ArtefactMetadata,
    rescorings: list[odg.model.ArtefactMetadata],
    release_date: datetime.datetime,
) -> list[odg.model.ArtefactMetadata]:
    filtered_rescorings = []
    for r in rescore.utility.rescorings_for_finding_by_specificity(
        finding=finding,
        rescorings=rescorings,
    ):
        if r.meta.creation_date < release_date:
            filtered_rescorings.append(r)

    return sorted(
        filtered_rescorings,
        key=lambda rescoring: rescoring.meta.creation_date,
    )


def determine_deadline_violations(
    finding: odg.model.ArtefactMetadata,
    sorted_rescorings: list[odg.model.ArtefactMetadata],
    release_date: datetime.datetime,
) -> list[odg.model.SlaViolation]:
    violations = []
    allowed_time = util.convert_to_timedelta(finding.allowed_processing_time)
    deadline = finding.discovery_date + allowed_time

    for rescoring in sorted_rescorings:
        if deadline and rescoring.meta.creation_date.date() > deadline:
            violations.append(
                odg.model.SlaViolation(
                    finding=odg.model.RescoringVulnerabilityFinding(
                        package_name=finding.data.package_name,
                        cve=finding.data.cve,
                    ),
                    referenced_type=odg.model.Datatype.VULNERABILITY_FINDING,
                    artefact=finding.artefact,
                ),
            )
        if rescoring.data.due_date:
            deadline = rescoring.data.due_date
        elif rescoring.data.allowed_processing_time is None:
            deadline = None
        else:
            allowed_time = util.convert_to_timedelta(rescoring.data.allowed_processing_time)
            deadline = finding.discovery_date + allowed_time

    if deadline and deadline < release_date.date():
        violations.append(
            odg.model.SlaViolation(
                finding=odg.model.RescoringVulnerabilityFinding(
                    package_name=finding.data.package_name,
                    cve=finding.data.cve,
                ),
                referenced_type=odg.model.Datatype.VULNERABILITY_FINDING,
                artefact=finding.artefact,
            ),
        )

    return violations


def determine_version_sla_violations(
    findings: list[odg.model.ArtefactMetadata],
    rescorings: list[odg.model.ArtefactMetadata],
    release_date: datetime.datetime,
) -> list[odg.model.SlaViolation]:
    version_sla_violations = []

    for finding in findings:
        if finding.meta.creation_date > release_date:
            continue

        if not finding.discovery_date:
            raise ValueError(f'finding is missing discovery_date: {finding}')

        if not finding.allowed_processing_time:
            continue

        sorted_rescorings = filter_rescorings_for_finding(finding, rescorings, release_date)
        violations = determine_deadline_violations(finding, sorted_rescorings, release_date)
        version_sla_violations.extend(violations)

    return version_sla_violations


if __name__ == '__main__':
    delivery_service_client = odg_client.DeliveryServiceClient(
        routes=odg_client.DeliveryServiceRoutes(
            base_url=os.environ['BASE_URL'],
        ),
        auth_token=os.environ['GITHUB_AUTH_TOKEN'],
        api_url=os.environ['API_URL'],
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

    versions = delivery_service_client.greatest_component_versions(
        component_name=os.environ['COMPONENT_NAME'],
        start_date=datetime.date(
            year=2025,
            month=2,
            day=4,
        ),
        end_date=datetime.date(
            year=2026,
            month=5,
            day=4,
        ),
    )

    sla_violations = []

    for version in versions:
        root_descriptor = ocm_lookup(
            f'{os.environ["COMPONENT_NAME"]}:{version}',
        )

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

        version_sla_violations = determine_version_sla_violations(
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
                    sla_violations=version_sla_violations,
                ),
            ),
        )
    delivery_service_client.update_metadata(data=sla_violations)
