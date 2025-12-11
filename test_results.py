import datetime
import ocm
import odg.findings
import odg.model


def find_artefact_with_truthy_test_policy_label(component: ocm.ComponentDescriptor) -> list[ocm.Artifact] | None:
    artefacts = []
    for resource in component.component.resources:
        if resource.relation == 'local': # !!WE NEED TO DISCUSS THIS IN THE TEAM!
            label = resource.find_label(name='gardener.cloud/test-policy')
            if label and label.value:
                artefacts.append(resource)

            else:
                if resource.type == ocm.ArtefactType.OCI_IMAGE:
                    artefacts.append(resource)
                else:
                    continue
    return artefacts


def find_test_artefacts(component: ocm.ComponentDescriptor) -> list[ocm.Artifact]:
    artefacts = []
    for resource in component.component.resources:
        for label in resource.labels:
            if label.name == 'gardener.cloud/purposes' and 'test' in label.value:
                artefacts.append(resource)
    return artefacts


def create_missing_test_finding(
        artefact: odg.model.ComponentArtefactId,
        sub_type: odg.model.TestStatus,
        categorisation: odg.findings.FindingCategorisation,
        creation_timestamp: datetime.datetime=datetime.datetime.now(
        tz=datetime.timezone.utc)
) -> odg.model.ArtefactMetadata | None:
    return odg.model.ArtefactMetadata(
        artefact=artefact,
        meta=odg.model.Metadata(
            datasource=odg.model.Datasource.TEST_RESULT_FINDING,
            type=odg.model.Datatype.TEST_RESULT_FINDING,
            creation_date=creation_timestamp,
            last_update=creation_timestamp,
        ),
        data=odg.model.TestResultMissingFinding(
            test_status=odg.model.TestStatus.NO_TEST,
            severity=categorisation.id),
        discovery_date=creation_timestamp.date(),
    )


def iter_artefacts_for_test_coverage(
    component: ocm.ComponentDescriptor,
    test_result_finding_config: odg.findings.Finding,
    sub_type: odg.model.TestStatus,
    artefact: odg.model.ComponentArtefactId,
    creation_timestamp: datetime.datetime=datetime.datetime.now(datetime.timezone.utc)
) -> <typehint>:

    categorisation = odg.findings.categorise_finding(
        finding_cfg=test_result_finding_config,
        finding_property=sub_type
    )

    artefacts_req_tests = find_artefact_with_truthy_test_policy_label(
        component)

    test_artefacts = find_test_artefacts(component)

    findings = []
    artefacts_with_tests = []

    for ta in test_artefacts:
        if not ta.find_label(name='gardener.cloud/test-scope'):
            # if label is absent, assume tests are scoping *all* resources within this component
            return
        for label in ta.labels:
            if label.name == 'gardener.cloud/test-scope':
                artefacts_with_tests.append(label.value)

    for artefact_requiring_tests in artefacts_req_tests:
        if artefact_requiring_tests.name not in artefacts_with_tests:
            findings.append(
                create_missing_test_finding(
                    artefact, sub_type, categorisation, creation_timestamp)
                )
        return findings
