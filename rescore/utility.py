import collections.abc
import datetime
import re

import ocm.iter

import consts
import odg.cvss
import odg.findings
import odg.labels
import odg.model
import rescore.model


def _iter_rescorings_for_finding(
    finding: odg.model.ArtefactMetadata,
    rescorings: collections.abc.Iterable[odg.model.ArtefactMetadata],
) -> collections.abc.Generator[odg.model.ArtefactMetadata, None, None]:
    for rescoring in rescorings:
        if rescoring.data.referenced_type != finding.meta.type:
            continue

        if rescoring.artefact.artefact_kind != finding.artefact.artefact_kind:
            continue

        if rescoring.artefact.artefact.artefact_type != finding.artefact.artefact.artefact_type:
            continue

        if (
            rescoring.artefact.component_name
            and rescoring.artefact.component_name != finding.artefact.component_name
        ):
            continue

        if (
            rescoring.artefact.component_version
            and finding.artefact.component_version
            and rescoring.artefact.component_version != finding.artefact.component_version
        ):
            continue

        if (
            rescoring.artefact.artefact.artefact_name
            and rescoring.artefact.artefact.artefact_name != finding.artefact.artefact.artefact_name
        ):
            continue

        if (
            rescoring.artefact.artefact.artefact_version
            and rescoring.artefact.artefact.artefact_version
                != finding.artefact.artefact.artefact_version
        ):
            continue

        if (
            rescoring.artefact.artefact.artefact_extra_id
            and rescoring.artefact.artefact.normalised_artefact_extra_id
                != finding.artefact.artefact.normalised_artefact_extra_id
        ):
            continue

        if finding.meta.type == odg.model.Datatype.VULNERABILITY_FINDING:
            if (
                rescoring.data.finding.cve != finding.data.cve
                or rescoring.data.finding.package_name != finding.data.package_name
            ):
                continue

        elif finding.meta.type == odg.model.Datatype.LICENSE_FINDING:
            if (
                rescoring.data.finding.license.name != finding.data.license.name
                or rescoring.data.finding.package_name != finding.data.package_name
            ):
                continue

        elif finding.meta.type == odg.model.Datatype.IP_FINDING:
            if (
                rescoring.data.finding.license.name != finding.data.license.name
                or rescoring.data.finding.package_name != finding.data.package_name
                or rescoring.data.finding.policy_violation.name != finding.data.policy_violation.name
                or sorted(rescoring.data.finding.labels) != sorted(finding.data.labels)
            ):
                continue
        else:
            if rescoring.data.finding.key != finding.data.key:
                continue

        yield rescoring


def _specificity_of_rescoring(
    rescoring: odg.model.ArtefactMetadata,
) -> odg.findings.RescoringSpecificity:
    '''
    There are four possible scopes for a rescoring. If multiple rescorings match
    one finding, the rescoring with the greatest specificity based on its scope
    should be used.

    Thereby, the "Global" scope has neither component name or version nor artefact
    name or version set. The "Component" scope only refers to the component name,
    the "Artefact" scope only to the component name as well as the artefact name.
    Last, the "Single" scope requires all four parameters to be set.
    '''
    if not rescoring.artefact.component_name:
        return odg.findings.RescoringSpecificity.GLOBAL

    if not rescoring.artefact.artefact.artefact_name:
        return odg.findings.RescoringSpecificity.COMPONENT

    if not rescoring.artefact.artefact.artefact_version:
        return odg.findings.RescoringSpecificity.ARTEFACT

    return odg.findings.RescoringSpecificity.SINGLE


def rescorings_for_finding_by_specificity(
    finding: odg.model.ArtefactMetadata,
    rescorings: collections.abc.Iterable[odg.model.ArtefactMetadata],
) -> tuple[odg.model.ArtefactMetadata]:
    '''
    Returns all rescorings of `rescorings` which match the given `finding`. If multiple
    rescorings match the finding, they are ordered based on their specificity (greatest
    specificity first and if the specificity is the same, the latest rescorings wins).
    '''
    rescorings_for_finding = _iter_rescorings_for_finding(
        finding=finding,
        rescorings=rescorings,
    )

    return tuple(sorted(
        rescorings_for_finding,
        key=lambda rescoring: (
            _specificity_of_rescoring(rescoring=rescoring),
            rescoring.meta.creation_date,
        ),
        reverse=True,
    ))


def find_cve_categorisation(
    artefact_node: ocm.iter.Node | ocm.iter.ArtefactNode,
) -> odg.cvss.CveCategorisation | None:
    label_name = odg.labels.CveCategorisationLabel.name

    if not (categorisation_label := artefact_node.artefact.find_label(label_name)):
        if not (categorisation_label := artefact_node.component.find_label(label_name)):
            return None

    return odg.labels.deserialise_label(categorisation_label).value


def matching_rescore_rules(
    rescoring_rules: collections.abc.Iterable[rescore.model.CveRescoringRule],
    categorisation: odg.cvss.CveCategorisation,
    cvss: odg.cvss.CVSSV3 | dict,
) -> collections.abc.Generator[rescore.model.CveRescoringRule, None, None]:
    for rescoring_rule in rescoring_rules:
        if not rescoring_rule.matches_categorisation(categorisation):
            continue
        if not rescoring_rule.matches_cvss(cvss):
            continue

        yield rescoring_rule


def rescore_finding(
    finding_cfg: odg.findings.Finding,
    current_categorisation: odg.findings.FindingCategorisation,
    rescoring_rules: collections.abc.Iterable[rescore.model.Rule],
    operations: dict[str, rescore.model.Operation | str] | None,
) -> odg.findings.FindingCategorisation:
    '''
    Applies the `rescoring_rules` to the `current_categorisation`. A rescoring rule may either
    express a generic operation (specified in the rescoring ruleset), or a rescoring to a concrete
    categorisation id.
    '''
    for rule in rescoring_rules:
        if operations and rule.operation in operations.keys():
            # specified operation is one of the pre-defined operations
            operation = operations[rule.operation]
        else:
            operation = rule.operation

        if isinstance(operation, str):
            if not operation.startswith(consts.RESCORING_OPERATOR_SET_TO_PREFIX):
                raise ValueError(
                    f'invalid {operation=}, must match pattern '
                    f'`{consts.RESCORING_OPERATOR_SET_TO_PREFIX}<categorisation-id>`'
                )
            operation = operation.removeprefix(consts.RESCORING_OPERATOR_SET_TO_PREFIX)

        elif isinstance(operation, rescore.model.Operation):
            for idx, op in enumerate(operation.order):
                if op != current_categorisation.id:
                    continue

                # use either the "<value>"-next operation ("value" might be negative)
                next_categorisation_idx = idx + operation.value

                # ensure lower and upper limit (specified via "order" property)
                next_categorisation_idx = min(next_categorisation_idx, len(operation.order) - 1)
                next_categorisation_idx = max(next_categorisation_idx, 0)

                operation = operation.order[next_categorisation_idx]
                break

        current_categorisation = finding_cfg.categorisation_by_id(operation)

    return current_categorisation


def iter_matching_sast_rescoring_rules(
    rescoring_rules: collections.abc.Iterable[rescore.model.SastRescoringRule],
    finding: odg.model.ArtefactMetadata,
) -> collections.abc.Generator[rescore.model.SastRescoringRule, None, None]:
    for rescoring_rule in rescoring_rules:
        if any(
            re.match(condition.component_name, finding.artefact.component_name)
            for condition in rescoring_rule.match
        ) and finding.data.sub_type in rescoring_rule.sub_types:
            yield rescoring_rule


def rescoring_for_sast_finding(
    finding: odg.model.ArtefactMetadata,
    sast_finding_cfg: odg.findings.Finding,
    categorisation: odg.findings.FindingCategorisation,
    user: odg.model.User,
    creation_timestamp: datetime.datetime
) -> odg.model.ArtefactMetadata | None:
    if (
        not categorisation
        or not categorisation.automatic_rescoring
        or not sast_finding_cfg.rescoring_ruleset
    ):
        return None

    matching_rules = list(
        iter_matching_sast_rescoring_rules(
            rescoring_rules=sast_finding_cfg.rescoring_ruleset.rules,
            finding=finding,
        )
    )

    if not matching_rules:
        return None

    rescored_categorisation = rescore_finding(
        finding_cfg=sast_finding_cfg,
        current_categorisation=categorisation,
        rescoring_rules=matching_rules,
        operations=sast_finding_cfg.rescoring_ruleset.operations,
    )

    if rescored_categorisation.id == categorisation.id:
        return None # categorisation did not change -> no need to create a rescoring

    return odg.model.ArtefactMetadata(
        artefact=finding.artefact,
        meta=odg.model.Metadata(
            datasource=finding.meta.datasource,
            type=odg.model.Datatype.RESCORING,
            creation_date=creation_timestamp,
            last_update=creation_timestamp,
        ),
        data=odg.model.CustomRescoring(
            finding=odg.model.RescoreSastFinding(
                sast_status=finding.data.sast_status,
                sub_type=finding.data.sub_type,
            ),
            referenced_type=odg.model.Datatype.SAST_FINDING,
            severity=rescored_categorisation.id,
            user=user,
            matching_rules=[rule.name for rule in matching_rules],
            comment='Automatically rescored due_date on rules.',
            allowed_processing_time=rescored_categorisation.allowed_processing_time_raw,
        ),
    )
