import collections.abc
import enum
import typing

import dso.model
import dso.cvss

import rescore.model


class RescoringSpecificity(enum.IntEnum):
    GLOBAL = 0
    COMPONENT = 1
    ARTEFACT = 2
    SINGLE = 3


def _iter_rescorings_for_finding(
    finding: dso.model.ArtefactMetadata,
    rescorings: collections.abc.Iterable[dso.model.ArtefactMetadata],
) -> collections.abc.Generator[dso.model.ArtefactMetadata, None, None]:
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

        if (
            finding.meta.type == dso.model.Datatype.VULNERABILITY
            and (
                rescoring.data.finding.cve != finding.data.cve
                or rescoring.data.finding.package_name != finding.data.package_name
            )
        ):
            continue

        if (
            finding.meta.type == dso.model.Datatype.LICENSE
            and (
                rescoring.data.finding.license.name != finding.data.license.name
                or rescoring.data.finding.package_name != finding.data.package_name
            )
        ):
            continue

        if (
            finding.meta.type == dso.model.Datatype.MALWARE_FINDING
            and rescoring.data.finding.key != finding.data.finding.key
        ):
            continue

        if (
            finding.meta.type == dso.model.Datatype.FIPS_FINDING
            and rescoring.data.finding.key != finding.data.asset.key
        ):
            continue

        yield rescoring


def _specificity_of_rescoring(
    rescoring: dso.model.ArtefactMetadata,
) -> RescoringSpecificity:
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
        return RescoringSpecificity.GLOBAL

    if not rescoring.artefact.artefact.artefact_name:
        return RescoringSpecificity.COMPONENT

    if not rescoring.artefact.artefact.artefact_version:
        return RescoringSpecificity.ARTEFACT

    return RescoringSpecificity.SINGLE


def rescorings_for_finding_by_specificity(
    finding: dso.model.ArtefactMetadata,
    rescorings: collections.abc.Iterable[dso.model.ArtefactMetadata],
) -> tuple[dso.model.ArtefactMetadata]:
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


def matching_rescore_rules(
    rescoring_rules: typing.Iterable[rescore.model.CveRescoringRule],
    categorisation: dso.cvss.CveCategorisation,
    cvss: dso.cvss.CVSSV3 | dict,
) -> typing.Generator[rescore.model.CveRescoringRule, None, None]:
    for rescoring_rule in rescoring_rules:
        if not rescoring_rule.matches_categorisation(categorisation):
            continue
        if not rescoring_rule.matches_cvss(cvss):
            continue

        yield rescoring_rule


def rescore_severity(
    rescoring_rules: typing.Iterable[rescore.model.CveRescoringRule],
    severity: dso.cvss.CVESeverity,
    minimum_severity: int=dso.cvss.CVESeverity.NONE,
) -> dso.cvss.CVESeverity:
    for rule in rescoring_rules:
        if rule.rescore is rescore.model.Rescore.NO_CHANGE:
            continue
        elif rule.rescore is rescore.model.Rescore.REDUCE:
            severity = severity.reduce(
                severity_classes=1,
                minimum_severity=minimum_severity,
            )
        elif rule.rescore is rescore.model.Rescore.NOT_EXPLOITABLE:
            return dso.cvss.CVESeverity(minimum_severity)
        else:
            raise NotImplementedError(rule.rescore)

    return severity
