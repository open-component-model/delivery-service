import dso.model
import ocm


def find_artefact_of_component_or_none(
    component: ocm.Component,
    artefact: dso.model.ComponentArtefactId,
) -> ocm.Resource | ocm.Source | None:
    if artefact.component_name and component.name != artefact.component_name:
        return None

    if artefact.component_version and component.version != artefact.component_version:
        return None

    if not artefact.artefact:
        return None

    local_artefact = artefact.artefact
    artefact_kind = artefact.artefact_kind

    for artefact in component.resources + component.sources:
        artefact: ocm.Resource | ocm.Source

        if local_artefact.artefact_name and artefact.name != local_artefact.artefact_name:
            continue

        if local_artefact.artefact_version and artefact.version != local_artefact.artefact_version:
            continue

        if local_artefact.artefact_type and artefact.type != local_artefact.artefact_type:
            continue

        if local_artefact.artefact_extra_id and dso.model.normalise_artefact_extra_id(
            artefact_extra_id=artefact.extraIdentity,
        ) != local_artefact.normalised_artefact_extra_id():
            continue

        if isinstance(artefact, ocm.Resource) and artefact_kind != dso.model.ArtefactKind.RESOURCE:
            continue

        if isinstance(artefact, ocm.Source) and artefact_kind != dso.model.ArtefactKind.SOURCE:
            continue

        # artefact is referenced in component
        break
    else:
        # artefact is not referenced in component
        artefact = None

    return artefact
