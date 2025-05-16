import collections.abc
import functools
import logging

import ci.log
import delivery.client

import k8s.logging
import odg.extensions_cfg
import odg.findings
import odg.model
import odg.util
import paths
import responsibles_extension.filters
import secret_mgmt


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()


def matches(
    artefact: odg.model.ComponentArtefactId,
    finding_type: odg.model.Datatype,
    filters: collections.abc.Iterable[responsibles_extension.filters.FilterBase],
) -> bool:
    for filter in filters:
        if not filter.matches(artefact, finding_type):
            return False
    return True


def update_responsibles(
    artefact: odg.model.ComponentArtefactId,
    extension_cfg: odg.extensions_cfg.ResponsiblesConfig,
    finding_cfgs: collections.abc.Iterable[odg.findings.Finding],
    delivery_client: delivery.client.DeliveryServiceClient,
    secret_factory: secret_mgmt.SecretFactory,
    **kwargs,
):
    responsibles_artefacts = []

    for finding_cfg in finding_cfgs:
        finding_type = finding_cfg.type

        for rule in extension_cfg.rules:
            if not matches(
                artefact=artefact,
                finding_type=finding_type,
                filters=rule.filters,
            ):
                continue

            logger.info(f'rule "{rule.name}" will process {artefact} for {finding_type=}')

            responsibles = []
            for strategy in rule.strategies:
                responsibles.extend(strategy.iter_responsibles(
                    artefact=artefact,
                    datatype=finding_type,
                    secret_factory=secret_factory,
                    delivery_client=delivery_client,
                ))

            responsibles_artefacts.append(odg.model.ArtefactMetadata(
                artefact=artefact,
                meta=odg.model.Metadata(
                    datasource=odg.model.Datasource.RESPONSIBLES,
                    type=odg.model.Datatype.RESPONSIBLES,
                    responsibles=responsibles,
                    assignee_mode=rule.assignee_mode,
                ),
                data=odg.model.ResponsibleInfo(
                    referenced_type=finding_type,
                ),
            ))

            break
        else:
            logger.warning(
                f'did not find a matching rule for {artefact} and {finding_type=}, skipping...'
            )

    delivery_client.update_metadata(
        data=responsibles_artefacts,
    )


def main():
    parsed_arguments = odg.util.parse_args()

    if not (findings_cfg_path := parsed_arguments.findings_cfg_path):
        findings_cfg_path = paths.findings_cfg_path()

    finding_cfgs = odg.findings.Finding.from_file(findings_cfg_path)

    update_responsibles_callback = functools.partial(
        update_responsibles,
        finding_cfgs=finding_cfgs,
    )

    odg.util.process_backlog_items(
        parsed_arguments=parsed_arguments,
        service=odg.extensions_cfg.Services.RESPONSIBLES,
        callback=update_responsibles_callback,
    )


if __name__ == '__main__':
    main()
