import atexit
import collections.abc
import logging
import signal
import sys
import time

import ci.log
import delivery.client

import consts
import ctx_util
import k8s.backlog
import k8s.logging
import k8s.util
import lookups
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
    responsibles_cfg: odg.extensions_cfg.ResponsiblesConfig,
    finding_cfgs: collections.abc.Iterable[odg.findings.Finding],
    secret_factory: secret_mgmt.SecretFactory,
    delivery_client: delivery.client.DeliveryServiceClient,
):
    responsibles_artefacts = []

    for finding_cfg in finding_cfgs:
        finding_type = finding_cfg.type

        for rule in responsibles_cfg.rules:
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
    signal.signal(signal.SIGTERM, handle_termination_signal)
    signal.signal(signal.SIGINT, handle_termination_signal)

    parsed_arguments = odg.util.parse_args()
    namespace = parsed_arguments.k8s_namespace

    secret_factory = ctx_util.secret_factory()

    if parsed_arguments.k8s_cfg_name:
        kubernetes_cfg = secret_factory.kubernetes(parsed_arguments.k8s_cfg_name)
        kubernetes_api = k8s.util.kubernetes_api(kubernetes_cfg=kubernetes_cfg)
    else:
        kubernetes_api = k8s.util.kubernetes_api(kubeconfig_path=parsed_arguments.kubeconfig)

    k8s.logging.init_logging_thread(
        service=odg.extensions_cfg.Services.RESPONSIBLES,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )
    atexit.register(
        k8s.logging.log_to_crd,
        service=odg.extensions_cfg.Services.RESPONSIBLES,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    if not (extensions_cfg_path := parsed_arguments.extensions_cfg_path):
        extensions_cfg_path = paths.extensions_cfg_path()

    extensions_cfg = odg.extensions_cfg.ExtensionsConfiguration.from_file(extensions_cfg_path)
    responsibles_cfg = extensions_cfg.responsibles

    if not (findings_cfg_path := parsed_arguments.findings_cfg_path):
        findings_cfg_path = paths.findings_cfg_path()

    finding_cfgs = odg.findings.Finding.from_file(findings_cfg_path)

    if not (delivery_service_url := parsed_arguments.delivery_service_url):
        delivery_service_url = responsibles_cfg.delivery_service_url

    delivery_client = delivery.client.DeliveryServiceClient(
        routes=delivery.client.DeliveryServiceRoutes(
            base_url=delivery_service_url,
        ),
        auth_token_lookup=lookups.github_auth_token_lookup,
    )

    global ready_to_terminate
    while not wants_to_terminate:
        ready_to_terminate = False

        backlog_crd = k8s.backlog.get_backlog_crd_and_claim(
            service=odg.extensions_cfg.Services.RESPONSIBLES,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
        )

        if not backlog_crd:
            ready_to_terminate = True
            sleep_interval_seconds = consts.BACKLOG_ITEM_SLEEP_INTERVAL_SECONDS
            logger.info(f'no open backlog item found, will sleep for {sleep_interval_seconds=}')
            time.sleep(sleep_interval_seconds)
            continue

        name = backlog_crd.get('metadata').get('name')
        logger.info(f'processing backlog item {name}')

        backlog_item = k8s.backlog.BacklogItem.from_dict(
            backlog_item=backlog_crd.get('spec'),
        )

        update_responsibles(
            artefact=backlog_item.artefact,
            responsibles_cfg=responsibles_cfg,
            finding_cfgs=finding_cfgs,
            secret_factory=secret_factory,
            delivery_client=delivery_client,
        )

        k8s.util.delete_custom_resource(
            crd=k8s.model.BacklogItemCrd,
            name=name,
            namespace=namespace,
            kubernetes_api=kubernetes_api,
        )
        logger.info(f'processed and deleted backlog item {name}')


if __name__ == '__main__':
    main()
