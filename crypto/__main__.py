import argparse
import atexit
import base64
import collections.abc
import datetime
import json
import logging
import os
import signal
import subprocess
import sys
import tarfile
import time

import ci.log
import ci.util
import cnudie.retrieve
import delivery.client
import dso.model
import oci.client
import ocm

import consts
import crypto.config
import crypto.model
import crypto.validate
import ctx_util
import k8s.backlog
import k8s.logging
import k8s.model
import k8s.util
import lookups
import odg.extensions_cfg
import odg.findings
import paths
import secret_mgmt
import secret_mgmt.oci_registry


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()

own_dir = os.path.abspath(os.path.dirname(__file__))
default_cache_dir = os.path.join(own_dir, '.cache')

ready_to_terminate = True
wants_to_terminate = False


def handle_termination_signal(*args):
    global ready_to_terminate, wants_to_terminate

    # also terminate if > 1 termination signals were received
    if ready_to_terminate or wants_to_terminate:
        sys.exit(0)

    # grace period to finish current scan is defined in the replica set
    # after this period, the scan will be terminated anyways by k8s means
    logger.info('termination signal received, will try to finish current scan and then exit')
    wants_to_terminate = True


def _prepare_docker_cfg(
    secret_factory: secret_mgmt.SecretFactory,
    image_reference: str,
):
    hostname = ci.util.urlparse(image_reference).hostname

    oci_secret = secret_mgmt.oci_registry.find_cfg(
        secret_factory=secret_factory,
        image_reference=image_reference,
    )

    auth_str = f'{oci_secret.username}:{oci_secret.password}'
    encoded_auth_str = base64.b64encode(auth_str.encode()).decode()

    docker_cfg = {
        'auths': {
            hostname: {
                'auth': encoded_auth_str,
            },
        },
    }

    docker_cfg_path = os.path.join(
        os.environ['HOME'],
        '.docker',
        'config.json',
    )
    docker_cfg_dir = os.path.dirname(docker_cfg_path)
    os.makedirs(docker_cfg_dir, exist_ok=True)
    with open(docker_cfg_path, 'w') as f:
        json.dump(docker_cfg, f)


def create_sbom(
    source: str,
    output_path: str | None=None,
) -> dict:
    sbom_cmd = (
        'syft',
        source,
        '--scope', 'all-layers',
        '--output', 'cyclonedx-json'
    )
    logger.info(f'run cmd "{' '.join(sbom_cmd)}"')
    try:
        sbom_raw = subprocess.run(sbom_cmd, check=True, capture_output=True, text=True).stdout
    except subprocess.CalledProcessError as e:
        e.add_note(f'{e.stdout=}')
        e.add_note(f'{e.stderr=}')
        raise

    sbom = json.loads(sbom_raw)

    if output_path:
        with open(output_path, 'w') as file:
            file.write(sbom_raw)

    return sbom


def create_cbom(
    image: str | None=None,
    dir: str | None=None,
    sbom_path: str | None=None,
) -> dict:
    if not (bool(image) ^ bool(dir)):
        raise ValueError(f'exactly one of {image=} and {dir=} must be set')

    docker_cmd = [
        'docker',
        'run',
        '--rm',
    ]

    if sbom_path:
        docker_cmd.extend(['-v', f'{sbom_path}:/sbom'])

    if image:
        cbomkit_theia_cmd = [
            'cbomkit-theia',
            'image',
            'get',
            image,
        ]
    else:
        docker_cmd.extend(['-v', f'{dir}:/local_dir'])

        cbomkit_theia_cmd = [
            'cbomkit-theia',
            'dir',
            '/local_dir',
        ]

    if sbom_path:
        cbomkit_theia_cmd.extend(['--bom', '/sbom'])

    cbom_cmd = docker_cmd + cbomkit_theia_cmd
    logger.info(f'run cmd "{' '.join(cbom_cmd)}"')
    try:
        cbom_raw = subprocess.run(cbom_cmd, check=True, capture_output=True, text=True).stdout
    except subprocess.CalledProcessError as e:
        e.add_note(f'{e.stdout=}')
        e.add_note(f'{e.stderr=}')
        raise

    return json.loads(cbom_raw)


def find_cbom_or_create(
    component: ocm.Component,
    access: ocm.Access,
    mapping: odg.extensions_cfg.CryptoMapping,
    oci_client: oci.client.Client,
    secret_factory: secret_mgmt.SecretFactory,
) -> dict:
    '''
    Looks up an existing CBOM document (to be implemented once it is aligned on target picture) or
    creates a CBOM ad-hoc using `syft` and `cbomkit-theia`.
    '''
    sbom_path = os.path.join(own_dir, 'sbom.json')

    if access.type is ocm.AccessType.OCI_REGISTRY:
        _prepare_docker_cfg(
            secret_factory=secret_factory,
            image_reference=access.imageReference,
        )

        create_sbom(
            source=access.imageReference,
            output_path=sbom_path,
        )

        cbom = create_cbom(
            image=access.imageReference,
            sbom_path=sbom_path,
        )

    elif access.type is ocm.AccessType.S3:
        if not mapping.aws_secret_name:
            raise ValueError('"aws_secret_name" must be configured for resources stored in S3')

        logger.info(f'using AWS secret element "{mapping.aws_secret_name}"')
        aws_secret = secret_factory.aws(mapping.aws_secret_name)
        s3_client = aws_secret.session.client('s3')

        fileobj = s3_client.get_object(Bucket=access.bucketName, Key=access.objectKey)['Body']
        s3_path = os.path.join(own_dir, 's3')

        with tarfile.open(fileobj=fileobj, mode='r|*') as tar:
            tar.extractall(
                path=s3_path,
                filter=tarfile.tar_filter,
            )

        create_sbom(
            source=s3_path,
            output_path=sbom_path,
        )

        cbom = create_cbom(
            dir=s3_path,
            sbom_path=sbom_path,
        )

        os.remove(s3_path)

    elif access.type is ocm.AccessType.LOCAL_BLOB:
        if access.globalAccess:
            image_reference = access.globalAccess.ref
            digest = access.globalAccess.digest
        else:
            image_reference = component.current_ocm_repo.component_version_oci_ref(
                name=component.name,
                version=component.version,
            )
            digest = access.localReference

        blob = oci_client.blob(
            image_reference=image_reference,
            digest=digest,
            stream=True,
        )

        local_blob_path = os.path.join(own_dir, 'local_blob')

        with open(local_blob_path, 'wb') as file:
            file.write(b''.join(blob.iter_content(chunk_size=4096)))

        create_sbom(
            source=local_blob_path,
            output_path=sbom_path,
        )

        cbom = create_cbom(
            dir=local_blob_path,
            sbom_path=sbom_path,
        )

        os.remove(local_blob_path)

    else:
        # we filtered supported access types already earlier
        raise RuntimeError('this is a bug, this line should never be reached')

    os.remove(sbom_path)

    return cbom


def as_artefact_metadata(
    artefact: dso.model.ComponentArtefactId,
    crypto_assets: collections.abc.Iterable[dso.model.CryptoAsset],
    findings: collections.abc.Iterable[dso.model.CryptoFinding],
) -> collections.abc.Generator[dso.model.ArtefactMetadata, None, None]:
    today = datetime.date.today()
    now = datetime.datetime.now(tz=datetime.timezone.utc)

    meta = dso.model.Metadata(
        datasource=dso.model.Datasource.CRYPTO,
        type=dso.model.Datatype.ARTEFACT_SCAN_INFO,
        creation_date=now,
        last_update=now,
    )

    yield dso.model.ArtefactMetadata(
        artefact=artefact,
        meta=meta,
        data={},
    )

    meta = dso.model.Metadata(
        datasource=dso.model.Datasource.CRYPTO,
        type=dso.model.Datatype.CRYPTO_ASSET,
        creation_date=now,
        last_update=now,
    )

    for crypto_asset in crypto_assets:
        yield dso.model.ArtefactMetadata(
            artefact=artefact,
            meta=meta,
            data=crypto_asset,
        )

    meta = dso.model.Metadata(
        datasource=dso.model.Datasource.CRYPTO,
        type=odg.findings.FindingType.CRYPTO,
        creation_date=now,
        last_update=now,
    )

    for finding in findings:
        yield dso.model.ArtefactMetadata(
            artefact=artefact,
            meta=meta,
            data=finding,
            discovery_date=today,
        )


def scan(
    artefact: dso.model.ComponentArtefactId,
    crypto_cfg: odg.extensions_cfg.CryptoConfig,
    crypto_finding_cfg: odg.findings.Finding | None,
    validation_config: crypto.config.CryptoConfig,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    delivery_client: delivery.client.DeliveryServiceClient,
    oci_client: oci.client.Client,
    secret_factory: secret_mgmt.SecretFactory,
):
    logger.info(f'scanning {artefact}')

    retrieve_crypto_findings = crypto_finding_cfg and crypto_finding_cfg.matches(artefact)

    if not retrieve_crypto_findings:
        logger.info('crypto findings are filtered out for this artefact, skipping...')
        return

    if not crypto_cfg.is_supported(artefact_kind=artefact.artefact_kind):
        if crypto_cfg.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(
                f'{artefact.artefact_kind} is not supported by the crypto extension, maybe the '
                'filter configurations have to be adjusted to filter out this artefact kind'
            )
        return

    resource_node = k8s.util.get_ocm_node(
        component_descriptor_lookup=component_descriptor_lookup,
        artefact=artefact,
    )
    access_type = resource_node.resource.access.type
    resource_type = resource_node.resource.type

    if not crypto_cfg.is_supported(
        access_type=access_type,
        artefact_type=resource_type,
    ):
        if crypto_cfg.on_unsupported is odg.extensions_cfg.WarningVerbosities.FAIL:
            raise TypeError(
                f'{access_type=} with {resource_type=} is not supported by the crypto extension, '
                'maybe the filter configurations have to be adjusted to filter out these types'
            )
        return

    mapping = crypto_cfg.mapping(artefact.component_name)

    cbom = find_cbom_or_create(
        component=resource_node.component,
        access=resource_node.resource.access,
        mapping=mapping,
        oci_client=oci_client,
        secret_factory=secret_factory,
    )

    logger.info('successfully created CBOM document')

    crypto_assets = crypto.model.iter_crypto_assets(
        cbom=cbom,
        crypto_libraries=validation_config.libraries,
        included_asset_types=mapping.included_asset_types,
    )

    findings = list(crypto.validate.iter_findings_for_standards(
        crypto_assets=crypto_assets,
        standards=validation_config.iter_filtered_standards(included_standards=mapping.standards),
        crypto_finding_cfg=crypto_finding_cfg,
    ))

    artefact_metadata = list(as_artefact_metadata(
        artefact=artefact,
        crypto_assets=crypto_assets,
        findings=findings,
    ))

    existing_artefact_metadata = (
        existing_artefact_metadatum
        for existing_artefact_metadatum in delivery_client.query_metadata(
            artefacts=(artefact,),
            type=(
                dso.model.Datatype.CRYPTO_ASSET,
                odg.findings.FindingType.CRYPTO,
            ),
        ) if existing_artefact_metadatum.meta.datasource == dso.model.Datasource.CRYPTO
    )

    stale_artefact_metadata = []
    for existing_artefact_metadatum in existing_artefact_metadata:
        for asset in crypto_assets + findings:
            if existing_artefact_metadatum.data.key == asset.key:
                # finding still appeared in current scan result -> keep it
                break
        else:
            # finding did not appear in current scan result -> delete it
            stale_artefact_metadata.append(existing_artefact_metadatum)

    if stale_artefact_metadata:
        delivery_client.delete_metadata(data=stale_artefact_metadata)

    delivery_client.update_metadata(
        data=artefact_metadata,
    )

    logger.info(f'finished scan of artefact {artefact}')


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--k8s-cfg-name',
        help='specify kubernetes cluster to interact with',
        default=os.environ.get('K8S_CFG_NAME'),
    )
    parser.add_argument(
        '--kubeconfig',
        help='''
            specify kubernetes cluster to interact with extensions (and logs); if both
            `k8s-cfg-name` and `kubeconfig` are set, `k8s-cfg-name` takes precedence
        ''',
    )
    parser.add_argument(
        '--k8s-namespace',
        help='specify kubernetes cluster namespace to interact with',
        default=os.environ.get('K8S_TARGET_NAMESPACE'),
    )
    parser.add_argument(
        '--extensions-cfg-path',
        help='path to the `extensions_cfg.yaml` file that should be used',
    )
    parser.add_argument(
        '--findings-cfg-path',
        help='path to the `findings.yaml` file that should be used',
    )
    parser.add_argument(
        '--crypto-cfg-path',
        help='''
            path to the YAML file containing the crypto related configuration, i.e. known crypto
            libraries and defined standards.
        ''',
    )
    parser.add_argument(
        '--delivery-service-url',
        help='''
            specify the url of the delivery service to use instead of the one configured in the
            respective extensions configuration
        ''',
    )
    parser.add_argument('--cache-dir', default=default_cache_dir)

    parsed_arguments = parser.parse_args()

    if not parsed_arguments.k8s_namespace:
        raise ValueError(
            'k8s namespace must be set, either via argument "--k8s-namespace" '
            'or via environment variable "K8S_TARGET_NAMESPACE"'
        )

    return parsed_arguments


def main():
    '''
    Note: Currently (as of 2024-12-05), CycloneDX Python lib's model class is not feature complete,
    hence deserialisation does not work. Instead, an own model class will be used which only supports
    properties which are required by this extension (see dso.model.CryptoAsset).
    '''
    signal.signal(signal.SIGTERM, handle_termination_signal)
    signal.signal(signal.SIGINT, handle_termination_signal)

    parsed_arguments = parse_args()
    namespace = parsed_arguments.k8s_namespace
    delivery_service_url = parsed_arguments.delivery_service_url

    secret_factory = ctx_util.secret_factory()

    if parsed_arguments.k8s_cfg_name:
        kubernetes_cfg = secret_factory.kubernetes(parsed_arguments.k8s_cfg_name)
        kubernetes_api = k8s.util.kubernetes_api(kubernetes_cfg=kubernetes_cfg)
    else:
        kubernetes_api = k8s.util.kubernetes_api(
            kubeconfig_path=parsed_arguments.kubeconfig,
        )

    k8s.logging.init_logging_thread(
        service=odg.extensions_cfg.Services.CRYPTO,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )
    atexit.register(
        k8s.logging.log_to_crd,
        service=odg.extensions_cfg.Services.CRYPTO,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    if not (extensions_cfg_path := parsed_arguments.extensions_cfg_path):
        extensions_cfg_path = paths.extensions_cfg_path()

    extensions_cfg = odg.extensions_cfg.ExtensionsConfiguration.from_file(extensions_cfg_path)
    crypto_cfg = extensions_cfg.crypto

    if not (findings_cfg_path := parsed_arguments.findings_cfg_path):
        findings_cfg_path = paths.findings_cfg_path()

    crypto_finding_cfg = odg.findings.Finding.from_file(
        path=findings_cfg_path,
        finding_type=odg.findings.FindingType.CRYPTO,
    )

    if not (crypto_cfg_path := parsed_arguments.crypto_cfg_path):
        crypto_cfg_path = paths.crypto_cfg_path()

    validation_config = crypto.config.CryptoConfig.from_file(crypto_cfg_path)

    if not delivery_service_url:
        delivery_service_url = crypto_cfg.delivery_service_url

    delivery_client = delivery.client.DeliveryServiceClient(
        routes=delivery.client.DeliveryServiceRoutes(
            base_url=delivery_service_url,
        ),
        auth_token_lookup=lookups.github_auth_token_lookup,
    )

    oci_client = lookups.semver_sanitising_oci_client(
        secret_factory=secret_factory,
    )

    component_descriptor_lookup = lookups.init_component_descriptor_lookup(
        cache_dir=parsed_arguments.cache_dir,
        delivery_client=delivery_client,
        oci_client=oci_client,
    )

    global ready_to_terminate, wants_to_terminate
    while not wants_to_terminate:
        ready_to_terminate = False

        backlog_crd = k8s.backlog.get_backlog_crd_and_claim(
            service=odg.extensions_cfg.Services.CRYPTO,
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

        scan(
            artefact=backlog_item.artefact,
            crypto_cfg=crypto_cfg,
            crypto_finding_cfg=crypto_finding_cfg,
            validation_config=validation_config,
            component_descriptor_lookup=component_descriptor_lookup,
            delivery_client=delivery_client,
            oci_client=oci_client,
            secret_factory=secret_factory,
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
