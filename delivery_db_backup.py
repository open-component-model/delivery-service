import argparse
import atexit
import collections.abc
import datetime
import hashlib
import logging
import os
import subprocess
import tarfile

import ci.log
import cnudie.iter
import cnudie.purge
import cnudie.retrieve
import cnudie.util
import delivery.client
import oci.auth
import oci.client
import ocm
import ocm.upload
import version

import ctx_util
import k8s.logging
import k8s.util
import lookups
import odg.extensions_cfg
import odg.findings
import paths
import secret_mgmt
import secret_mgmt.delivery_db
import secret_mgmt.oci_registry


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()


BACKUP_BLOB_MEDIA_TYPE = 'application/data+tar'


def create_local_backup(
    outfile: str,
    delivery_db_cfg: secret_mgmt.delivery_db.DeliveryDB,
    additional_args: list[str] = [],
):
    outfile_path = os.path.abspath(outfile)
    os.environ['PGPASSWORD'] = delivery_db_cfg.password

    pg_dump_argv = [
        'pg_dump',
        '--host',
        delivery_db_cfg.hostname,
        '--port',
        str(delivery_db_cfg.port),
        '--username',
        delivery_db_cfg.username,
        '--file',
        outfile_path,
        '--format',
        'tar',
        '--verbose',
        'postgres',
    ] + additional_args

    logger.info(f'{pg_dump_argv=}')

    process = subprocess.Popen(
        pg_dump_argv,
        stdout=subprocess.PIPE,
        universal_newlines=True,
        stderr=subprocess.STDOUT,
    )
    for line in iter(process.stdout.readline, ''):
        logger.info(line)

    process.stdout.close()
    return_code = process.wait()

    if return_code != 0:
        logger.error('error occurred creating local backup')
        exit(1)

    logger.info('successfully created local backup')
    return


def create_ocm_descriptor(
    component_name: str,
    component_version: str,
    ocm_repo: str,
    backup_digest: str,
    size: int,
) -> ocm.ComponentDescriptor:
    return ocm.ComponentDescriptor(
      meta=ocm.Metadata(schemaVersion=ocm.SchemaVersion.V2),
      component=ocm.Component(
        name=component_name,
        version=component_version,
        repositoryContexts=[
          ocm.OciOcmRepository(
            baseUrl=ocm_repo,
            type=ocm.AccessType.OCI_REGISTRY,
          )
        ],
        provider='internal',
        sources=[],
        componentReferences=[],
        resources=[
            ocm.Resource(
                name='delivery-db-backup',
                version=component_version,
                type=ocm.ArtefactType.BLOB,
                access=ocm.LocalBlobAccess(
                    localReference=backup_digest,
                    mediaType=BACKUP_BLOB_MEDIA_TYPE,
                    size=size,
                ),
            )
        ],
        labels=[
            ocm.Label(
                name='cloud.gardener/ocm/creation-date',
                value=datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
            ),
        ],
      ),
    )


def calculate_sha256(tar_file_path):
    sha256_hash = hashlib.sha256()

    with open(tar_file_path, 'rb') as file:
        while chunk := file.read(8192):
            sha256_hash.update(chunk)

    return sha256_hash.hexdigest()


def upload_from_file(
    outfile: str,
    oci_client: oci.client.Client,
    target_ref: str,
    size: int,
) -> tuple[str, str]:
    with tarfile.open(outfile) as tf:
        data = tf.fileobj
        cd_digest_with_alg = f'sha256:{calculate_sha256(outfile)}'
        data.seek(0)

        logger.info(f'uploading blob {cd_digest_with_alg} to {target_ref}')

        oci_client.put_blob(
            image_reference=target_ref,
            digest=cd_digest_with_alg,
            octets_count=size,
            data=data,
        )

    return cd_digest_with_alg


def iter_components_to_purge(
    backup_retention_count: int,
    component: ocm.Component,
    oci_client: oci.client.Client,
    lookup,
) -> collections.abc.Generator[ocm.Component, None, None]:
    oci_ref = cnudie.util.oci_ref(component=component)
    all_versions = oci_client.tags(oci_ref.ref_without_tag)

    sorted_versions = sorted(all_versions, key=lambda v: version.parse_to_semver(
        version=v,
        invalid_semver_ok=True,
    ))

    return (
        lookup(
            ocm.ComponentIdentity(
                name=component.name,
                version=v,
            ),
        )
        for v in sorted_versions[:-backup_retention_count]
    )


def iter_local_resources(
    component: ocm.Component,
) -> collections.abc.Generator[None, None, ocm.Resource]:
    for resource_node in cnudie.iter.iter(
        component=component,
        node_filter=cnudie.iter.Filter.resources,
        recursion_depth=0,
    ):
        resource_node: cnudie.iter.ResourceNode
        if isinstance(resource_node.resource.access, ocm.LocalBlobAccess):
            yield resource_node.resource


def delete_old_backup_versions(
    backup_retention_count: int,
    oci_ref: str,
    secret_factory: secret_mgmt.SecretFactory,
    ocm_repo: str,
    component: ocm.Component,
):
    logger.info(f'deleting old backup component versions, {backup_retention_count=}')

    if backup_retention_count < 0:
        raise ValueError(f'{backup_retention_count=} must be a positive integer value')

    cfg_for_delete = secret_mgmt.oci_registry.find_cfg(
        secret_factory=secret_factory,
        image_reference=oci_ref,
        privileges=oci.auth.Privileges.ADMIN,
    )

    def oci_cfg_lookup(
        **kwargs,
    ):
        return oci.auth.OciBasicAuthCredentials(
            username=cfg_for_delete.username,
            password=cfg_for_delete.password,
        )

    oci_client = oci.client.Client(
        credentials_lookup=oci_cfg_lookup,
        tag_preprocessing_callback=cnudie.util.sanitise_version,
        tag_postprocessing_callback=cnudie.util.desanitise_version,
    )

    lookup = cnudie.retrieve.oci_component_descriptor_lookup(
        ocm_repository_lookup=cnudie.retrieve.ocm_repository_lookup(ocm_repo),
        oci_client=oci_client,
    )

    for component in iter_components_to_purge(
        backup_retention_count=backup_retention_count,
        component=component,
        oci_client=oci_client,
        lookup=lookup,
    ):
        local_resources = iter_local_resources(component)

        # local blobs can only be deleted if no ref remains -> delete component-descriptor first
        cnudie.purge.remove_component_descriptor_and_referenced_artefacts(
            component=component,
            oci_client=oci_client,
        )

        for resource in local_resources:
            resource: ocm.Resource
            resource.access: ocm.LocalBlobAccess

            logger.info(f'deleting blob with {resource.access.localReference=}')

            oci_client.delete_blob(
                image_reference=oci_ref,
                digest=resource.access.localReference,
            )


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

    parsed_arguments = parser.parse_args()

    if not parsed_arguments.k8s_namespace:
        raise ValueError(
            'k8s namespace must be set, either via argument "--k8s-namespace" '
            'or via environment variable "K8S_TARGET_NAMESPACE"'
        )

    return parsed_arguments


def main():
    parsed_arguments = parse_args()
    namespace = parsed_arguments.k8s_namespace

    secret_factory = ctx_util.secret_factory()

    if parsed_arguments.k8s_cfg_name:
        kubernetes_cfg = secret_factory.kubernetes(parsed_arguments.k8s_cfg_name)
        kubernetes_api = k8s.util.kubernetes_api(kubernetes_cfg=kubernetes_cfg)
    else:
        kubernetes_api = k8s.util.kubernetes_api(
            kubeconfig_path=parsed_arguments.kubeconfig,
        )

    k8s.logging.init_logging_thread(
        service=odg.extensions_cfg.Services.DELIVERY_DB_BACKUP,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )
    atexit.register(
        k8s.logging.log_to_crd,
        service=odg.extensions_cfg.Services.DELIVERY_DB_BACKUP,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    logger.info('creating delivery-db backup')

    if not (extensions_cfg_path := parsed_arguments.extensions_cfg_path):
        extensions_cfg_path = paths.extensions_cfg_path()

    extensions_cfg = odg.extensions_cfg.ExtensionsConfiguration.from_file(extensions_cfg_path)
    delivery_db_backup_cfg = extensions_cfg.delivery_db_backup

    delivery_db_cfgs = secret_factory.delivery_db()
    if len(delivery_db_cfgs) != 1:
        raise ValueError(
            f'There must be exactly one delivery-db secret, found {len(delivery_db_cfgs)}'
        )
    delivery_db_cfg = delivery_db_cfgs[0]

    component_name = delivery_db_backup_cfg.component_name
    ocm_repo = delivery_db_backup_cfg.ocm_repo_url
    additional_args = delivery_db_backup_cfg.extra_pg_dump_args
    delivery_service_url = delivery_db_backup_cfg.delivery_service_url
    backup_retention_count = delivery_db_backup_cfg.backup_retention_count
    initial_version = delivery_db_backup_cfg.initial_version

    delivery_service_client = delivery.client.DeliveryServiceClient(
        routes=delivery.client.DeliveryServiceRoutes(
            base_url=delivery_service_url,
        ),
        auth_token_lookup=lookups.github_auth_token_lookup,
    )

    greatest_versions = delivery_service_client.greatest_component_versions(
        component_name=component_name,
        max_versions=1,
        ocm_repo=ocm.OciOcmRepository(baseUrl=ocm_repo),
    )

    if greatest_versions:
        component_version = version.process_version(
            version_str=greatest_versions[0],
            operation='bump_minor',
        )
    else:
        component_version = initial_version

    outfile = os.path.abspath('./delivery-db-backup.tar')

    if os.path.exists(outfile):
        logger.info('local backup present already, skipping creation')

    else:
        create_local_backup(
            outfile=outfile,
            delivery_db_cfg=delivery_db_cfg,
            additional_args=additional_args,
        )

    target_ref = cnudie.util.oci_artefact_reference(
        component=f'{component_name}:{component_version}',
        ocm_repository=ocm_repo,
    )

    oci_client = lookups.semver_sanitising_oci_client(
        secret_factory=secret_factory,
    )

    size = os.path.getsize(outfile)

    backup_digest = upload_from_file(
        outfile=outfile,
        oci_client=oci_client,
        target_ref=target_ref,
        size=size,
    )

    component_descriptor = create_ocm_descriptor(
        component_name=component_name,
        component_version=component_version,
        ocm_repo=ocm_repo,
        backup_digest=backup_digest,
        size=size,
    )
    component = component_descriptor.component

    ocm.upload.upload_component_descriptor(
        component_descriptor=component_descriptor,
        on_exist=ocm.upload.UploadMode.OVERWRITE,
        oci_client=oci_client,
    )

    logger.info(f'backup successful. {ocm_repo=} ; {component_name=} ; {component_version=}')

    if not backup_retention_count:
        return

    delete_old_backup_versions(
        backup_retention_count=backup_retention_count,
        oci_ref=cnudie.util.oci_ref(component),
        secret_factory=secret_factory,
        ocm_repo=ocm_repo,
        component=component,
    )


if __name__ == '__main__':
    main()
