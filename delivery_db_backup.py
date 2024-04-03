import argparse
import atexit
import datetime
import hashlib
import logging
import os
import subprocess
import tarfile
import typing

import ccc.oci
import ci.log
import ci.util
import cnudie.iter
import cnudie.purge
import cnudie.retrieve
import cnudie.upload
import cnudie.util
import delivery.client
import gci.componentmodel as cm
import model.container_registry
import model.delivery_db
import oci.auth
import oci.client
import version

import config
import ctx_util
import k8s.logging
import k8s.util


logger = logging.getLogger(__name__)
ci.log.configure_default_logging()
k8s.logging.configure_kubernetes_logging()


BACKUP_BLOB_MEDIA_TYPE = 'application/data+tar'


def create_local_backup(
    outfile: str,
    delivery_db_cfg: model.delivery_db.DeliveryDbConfig,
    additional_args: list[str] = [],
):
    outfile_path = os.path.abspath(outfile)
    os.environ['PGPASSWORD'] = delivery_db_cfg.credentials().passwd()

    pg_dump_argv = [
        'pg_dump',
        '--host',
        delivery_db_cfg.hostname(),
        '--port',
        str(delivery_db_cfg.port()),
        '--username',
        delivery_db_cfg.credentials().username(),
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
) -> cm.ComponentDescriptor:
    return cm.ComponentDescriptor(
      meta=cm.Metadata(schemaVersion=cm.SchemaVersion.V2),
      component=cm.Component(
        name=component_name,
        version=component_version,
        repositoryContexts=[
          cm.OciOcmRepository(
            baseUrl=ocm_repo,
            type=cm.AccessType.OCI_REGISTRY,
          )
        ],
        provider='internal',
        sources=[],
        componentReferences=[],
        resources=[
            cm.Resource(
                name='delivery-db-backup',
                version=component_version,
                type=cm.ArtefactType.BLOB,
                access=cm.LocalBlobAccess(
                    localReference=backup_digest,
                    mediaType=BACKUP_BLOB_MEDIA_TYPE,
                    size=size,
                ),
            )
        ],
        labels=[
            cm.Label(
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
    ocm_repo: str,
    component: cm.Component,
    oci_client: oci.client.Client,
    lookup,
) -> typing.Generator[cm.Component, None, None]:
    oci_ref = cnudie.util.oci_ref(component=component)
    all_versions = oci_client.tags(oci_ref.ref_without_tag)

    sorted_versions = sorted(all_versions, key=lambda v: version.parse_to_semver(
        version=v,
        invalid_semver_ok=True,
    ))

    return (
        lookup(
            cm.ComponentIdentity(
                name=component.name,
                version=v,
            ),
            ctx_repo=ocm_repo,
        )
        for v in sorted_versions[:-backup_retention_count]
    )


def iter_local_resources(
    component: cm.Component,
) -> typing.Generator[None, None, cm.Resource]:
    for resource_node in cnudie.iter.iter(
        component=component,
        node_filter=cnudie.iter.Filter.resources,
        recursion_depth=0,
    ):
        resource_node: cnudie.iter.ResourceNode
        if isinstance(resource_node.resource.access, cm.LocalBlobAccess):
            yield resource_node.resource


def delete_old_backup_versions(
    backup_retention_count: int,
    oci_ref: str,
    cfg_factory,
    ocm_repo: str,
    component: cm.Component,
):
    logger.info(f'deleting old backup component versions, {backup_retention_count=}')

    if backup_retention_count < 0:
        raise ValueError(f'{backup_retention_count=} must be a positive integer value')

    cfg_for_delete = model.container_registry.find_config(
        image_reference=oci_ref,
        privileges=oci.auth.Privileges.ADMIN,
        cfg_factory=cfg_factory,
    )

    def oci_cfg_lookup(
        **kwargs,
    ):
        creds = cfg_for_delete.credentials()
        return oci.auth.OciBasicAuthCredentials(
            username=creds.username(),
            password=creds.passwd(),
        )

    oci_client = oci.client.Client(
        credentials_lookup=oci_cfg_lookup,
    )

    lookup = cnudie.retrieve.oci_component_descriptor_lookup(oci_client=oci_client)

    for component in iter_components_to_purge(
        backup_retention_count=backup_retention_count,
        ocm_repo=ocm_repo,
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
            resource: cm.Resource
            resource.access: cm.LocalBlobAccess

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
        '--k8s-namespace',
        help='specify kubernetes cluster namespace to interact with',
        default=os.environ.get('K8S_TARGET_NAMESPACE'),
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

    cfg_factory = ctx_util.cfg_factory()

    if parsed_arguments.k8s_cfg_name:
        kubernetes_cfg = cfg_factory.kubernetes(parsed_arguments.k8s_cfg_name)
        kubernetes_api = k8s.util.kubernetes_api(kubernetes_cfg=kubernetes_cfg)
    else:
        kubernetes_api = k8s.util.kubernetes_api()

    k8s.logging.init_logging_thread(
        service=config.Services.DELIVERY_DB_BACKUP,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )
    atexit.register(
        k8s.logging.log_to_crd,
        service=config.Services.DELIVERY_DB_BACKUP,
        namespace=namespace,
        kubernetes_api=kubernetes_api,
    )

    logger.info('creating delivery-db backup')

    delivery_gear_extension_cfg_name = ci.util.check_env('DELIVERY_GEAR_CFG_NAME')
    delivery_gear_extension_cfg = cfg_factory.delivery_gear_extensions(
        delivery_gear_extension_cfg_name,
    )

    backup_cfg = delivery_gear_extension_cfg.deliveryDbBackup()

    delivery_db_cfg = cfg_factory.delivery_db(backup_cfg['delivery_db_cfg_name'])
    component_name = backup_cfg['component_name']
    ocm_repo = backup_cfg['ocm_repo']
    additional_args = backup_cfg.get('extra_pg_dump_args', [])
    delivery_service_url = delivery_gear_extension_cfg.defaults()['delivery_service_url']
    backup_retention_count = backup_cfg.get('backup_retention_count')

    delivery_service_client = delivery.client.DeliveryServiceClient(
        routes=delivery.client.DeliveryServiceRoutes(delivery_service_url)
    )

    greatest_version = delivery_service_client.greatest_component_versions(
        component_name=component_name,
        max_versions=1,
        ocm_repo=cm.OciOcmRepository(baseUrl=ocm_repo),
    )[0]

    component_version = version.process_version(
        version_str=greatest_version,
        operation='bump_minor',
    )

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

    oci_client = ccc.oci.oci_client(cfg_factory=cfg_factory)

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

    cnudie.upload.upload_component_descriptor(
        component_descriptor=component_descriptor,
        on_exist=cnudie.upload.UploadMode.OVERWRITE,
        oci_client=oci_client,
    )

    logger.info(f'backup successful. {ocm_repo=} ; {component_name=} ; {component_version=}')

    if not backup_retention_count:
        return

    delete_old_backup_versions(
        backup_retention_count=backup_retention_count,
        oci_ref=cnudie.util.oci_ref(component),
        cfg_factory=cfg_factory,
        ocm_repo=ocm_repo,
        component=component,
    )


if __name__ == '__main__':
    main()
