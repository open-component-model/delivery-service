import collections.abc
import dataclasses
import enum
import io
import os

import github3.exceptions
import github3.repos
import yaml

import cnudie.retrieve
import oci.client
import ocm

import ctx_util
import lookups
import secret_mgmt


own_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.abspath(os.path.join(own_dir, os.pardir))


class ReferenceType(enum.StrEnum):
    GITHUB = 'github'
    LOCAL = 'local'
    OCM = 'ocm'


@dataclasses.dataclass
class SharedCfgReference:
    type: ReferenceType


@dataclasses.dataclass(kw_only=True)
class SharedCfgGitHubReference(SharedCfgReference):
    type: ReferenceType = ReferenceType.GITHUB
    repository: str
    path: str


@dataclasses.dataclass(kw_only=True)
class SharedCfgLocalReference(SharedCfgReference):
    type: ReferenceType = ReferenceType.LOCAL
    path: str


@dataclasses.dataclass(kw_only=True)
class SharedCfgOCMReference(SharedCfgReference):
    type: ReferenceType = ReferenceType.OCM
    component_name: str
    component_version: str
    artefact_name: str
    artefact_version: str | None
    artefact_extra_id: dict | None
    ocm_repo_url: str | None

    @property
    def component_id(self) -> ocm.ComponentIdentity:
        return ocm.ComponentIdentity(
            name=self.component_name,
            version=self.component_version,
        )

    @property
    def ocm_repo(self) -> ocm.OciOcmRepository | None:
        if not self.ocm_repo_url:
            return None

        return ocm.OciOcmRepository(baseUrl=self.ocm_repo_url)


def shared_cfg_lookup(
    secret_factory: secret_mgmt.SecretFactory | None=None,
    github_repo_lookup: collections.abc.Callable[[str], github3.repos.Repository] | None=None,
    oci_client: oci.client.Client | None=None,
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById | None=None,
) -> collections.abc.Callable[[SharedCfgReference], dict]:
    '''
    Creates a shared-cfg-lookup. Ideally, this lookup should be created at application launch, and
    passed to consumers.
    '''
    if not secret_factory:
        secret_factory = ctx_util.secret_factory()

    if not github_repo_lookup:
        github_api_lookup = lookups.github_api_lookup(secret_factory)
        github_repo_lookup = lookups.github_repo_lookup(github_api_lookup)

    if not oci_client:
        oci_client = lookups.semver_sanitising_oci_client(secret_factory)

    if not component_descriptor_lookup:
        component_descriptor_lookup = lookups.init_component_descriptor_lookup()

    def retrieve_github_ref(
        github_ref: SharedCfgGitHubReference,
    ) -> dict:
        repo = github_repo_lookup(github_ref.repository)

        try:
            file_contents = repo.file_contents(github_ref.path).decoded.decode()
        except github3.exceptions.NotFoundError as e:
            e.add_note(f'did not find default cfg file for {github_ref=}')
            raise

        return yaml.safe_load(file_contents)

    def retrieve_local_ref(
        local_ref: SharedCfgLocalReference,
    ) -> dict:
        with open(os.path.join(root_dir, local_ref.path)) as file:
            return yaml.safe_load(file)

    def retrieve_ocm_ref(
        ocm_ref: SharedCfgOCMReference,
    ) -> dict:
        if ocm_ref.ocm_repo:
            component = component_descriptor_lookup(
                ocm_ref.component_id,
                ocm_repository_lookup=cnudie.retrieve.ocm_repository_lookup(ocm_ref.ocm_repo),
            ).component
        else:
            component = component_descriptor_lookup(ocm_ref.component_id).component

        def matches(artefact: ocm.Artifact) -> bool:
            if ocm_ref.artefact_name != artefact.name:
                return False
            if ocm_ref.artefact_version and ocm_ref.artefact_version != artefact.version:
                return False

            if ocm_ref.artefact_extra_id:
                for key, value in ocm_ref.artefact_extra_id.items():
                    if artefact.extraIdentity.get(key) != value:
                        return False

            return True

        for artefact in component.iter_artefacts():
            if matches(artefact=artefact):
                break
        else:
            raise ValueError(f'did not find requested OCM artefact for {ocm_ref=}')

        access = artefact.access

        if not isinstance(access, ocm.LocalBlobAccess):
            raise TypeError(f'{artefact.name=} has {access.type=} only localBlobAccess is supported')

        digest = access.globalAccess.digest if access.globalAccess else access.localReference

        blob = oci_client.blob(
            image_reference=component.current_ocm_repo.component_oci_ref(component),
            digest=digest,
            stream=False, # cfg-files are typically small, do not bother with streaming
        )

        return yaml.safe_load(io.BytesIO(blob.content))

    def shared_cfg_lookup(
        shared_cfg_reference: SharedCfgReference,
        /,
    ) -> dict:
        if shared_cfg_reference.type is ReferenceType.GITHUB:
            shared_cfg = retrieve_github_ref(shared_cfg_reference)

        elif shared_cfg_reference.type is ReferenceType.LOCAL:
            shared_cfg = retrieve_local_ref(shared_cfg_reference)

        elif shared_cfg_reference.type is ReferenceType.OCM:
            shared_cfg = retrieve_ocm_ref(shared_cfg_reference)

        else:
            raise ValueError(f'unsupported {shared_cfg_reference.type=}')

        return shared_cfg

    return shared_cfg_lookup
