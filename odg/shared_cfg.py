import dataclasses
import enum
import io
import os

import github3.exceptions
import yaml

import cnudie.retrieve
import ocm

import lookups


own_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.abspath(os.path.join(own_dir, os.pardir))


class ReferenceType(enum.StrEnum):
    GITHUB = 'github'
    LOCAL = 'local'
    OCM = 'ocm'


@dataclasses.dataclass
class SharedCfgReference:
    type: ReferenceType

    def retrieve(self) -> dict:
        raise NotImplementedError('function must be implemented by derived classes')


@dataclasses.dataclass(kw_only=True)
class SharedCfgGitHubReference(SharedCfgReference):
    type: ReferenceType = ReferenceType.GITHUB
    repository: str
    path: str

    def retrieve(self) -> dict:
        github_api_lookup = lookups.github_api_lookup()
        github_repo_lookup = lookups.github_repo_lookup(github_api_lookup)

        repo = github_repo_lookup(self.repository)

        try:
            file_contents = repo.file_contents(self.path).decoded.decode()
        except github3.exceptions.NotFoundError as e:
            e.add_note(f'did not find default cfg file for {self}')
            raise

        return yaml.safe_load(file_contents)


@dataclasses.dataclass(kw_only=True)
class SharedCfgLocalReference(SharedCfgReference):
    type: ReferenceType = ReferenceType.LOCAL
    path: str

    def retrieve(self) -> dict:
        with open(os.path.join(root_dir, self.path)) as file:
            return yaml.safe_load(file)


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

    def retrieve(self) -> dict:
        component_descriptor_lookup = lookups.init_component_descriptor_lookup()

        if self.ocm_repo:
            component: ocm.Component = component_descriptor_lookup(
                self.component_id,
                ocm_repository_lookup=cnudie.retrieve.ocm_repository_lookup(self.ocm_repo),
            ).component
        else:
            component: ocm.Component = component_descriptor_lookup(self.component_id).component

        def matches(artefact: ocm.Artifact) -> bool:
            if self.artefact_name != artefact.name:
                return False
            if self.artefact_version and self.artefact_version != artefact.version:
                return False

            if self.artefact_extra_id:
                for key, value in self.artefact_extra_id.items():
                    if artefact.extraIdentity.get(key) != value:
                        return False

            return True

        for artefact in component.iter_artefacts():
            if matches(artefact=artefact):
                break
        else:
            raise ValueError(f'did not find requested OCM artefact for {self}')

        access = artefact.access

        if not isinstance(access, ocm.LocalBlobAccess):
            raise TypeError(f'{artefact.name=} has {access.type=} only localBlobAccess is supported')

        oci_client = lookups.semver_sanitising_oci_client()

        digest = access.globalAccess.digest if access.globalAccess else access.localReference

        blob = oci_client.blob(
            image_reference=component.current_ocm_repo.component_oci_ref(component),
            digest=digest,
            stream=False, # cfg-files are typically small, do not bother with streaming
        )

        return yaml.safe_load(io.BytesIO(blob.content))
