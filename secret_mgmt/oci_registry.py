import collections.abc
import dataclasses
import functools

import oci.auth
import oci.model
import oci.util

import secret_mgmt


@dataclasses.dataclass
class OciRegistry:
    username: str
    password: str
    image_reference_prefixes: list[str]
    privileges: oci.auth.Privileges = oci.auth.Privileges.READONLY

    def image_reference_matches(
        self,
        image_reference: oci.model.OciImageReference | str,
        privileges: oci.auth.Privileges=None,
    ) -> bool:
        image_reference = str(image_reference)

        if not self.image_reference_prefixes:
            return False

        if privileges and self.privileges < privileges:
            return False

        for image_reference_prefix in self.image_reference_prefixes:
            if image_reference.startswith(image_reference_prefix):
                return True

        return False


def find_cfg(
    secret_factory: secret_mgmt.SecretFactory,
    image_reference: oci.model.OciImageReference | str,
    privileges: oci.auth.Privileges=None,
    _normalised_image_reference: bool=False,
) -> OciRegistry | None:
    if isinstance(image_reference, oci.model.OciImageReference):
        image_reference = image_reference.normalised_image_reference
        _normalised_image_reference = True

    oci_registry_cfgs: list[OciRegistry] = secret_factory.oci_registry()

    matching_cfgs = (
        oci_registry_cfg
        for oci_registry_cfg in oci_registry_cfgs
        if oci_registry_cfg.image_reference_matches(
            image_reference=image_reference,
            privileges=privileges,
        )
    )

    sorted_matching_cfgs = sorted(
        matching_cfgs,
        key=lambda cfg: cfg.privileges,
    )

    if not sorted_matching_cfgs:
        if _normalised_image_reference:
            # finally give up - did not match anything, even after normalisation
            return None
        else:
            return find_cfg(
                secret_factory=secret_factory,
                image_reference=oci.util.normalise_image_reference(image_reference=image_reference),
                privileges=privileges,
                _normalised_image_reference=True,
            )

    # return first match (because they are sorted, this will be the one with least privileges)
    return sorted_matching_cfgs[0]


@functools.lru_cache
def oci_cfg_lookup(
    secret_factory: secret_mgmt.SecretFactory,
) -> collections.abc.Callable[[str, oci.auth.Privileges, bool], oci.auth.OciCredentials]:
    def find_credentials(
        image_reference: oci.model.OciImageReference | str,
        privileges: oci.auth.Privileges=oci.auth.Privileges.READONLY,
        absent_ok: bool=True,
    ):
        oci_registry_cfg = find_cfg(
            secret_factory=secret_factory,
            image_reference=image_reference,
            privileges=privileges,
        )

        if not oci_registry_cfg:
            if absent_ok:
                return None # fallback to docker-cfg (or try w/o auth)

            raise RuntimeError(f'No credentials found for {image_reference=} with {privileges=}')

        return oci.auth.OciBasicAuthCredentials(
            username=oci_registry_cfg.username,
            password=oci_registry_cfg.password,
        )

    return find_credentials
