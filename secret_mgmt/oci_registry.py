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
    image_reference_prefixes: list[str] = dataclasses.field(default_factory=list)
    privileges: oci.auth.Privileges = oci.auth.Privileges.READONLY

    def image_reference_matches(
        self,
        image_reference: oci.model.OciImageReference | str,
        privileges: oci.auth.Privileges=None,
    ) -> bool:
        image_reference = str(image_reference)

        if privileges and self.privileges < privileges:
            return False

        if not self.image_reference_prefixes:
            # credentials are not restricted to any image-ref prefix -> may always be used
            return True

        for image_reference_prefix in self.image_reference_prefixes:
            if image_reference.startswith(image_reference_prefix):
                return True

        return False


def find_cfg(
    secret_factory: secret_mgmt.SecretFactory,
    image_reference: oci.model.OciImageReference | str,
    privileges: oci.auth.Privileges=None,
    absent_ok: bool=True,
    _normalised_image_reference: bool=False,
) -> OciRegistry | None:
    if isinstance(image_reference, oci.model.OciImageReference):
        image_reference = image_reference.normalised_image_reference
        _normalised_image_reference = True

    try:
        oci_registry_cfgs: list[OciRegistry] = secret_factory.oci_registry()
    except secret_mgmt.SecretTypeNotFound as e:
        if absent_ok:
            return None
        raise ValueError('no OCI registry credentials found') from e

    matching_cfgs = (
        oci_registry_cfg
        for oci_registry_cfg in oci_registry_cfgs
        if oci_registry_cfg.image_reference_matches(
            image_reference=image_reference,
            privileges=privileges,
        )
    )

    # use the cfg with the least (but enough) privileges and the most prefixes (most specific one)
    sorted_matching_cfgs = sorted(
        matching_cfgs,
        key=lambda cfg: (cfg.privileges, -len(cfg.image_reference_prefixes)),
    )

    if not sorted_matching_cfgs:
        if _normalised_image_reference:
            # finally give up - did not match anything, even after normalisation
            if absent_ok:
                return None
            raise ValueError(f'no credentials found for {image_reference=} with {privileges=}')
        else:
            return find_cfg(
                secret_factory=secret_factory,
                image_reference=oci.util.normalise_image_reference(image_reference=image_reference),
                privileges=privileges,
                absent_ok=absent_ok,
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
            absent_ok=absent_ok,
        )

        if not oci_registry_cfg:
            return None

        registry_type = oci.model.OciRegistryType.from_image_ref(image_reference)

        if registry_type is oci.model.OciRegistryType.AWS:
            return oci.auth.OciAccessKeyCredentials(
                access_key_id=oci_registry_cfg.username,
                secret_access_key=oci_registry_cfg.password,
            )

        return oci.auth.OciBasicAuthCredentials(
            username=oci_registry_cfg.username,
            password=oci_registry_cfg.password,
        )

    return find_credentials
