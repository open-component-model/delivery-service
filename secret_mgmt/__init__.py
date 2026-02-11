import collections.abc
import dataclasses
import enum
import logging
import os
import typing

import dacite
import dacite.exceptions
import yaml

import util

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class GenericModelElement:
    name: str
    raw: dict
    type_name: str = None

    def __getattr__(self, attr):
        if attr in self.raw:
            return self.raw[attr]
        raise AttributeError(f'class has no attribute {attr}')

    def __str__(self):
        return f'{self.name}: {self.raw}'


class SecretTypeNotFound(ValueError):
    pass


class SecretElementNotFound(ValueError):
    pass


def default_secret_type_to_class(secret_type: str) -> object:
    match secret_type:
        case 'aws':
            import secret_mgmt.aws
            return secret_mgmt.aws.AWS
        case 'blackduck':
            import secret_mgmt.blackduck
            return secret_mgmt.blackduck.BlackDuck
        case 'bdba':
            import secret_mgmt.bdba
            return secret_mgmt.bdba.BDBA
        case 'delivery-db':
            import secret_mgmt.delivery_db
            return secret_mgmt.delivery_db.DeliveryDB
        case 'github':
            import secret_mgmt.github
            return secret_mgmt.github.GitHub
        case 'github-app':
            import secret_mgmt.github
            return secret_mgmt.github.GitHubApp
        case 'kubernetes':
            import secret_mgmt.kubernetes
            return secret_mgmt.kubernetes.Kubernetes
        case 'ppms':
            import secret_mgmt.ppms
            return secret_mgmt.ppms.PPMS
        case 'oauth-cfg':
            import secret_mgmt.oauth_cfg
            return secret_mgmt.oauth_cfg.OAuthCfg
        case 'oci-registry':
            import secret_mgmt.oci_registry
            return secret_mgmt.oci_registry.OciRegistry
        case 'rbac':
            import secret_mgmt.rbac
            return secret_mgmt.rbac.RoleBindings
        case 'signing-cfg':
            import secret_mgmt.signing_cfg
            return secret_mgmt.signing_cfg.SigningCfg
        case _:
            return GenericModelElement


class SecretFactory:
    _secrets_dict: dict[str, dict[str, object]]

    @staticmethod
    def from_dir(
        secrets_dir: str,
        secret_type_to_class: collections.abc.Callable[[str], object]=default_secret_type_to_class,
        type_hooks: dict={}
    ) -> typing.Self:
        '''
        The referenced `secrets_dir` is expected to have a directory structure where the directories
        are named like the respective secret type and the files within are named like the respective
        secret element name. Within such a file, exactly one secret is expected according to the
        model class defined for the secret type.

        Example::

            secrets_dir
            |- github
            |  |- github_com
            |- oci-registry
            |  |- ghcr_io_readonly
            |  |- ghcr_io_readwrite
            |  |- ghcr_io_admin

        The secret factory is intended to be extensible so that new types may be added dynamically
        without requiring the general model to be adjusted. Therefore, `secret_type_to_class` can be
        overwritten to add custom type-to-model-class mappings. Note that passing such a custom
        mapping will _overwrite_ the existing mapping instead of extending it. To be able to use the
        general models as well, those will have to be considered in the custom mapping too.
        '''
        secrets_dict: dict[str, dict[str, object]] = {}

        for secret_type in os.listdir(secrets_dir):
            secret_type_dir = os.path.join(secrets_dir, secret_type)
            secret_type_class = secret_type_to_class(secret_type)

            secrets_dict[secret_type] = {}

            for secret_element_name in os.listdir(secret_type_dir):
                secret_element_path = os.path.join(secret_type_dir, secret_element_name)

                if not os.path.isfile(secret_element_path):
                    continue

                with open(secret_element_path) as f:
                    secret_element_raw = yaml.safe_load(f)

                try:
                    secret_element = dacite.from_dict(
                        data_class=secret_type_class,
                        data=secret_element_raw,
                        config=dacite.Config(
                            type_hooks=type_hooks,
                            cast=[enum.Enum],
                        ),
                    )
                except dacite.exceptions.DaciteError as e:
                    e.add_note(f'{secret_type=}')
                    raise

                secrets_dict[secret_type][secret_element_name] = secret_element

        return SecretFactory(
            secrets_dict=secrets_dict,
        )

    def __init__(
        self,
        secrets_dict: dict[str, dict[str, object]],
    ):
        self._secrets_dict = secrets_dict

    def __dir__(self):
        # prepend factory methods (improve REPL-shell experience)
        yield from [
            secret_type.replace('-', '_')
            for secret_type in self.secret_types()
        ]
        yield from super().__dir__()

    def __getattr__(
        self,
        secret_type: str,
    ):
        def func(secret_element_name: str | None=None):
            if secret_element_name:
                return self.secret_element_value(
                    secret_type=secret_type.replace('_', '-'),
                    secret_element_name=secret_element_name,
                )
            else:
                return self.secret_element_values(
                    secret_type=secret_type.replace('_', '-'),
                )

        return func

    def _validate_secret_type(
        self,
        secret_type: str,
    ):
        if secret_type in self._secrets_dict:
            return

        known_secret_types = sorted(secret_type for secret_type in self._secrets_dict)

        raise SecretTypeNotFound(
            f'Secret type "{secret_type}" is unknown or does not contain any secret elements. '
            f'Known secret types: {known_secret_types}.'
        )

    def _validate_secret_element_name(
        self,
        secret_type: str,
        secret_element_name: str,
    ):
        secret_element_names = self.secret_element_names(secret_type)

        if secret_element_name in secret_element_names:
            return

        raise SecretElementNotFound(
            f'Secret element "{secret_element_name}" is unknown for secret type "{secret_type}". '
            f'Known secret elements: {sorted(secret_element_names)}.'
        )

    def secret_types(self) -> list[str]:
        return list(self._secrets_dict.keys())

    def secret_elements(
        self,
        secret_type: str,
    ) -> dict[str, object]:
        self._validate_secret_type(secret_type)

        return self._secrets_dict[secret_type]

    def secret_element_names(
        self,
        secret_type: str,
    ) -> list[str]:
        self._validate_secret_type(secret_type)

        return list(self._secrets_dict[secret_type].keys())

    def secret_element_values(
        self,
        secret_type: str,
    ) -> list[object]:
        self._validate_secret_type(secret_type)

        return list(self._secrets_dict[secret_type].values())

    def secret_element_value(
        self,
        secret_type: str,
        secret_element_name: str,
    ) -> object:
        self._validate_secret_element_name(
            secret_type=secret_type,
            secret_element_name=secret_element_name,
        )

        return self.secret_elements(secret_type)[secret_element_name]

    def serialise(self) -> dict:
        return util.dict_serialisation(self._secrets_dict)
