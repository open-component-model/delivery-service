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
    def from_cfg_factory(
        cfg_factory=None,
    ) -> typing.Self:
        '''
        As a means to be backwards compatible for usages of github.com/gardener/cc-utils's
        `ConfigFactory` (esp. useful for local development within the Gardener unit or existing
        deployment pipelines), this function takes assumptions about the structure of the previous
        model classes to convert them to the models utilised by this `SecretFactory`.
        '''
        secrets_dict = collections.defaultdict(dict)

        if not cfg_factory:
            import ci.util
            cfg_factory = ci.util.ctx().cfg_factory()

        for cfg_type in cfg_factory._cfg_types():
            elements = []
            for element_name in cfg_factory._cfg_element_names(cfg_type_name=cfg_type):
                try:
                    elements.append(cfg_factory._cfg_element(
                        cfg_type_name=cfg_type,
                        cfg_name=element_name,
                    ))
                except:
                    logger.warning(f'could not retrieve {element_name=} for {cfg_type=}')

            key = cfg_type.replace('_', '-')

            for element in elements:
                if cfg_type == 'aws':
                    import secret_mgmt.aws
                    secrets_dict[key][element._name] = secret_mgmt.aws.AWS(
                        access_key_id=element.access_key_id(),
                        secret_access_key=element.secret_access_key(),
                        region=element.region(),
                    )
                elif cfg_type == 'bdba':
                    import secret_mgmt.bdba
                    secrets_dict[key][element._name] = secret_mgmt.bdba.BDBA(
                        api_url=element.api_url(),
                        group_ids=element.group_ids(),
                        token=element.credentials().token(),
                        tls_verify=element.tls_verify(),
                    )
                elif cfg_type == 'blackduck':
                    import secret_mgmt.blackduck
                    secrets_dict[key][element._name] = secret_mgmt.blackduck.BlackDuck(
                        api_url=element.api_url(),
                        group_id=element.group_id(),
                        token=element.credentials()['token'],
                    )
                elif cfg_type == 'delivery_db':
                    import secret_mgmt.delivery_db
                    secrets_dict[key][element._name] = secret_mgmt.delivery_db.DeliveryDB(
                        username=element.credentials().username(),
                        password=element.credentials().password(),
                    )
                elif cfg_type == 'github':
                    import secret_mgmt.github
                    creds = element.credentials_with_most_remaining_quota()
                    secrets_dict[key][element._name] = secret_mgmt.github.GitHub(
                        api_url=element.api_url(),
                        http_url=element.http_url(),
                        username=creds.username(),
                        auth_token=creds.auth_token(),
                        repo_urls=element.repo_urls(),
                        tls_verify=element.tls_validation(),
                    )
                elif cfg_type == 'github_app':
                    import secret_mgmt.github
                    secrets_dict[key][element._name] = secret_mgmt.github.GitHubApp(
                        api_url=element.api_url(),
                        app_id=element.app_id(),
                        mappings=[
                            dacite.from_dict(
                                data_class=secret_mgmt.github.GitHubAppMapping,
                                data=mapping,
                            ) for mapping in element.mappings()
                        ],
                        private_key=element.private_key(),
                    )
                elif cfg_type == 'kubernetes':
                    import secret_mgmt.kubernetes
                    secrets_dict[key][element._name] = secret_mgmt.kubernetes.Kubernetes(
                        kubeconfig=element.kubeconfig(),
                    )
                elif cfg_type == 'delivery':
                    if rbac_cfg := getattr(element, 'rbac', None):
                        import secret_mgmt.rbac

                        secrets_dict['rbac'][element._name] = secret_mgmt.rbac.RoleBindings(
                            permissions=[
                                dacite.from_dict(
                                    data_class=secret_mgmt.rbac.Permission,
                                    data=permission_raw,
                                ) for permission_raw in rbac_cfg().get('permissions', [])
                            ],
                            roles=[
                                dacite.from_dict(
                                    data_class=secret_mgmt.rbac.Role,
                                    data=role_raw,
                                ) for role_raw in rbac_cfg().get('roles', [])
                            ],
                        )
                    if oauth_cfgs := element.oauth_cfgs():
                        import secret_mgmt.oauth_cfg

                        for idx, oauth_cfg in enumerate(oauth_cfgs):
                            secrets_dict['oauth-cfg'][f'{element._name}{idx}'] = secret_mgmt.oauth_cfg.OAuthCfg( # noqa: E501
                                name=oauth_cfg['name'],
                                type=secret_mgmt.oauth_cfg.OAuthCfgTypes(oauth_cfg['type']),
                                api_url=oauth_cfg['api_url'],
                                client_id=oauth_cfg['client_id'],
                                client_secret=oauth_cfg['client_secret'],
                                role_bindings=[
                                    dacite.from_dict(
                                        data_class=secret_mgmt.oauth_cfg.RoleBinding,
                                        data=role_binding_raw,
                                        config=dacite.Config(
                                            cast=[enum.Enum],
                                        ),
                                    ) for role_binding_raw in oauth_cfg.get('role_bindings', [])
                                ],
                            )
                    if signing_cfgs := element.signing_cfgs():
                        import secret_mgmt.signing_cfg

                        for idx, signing_cfg in enumerate(signing_cfgs):
                            secrets_dict['signing-cfg'][f'{element._name}{idx}'] = secret_mgmt.signing_cfg.SigningCfg( # noqa: E501
                                id=signing_cfg['id'],
                                private_key=signing_cfg['private_key'],
                                public_key=signing_cfg['public_key'],
                                algorithm=signing_cfg['algorithm'],
                                priority=signing_cfg.get('priority', 0),
                            )
                elif cfg_type == 'container_registry':
                    import oci.model
                    import secret_mgmt.oci_registry
                    if element.registry_type() is oci.model.OciRegistryType.AWS:
                        username = element.credentials().access_key_id()
                    else:
                        username = element.credentials().username()
                    secrets_dict['oci-registry'][element._name] = secret_mgmt.oci_registry.OciRegistry( # noqa: E501
                        username=username,
                        password=element.credentials().passwd(),
                        image_reference_prefixes=element.image_reference_prefixes(),
                        privileges=element.privileges(),
                    )
                else:
                    secrets_dict[key][element._name] = GenericModelElement(
                        name=element._name,
                        raw=element.raw,
                        type_name=key,
                    )

        return SecretFactory(
            secrets_dict=secrets_dict,
        )

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
