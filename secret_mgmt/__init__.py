import collections.abc
import enum
import os
import typing

import dacite
import dacite.exceptions
import yaml

import util


class SecretTypeNotFound(ValueError):
    pass


class SecretElementNotFound(ValueError):
    pass


def default_secret_type_to_class(secret_type: str) -> object:
    match secret_type:
        case 'aws':
            import secret_mgmt.aws
            return secret_mgmt.aws.AWS
        case 'bdba':
            import secret_mgmt.bdba
            return secret_mgmt.bdba.BDBA
        case 'delivery-db':
            import secret_mgmt.delivery_db
            return secret_mgmt.delivery_db.DeliveryDB
        case 'github':
            import secret_mgmt.github
            return secret_mgmt.github.GitHub
        case 'kubernetes':
            import secret_mgmt.kubernetes
            return secret_mgmt.kubernetes.Kubernetes
        case 'oauth-cfg':
            import secret_mgmt.oauth_cfg
            return secret_mgmt.oauth_cfg.OAuthCfg
        case 'oci-registry':
            import secret_mgmt.oci_registry
            return secret_mgmt.oci_registry.OciRegistry
        case 'signing-cfg':
            import secret_mgmt.signing_cfg
            return secret_mgmt.signing_cfg.SigningCfg
        case _:
            raise SecretTypeNotFound(secret_type)


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
        secrets_dict: dict[str, dict[str, object]] = {}

        if not cfg_factory:
            import ci.util
            cfg_factory = ci.util.ctx().cfg_factory()

        if aws_cfgs := list(cfg_factory._cfg_elements(cfg_type_name='aws')):
            import secret_mgmt.aws
            secrets_dict['aws'] = {}

            for aws_cfg in aws_cfgs:
                secrets_dict['aws'][aws_cfg._name] = secret_mgmt.aws.AWS(
                    access_key_id=aws_cfg.access_key_id(),
                    secret_access_key=aws_cfg.secret_access_key(),
                    region=aws_cfg.region(),
                )

        if (
            'bdba' in cfg_factory._cfg_types()
            and (bdba_cfgs := list(cfg_factory._cfg_elements(cfg_type_name='bdba')))
        ):
            import secret_mgmt.bdba
            secrets_dict['bdba'] = {}

            for bdba_cfg in bdba_cfgs:
                secrets_dict['bdba'][bdba_cfg._name] = secret_mgmt.bdba.BDBA(
                    api_url=bdba_cfg.api_url(),
                    group_ids=bdba_cfg.group_ids(),
                    token=bdba_cfg.credentials().token(),
                    tls_verify=bdba_cfg.tls_verify(),
                )

        if (
            'delivery_db' in cfg_factory._cfg_types()
            and (delivery_db_cfgs := list(cfg_factory._cfg_elements(cfg_type_name='delivery_db')))
        ):
            import secret_mgmt.delivery_db
            secrets_dict['delivery-db'] = {}

            for delivery_db_cfg in delivery_db_cfgs:
                secrets_dict['delivery-db'][delivery_db_cfg._name] = secret_mgmt.delivery_db.DeliveryDB( # noqa: E501
                    hostname=delivery_db_cfg.hostname(),
                    port=delivery_db_cfg.port(),
                    username=delivery_db_cfg.credentials().username(),
                    password=delivery_db_cfg.credentials().password(),
                    db_type=delivery_db_cfg.db_type(),
                )

        if github_cfgs := list(cfg_factory._cfg_elements(cfg_type_name='github')):
            import secret_mgmt.github
            secrets_dict['github'] = {}

            for github_cfg in github_cfgs:
                credentials = github_cfg.credentials_with_most_remaining_quota()
                secrets_dict['github'][github_cfg._name] = secret_mgmt.github.GitHub(
                    api_url=github_cfg.api_url(),
                    http_url=github_cfg.http_url(),
                    username=credentials.username(),
                    auth_token=credentials.auth_token(),
                    repo_urls=github_cfg.repo_urls(),
                    tls_verify=github_cfg.tls_validation(),
                )

        if kubernetes_cfgs := list(cfg_factory._cfg_elements(cfg_type_name='kubernetes')):
            import secret_mgmt.kubernetes
            secrets_dict['kubernetes'] = {}

            for kubernetes_cfg in kubernetes_cfgs:
                secrets_dict['kubernetes'][kubernetes_cfg._name] = secret_mgmt.kubernetes.Kubernetes(
                    kubeconfig=kubernetes_cfg.kubeconfig(),
                )

        if (
            'delivery' in cfg_factory._cfg_types()
            and (delivery_cfgs := list(cfg_factory._cfg_elements(cfg_type_name='delivery')))
        ):
            for delivery_cfg in delivery_cfgs:
                if oauth_cfgs := delivery_cfg.oauth_cfgs():
                    import secret_mgmt.oauth_cfg
                    secrets_dict['oauth-cfg'] = secrets_dict.get('oauth-cfg', {})

                    for idx, oauth_cfg in enumerate(oauth_cfgs):
                        secrets_dict['oauth-cfg'][f'{delivery_cfg._name}{idx}'] = secret_mgmt.oauth_cfg.OAuthCfg( # noqa: E501
                            name=oauth_cfg['name'],
                            type=secret_mgmt.oauth_cfg.OAuthCfgTypes(oauth_cfg['type']),
                            github_secret_name=oauth_cfg['github_cfg'],
                            oauth_url=oauth_cfg['oauth_url'],
                            token_url=oauth_cfg['token_url'],
                            client_id=oauth_cfg['client_id'],
                            client_secret=oauth_cfg['client_secret'],
                            scope=oauth_cfg.get('scope'),
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

                if signing_cfgs := delivery_cfg.signing_cfgs():
                    import secret_mgmt.signing_cfg
                    secrets_dict['signing-cfg'] = secrets_dict.get('signing-cfg', {})

                    for idx, signing_cfg in enumerate(signing_cfgs):
                        secrets_dict['signing-cfg'][f'{delivery_cfg._name}{idx}'] = secret_mgmt.signing_cfg.SigningCfg( # noqa: E501
                            id=signing_cfg['id'],
                            private_key=signing_cfg['private_key'],
                            public_key=signing_cfg['public_key'],
                            algorithm=signing_cfg['algorithm'],
                            priority=signing_cfg.get('priority', 0),
                        )

        if oci_registry_cfgs := list(cfg_factory._cfg_elements(cfg_type_name='container_registry')):
            import secret_mgmt.oci_registry
            secrets_dict['oci-registry'] = {}

            for oci_registry_cfg in oci_registry_cfgs:
                secrets_dict['oci-registry'][oci_registry_cfg._name] = secret_mgmt.oci_registry.OciRegistry( # noqa: E501
                    username=oci_registry_cfg.credentials().username(),
                    password=oci_registry_cfg.credentials().passwd(),
                    image_reference_prefixes=oci_registry_cfg.image_reference_prefixes(),
                    privileges=oci_registry_cfg.privileges(),
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
