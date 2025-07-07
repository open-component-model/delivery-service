import collections.abc
import dataclasses

import dacite
import yaml

import paths


@dataclasses.dataclass
class Permission:
    name: str
    routes: list[str] | str
    methods: list[str] | str

    def __post_init__(self):
        if isinstance(self.routes, str):
            self.routes = [self.routes]
        if isinstance(self.methods, str):
            self.methods = [self.methods]


@dataclasses.dataclass
class Role:
    name: str
    permissions: list[str] | str

    def __post_init__(self):
        if isinstance(self.permissions, str):
            self.permissions = [self.permissions]


@dataclasses.dataclass
class RoleBindings:
    '''
    Next to the configured `permissions` and `roles`, there are bultin role bindings which are always
    mixed into the configured ones. If there are naming-collisions, the customly configured role
    bindings take precedence (i.e. it is possible to overwrite the builtin rolebindings by specifying
    role bindings with the same name).
    '''
    permissions: list[Permission] = dataclasses.field(default_factory=list)
    roles: list[Role] = dataclasses.field(default_factory=list)

    def __post_init__(self):
        with open(paths.builtin_role_bindings_path) as file:
            builtin_role_bindings_raw = yaml.safe_load(file)

        builtin_permissions = [
            dacite.from_dict(
                data_class=Permission,
                data=permission_raw,
            ) for permission_raw in builtin_role_bindings_raw.get('permissions', [])
        ]
        builtin_roles = [
            dacite.from_dict(
                data_class=Role,
                data=role_raw,
            ) for role_raw in builtin_role_bindings_raw.get('roles', [])
        ]

        for builtin_permission in builtin_permissions:
            for permission in self.permissions:
                if permission.name == builtin_permission.name:
                    break
            else:
                # did not find permission with same name yet -> add buitin one
                self.permissions.append(builtin_permission)

        for builtin_role in builtin_roles:
            for role in self.roles:
                if role.name == builtin_role.name:
                    break
            else:
                # did not find role with same name yet -> add builtin one
                self.roles.append(builtin_role)

    def find_permission(
        self,
        name: str,
        absent_ok: bool=False,
    ) -> Permission | None:
        for permission in self.permissions:
            if permission.name == name:
                return permission

        if absent_ok:
            return None

        raise ValueError(f'did not find permission with {name=}')

    def filter_roles(
        self,
        names: collections.abc.Sequence[str],
    ) -> collections.abc.Generator[Role, None, None]:
        return (
            role for role in self.roles
            if role.name in names
        )
