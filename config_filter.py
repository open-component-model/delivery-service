import collections.abc
import dataclasses
import enum
import logging

import dacite

import cnudie.iter
import reutil


logger = logging.getLogger(__name__)


class ComponentFilterSemantics(enum.StrEnum):
    INCLUDE = 'include'
    EXCLUDE = 'exclude'


@dataclasses.dataclass
class ConfigRule:
    target: str
    expression: str
    matching_semantics: ComponentFilterSemantics


@dataclasses.dataclass
class MatchingConfig:
    name: str
    rules: list[ConfigRule]


def matching_configs_from_dicts(
    dicts: collections.abc.Iterable[dict],
) -> list[MatchingConfig]:
    return [
        dacite.from_dict(
            data_class=MatchingConfig,
            data=d,
            config=dacite.Config(
                cast=[ComponentFilterSemantics]
            )
        ) for d in dicts
    ]


def filter_for_matching_configs(
    configs: collections.abc.Collection[MatchingConfig]
) -> collections.abc.Callable[[cnudie.iter.Node], bool]:
    if not configs:
        def match_all(node: cnudie.iter.Node):
            return True

        return match_all

    # A filter for several matching configs is the combination of its constituent filters joined
    # with a boolean OR
    filters_from_configs = [
        filter_for_matching_config(
            config=config,
        ) for config in configs
    ]
    return lambda node: any(
        filter_func(node) for filter_func in filters_from_configs
    )


def filter_for_matching_config(
    config: MatchingConfig,
) -> collections.abc.Callable[[cnudie.iter.Node], bool]:
    # A filter for a single matching configs is the combination of the filters for its rules joined
    # with a boolean AND
    rule_filters = [
        filter_for_rule(
            rule=rule,
        ) for rule in config.rules
    ]
    return lambda node: all(
        filter_func(node) for filter_func in rule_filters
    )


def traverse_path(
    obj: dict,
    path: list[str],
    absent_ok: bool=True,
):
    '''
    recursively traverse path to finally extract value, similar to `pydash.get`.
    if `absent_ok` and path cannot be traversed, `None` is returned.
    '''
    if not (element := obj.get(path[0])):
        if absent_ok:
            return None
        raise ValueError('element must not be empty, unable to traverse path')

    if len(path) == 1:
        return element

    return traverse_path(
        obj=element,
        path=path[1:],
        absent_ok=absent_ok,
    )


def filter_for_rule(
    rule: ConfigRule,
) -> collections.abc.Callable[[cnudie.iter.Node], bool]:
    def to_str(value):
        if isinstance(value, str):
            return value
        elif isinstance(value, bool):
            return 'true' if value else 'false'
        elif isinstance(value, int) or isinstance(value, float):
            return str(value)
        elif isinstance(value, enum.Enum):
            return value.value
        else:
            logger.warning(f'selected {value=} is no scalar - matching will likely fail')
            return str(value)

    match rule.matching_semantics:
        case ComponentFilterSemantics.INCLUDE:
            re_filter = reutil.re_filter(
                include_regexes=[rule.expression],
                value_transformation=to_str,
            )
        case ComponentFilterSemantics.EXCLUDE:
            re_filter = reutil.re_filter(
                exclude_regexes=[rule.expression],
                value_transformation=to_str,
            )
        case _:
            raise NotImplementedError(rule.matching_semantics)

    def filter_func(node: cnudie.iter.Node):
        match rule.target.split('.'):
            case ['component', *tail]:
                return re_filter(
                    traverse_path(
                        obj=dataclasses.asdict(node.component),
                        path=tail,
                    )
                )
            case ['resource', *tail]:
                # tail = ['extraIdentity', 'platform']
                if not isinstance(node, cnudie.iter.ResourceNode):
                    return True

                return re_filter(
                    traverse_path(
                        obj=dataclasses.asdict(node.resource),
                        path=tail,
                    )
                )
            case ['source', *tail]:
                if not isinstance(node, cnudie.iter.SourceNode):
                    return True

                return re_filter(
                    traverse_path(
                        obj=dataclasses.asdict(node.source),
                        path=tail,
                    )
                )
            case _:
                raise ValueError(f"Unable to parse matching rule '{rule.target}'")

    return filter_func
