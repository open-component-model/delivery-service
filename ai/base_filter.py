import abc
import typing

import gci.componentmodel

import ai.filter_json_structure


class BaseFilter(abc.ABC):
    def __init__(
        self,
        name: str,
        description: str,
    ) -> None:
        self.name = name
        self.description = description

    def filter_info(self):
        return {"name": self.name, "description": self.description}

    @abc.abstractmethod
    def filter(
        self,
        question: str,
        path: list[str],
        whole_plan: ai.filter_json_structure.FilterJsonStruckture,
    ) -> set[typing.Any]:
        pass


# ---------------------------------------
# Run Filters
# ---------------------------------------

FilterOperatorsList = typing.Union[
    list[ai.filter_json_structure.Filter],
    list[ai.filter_json_structure.OperatorNOT],
    list[ai.filter_json_structure.OperatorOR],
    list[ai.filter_json_structure.OperatorAND],
]
FilterOperator = typing.Union[
    ai.filter_json_structure.Filter,
    ai.filter_json_structure.OperatorNOT,
    ai.filter_json_structure.OperatorOR,
    ai.filter_json_structure.OperatorAND,
]

def add_to_dict(my_dict: dict, path: list[str], value: typing.Any):
    for key in path[:-1]:
        my_dict = my_dict.setdefault(key, {})
    my_dict[path[-1]] = value

def start_run_filters(
    whole_plan: ai.filter_json_structure.FilterJsonStruckture,
    filter: (
        ai.filter_json_structure.OperatorNOT
        | ai.filter_json_structure.OperatorOR
        | ai.filter_json_structure.OperatorAND
        | None
    ),
    available_filters: list[BaseFilter],
) -> dict[str, str | list[gci.componentmodel.ComponentIdentity]]:
    result_dict: dict[str, str | list[gci.componentmodel.ComponentIdentity]] = {}
    if isinstance(filter, ai.filter_json_structure.OperatorAND):
        recursive_run_filters(
            whole_plan=whole_plan,
            filter=filter.filter,
            available_filters=available_filters,
            path=["AND"],
            result_dict=result_dict,
        )
    elif isinstance(filter, ai.filter_json_structure.OperatorOR):
        recursive_run_filters(
            whole_plan=whole_plan,
            filter=filter.filter,
            available_filters=available_filters,
            path=["OR"],
            result_dict=result_dict,
        )
    elif isinstance(filter, ai.filter_json_structure.OperatorNOT):
        recursive_run_filters(
            whole_plan=whole_plan,
            filter=filter.filterA,
            available_filters=available_filters,
            path=["NOT"] + ["A"],
            result_dict=result_dict,
        )
        recursive_run_filters(
            whole_plan=whole_plan,
            filter=filter.filterB,
            available_filters=available_filters,
            path=["NOT"] + ["B"],
            result_dict=result_dict,
        )
    else:
        raise ValueError(
            "filters_plan of type Condition has no valid condition selected!"
        )

    return result_dict

def recursive_run_filters(
    whole_plan: ai.filter_json_structure.FilterJsonStruckture,
    filter: FilterOperator | FilterOperatorsList,
    available_filters: list[BaseFilter],
    path: list[str],
    result_dict: dict[str, typing.Any],
):
    if isinstance(filter, list):
        for single_filter in filter:
            if isinstance(single_filter, ai.filter_json_structure.Filter):
                for available_filter in available_filters:
                    if available_filter.name == single_filter.filter_name:
                        filter_result = available_filter.filter(
                            single_filter.instruction,
                            path + [single_filter.filter_name],
                            whole_plan,
                        )
                        add_to_dict(
                            result_dict,
                            path + [single_filter.filter_name],
                            list(filter_result),
                        )
            elif isinstance(single_filter, ai.filter_json_structure.OperatorNOT):
                recursive_run_filters(
                    whole_plan=whole_plan,
                    filter=single_filter.filterA,
                    available_filters=available_filters,
                    path=path + [(single_filter.logical_operator)] + ["A"],
                    result_dict=result_dict,
                )
                recursive_run_filters(
                    whole_plan=whole_plan,
                    filter=single_filter.filterB,
                    available_filters=available_filters,
                    path=path + [(single_filter.logical_operator)] + ["B"],
                    result_dict=result_dict,
                )
            else:
                recursive_run_filters(
                    whole_plan=whole_plan,
                    filter=single_filter.filter,
                    available_filters=available_filters,
                    path=path + [single_filter.logical_operator],
                    result_dict=result_dict,
                )

    else:
        if isinstance(filter, ai.filter_json_structure.Filter):
            for available_filter in available_filters:
                if available_filter.name == filter.filter_name:
                    filter_result = available_filter.filter(
                        filter.instruction, path + [filter.filter_name], whole_plan
                    )
                    add_to_dict(
                        result_dict, path + [filter.filter_name], list(filter_result)
                    )
        elif isinstance(filter, ai.filter_json_structure.OperatorNOT):
            recursive_run_filters(
                whole_plan=whole_plan,
                filter=filter.filterA,
                available_filters=available_filters,
                path=path + [(filter.logical_operator)] + ["A"],
                result_dict=result_dict,
            )
            recursive_run_filters(
                whole_plan=whole_plan,
                filter=filter.filterB,
                available_filters=available_filters,
                path=path + [(filter.logical_operator)] + ["B"],
                result_dict=result_dict,
            )
        else:
            recursive_run_filters(
                whole_plan=whole_plan,
                filter=filter.filter,
                available_filters=available_filters,
                path=path + [(filter.logical_operator)],
                result_dict=result_dict,
            )


# ---------------------------------------
# Merge Filters
# ---------------------------------------

def not_operator(list1, list2):
    return [item for item in list1 if item not in list2]


def or_operator(*lists):
    result = []
    for lst in lists:
        result.extend(lst)
    return list(set(result))


def and_operator(*lists):
    result = set(lists[0])
    for lst in lists[1:]:
        result.intersection_update(lst)
    return list(result)


def combine_lists(data):
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "NOT":
                return not_operator(
                    combine_lists(value.get("A", [])), combine_lists(value.get("B", []))
                )
            if key == "OR":
                return or_operator(*[combine_lists(v) for v in value.values()])
            if key == "AND":
                return and_operator(*[combine_lists(v) for v in value.values()])

            print("-------------")
            print(key)
            print(value)
            print("-------------")
            return value
    elif isinstance(data, list):
        return data
    else:
        return []
