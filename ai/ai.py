'''
AI Endpoint
'''

import os
import pprint
import typing

import cnudie.retrieve
import falcon
import gci.componentmodel
import instructor
import sqlalchemy.orm.session
from langfuse.openai import AzureOpenAI

import ai.base_filter
import ai.filter
import ai.filter_json_structure
import ai.pipelines
import components
import eol
import middleware.auth

OPEN_AI_MODEL: str = os.getenv("OPEN_AI_MODEL")  # type: ignore

client = instructor.from_openai(AzureOpenAI())

examples: dict[str, str] = {
    "component": """
    <question>\n
      Is there a component called \'github.com/gardener/cc-utils\' in the landscape with version 1.2424.0 which does not depend on the packages openssh and golang-runtime or is called github.com/gardener/gardener version 10.4.1?
    </question>\n  
    <answer>
      {
        "filter": {
          "logical_operator": "OR",
          "filter": [
            {
              "logical_operator": "NOT",
              "filterA": {
                "filter_name": "id",
                "instruction": "The component should be called 'github.com/gardener/cc-utils' and have version 1.2424.0"
              },
              "filterB": {
                "logical_operator": "OR",
                "filter": [
                  {
                    "filter_name": "package",
                    "instruction": "Components which depend on the package openssh"
                  },
                  {
                    "filter_name": "package",
                    "instruction": "Components which depend on the package golang-runtime"
                  }
                ]
              }
            }
            {
              "filter_name": "id",
              "instruction": "The component should be called 'github.com/gardener/gardener' and have version 10.4.1"
            }
          ]
        }
      }
    </answer>\n
  """,
    "package": """
    <question>\n
      All Packages which are called openssh and where detected by bdba but dont have a license called 'BSD 3-clause \"New\" or \"Revised\" License'.
    </question>\n  
    <answer>
      {
        "filter": {
          "logical_operator": "OR",
          "filter": [
            {
              "logical_operator": "NOT",
              "filterA": {
                "logical_operator": "AND",
                "filter": [
                  {
                    "filter_name": "package_name_and_version",
                    "instruction": "Packages with the name openssh."
                  },
                  {
                    "filter_name": "data_source",
                    "instruction": "Packages with the data source bdba."
                  }
                ]
              },
              "filterB": {
                "filter_name": "license",
                "instruction": "The packages should have the license called 'BSD 3-clause \"New\" or \"Revised\" License'"
              }
            }
          ]
        }
      }
    </answer>\n
  """,
}

goal = {"component": "OCM (Open Component Model) components", "package": "Packages"}


def choose_filters(
    question: str,
    pipeline_name: typing.Literal["component", "package"],
    available_filters: list[ai.base_filter.BaseFilter],
) -> ai.filter_json_structure.FilterJsonStruckture:
    chosen_filters = client.chat.completions.create(
        model=OPEN_AI_MODEL,
        temperature=0.0,
        response_model=ai.filter_json_structure.FilterJsonStruckture,
        max_retries=10,
        messages=[
            {
                "role": "system",
                "content": (
                    "The user has asked a question."
                    f" The goal of the question is a list of {goal[pipeline_name]}.\n"
                    "\n"
                    f"The current list contains all {goal[pipeline_name]}, for the landscape.\n"
                    "\n"
                    f"Please decide based on the users question, how this big list of {goal[pipeline_name]}"
                    " should be filtered. You can choose only one or several"
                    " filters and then decide, how the resulting lists of the different filters should"
                    " be merged.\n"
                    "You have these different filtering options:\n"
                    "<filter_options>\n"
                    f"{[filter.name for filter in available_filters]}\n"
                    "</filter_options>\n"
                    "You have the following operators at you had to combine the lists of several Filters"
                    " with a logical Operator:"
                    "<operator_options>\n"
                    '  ["AND", "OR", "NOT"]\n'
                    "</operator_options>\n"
                    ""
                    f"In the instruction of a filter do only describe what an {goal[pipeline_name]} should have."
                    " Use the NOT operator for negiation."
                    "\n"
                    "<example>\n"
                    f" {examples[pipeline_name]}"
                    "</example>\n"
                ),
            },
            {"role": "user", "content": question},
        ],
    )

    print("-----------Chosen Filters-----------")
    print(chosen_filters.model_dump_json(indent=2))
    print("\n")

    return chosen_filters


class ComponentPypeline(ai.pipelines.BasePypeline):
    def __init__(
        self,
        landscape_components: list[gci.componentmodel.Component],
        db_session: sqlalchemy.orm.session.Session,
        pipeline_manager: ai.pipelines.PipelineManager,
    ) -> None:
        self.available_filters: list[ai.base_filter.BaseFilter] = [
            ai.filter.ComponentIdFilter(
                name="id",
                description="Filter by component id, which consists of name and version.",
                landscape_components=landscape_components,
                client=client,
            ),
            ai.filter.ComponentPackageFilter(
                name="packages",
                description="Filter by Packages.",
                landscape_components=landscape_components,
                db_session=db_session,
                client=client,
                pipeline_manager=pipeline_manager,
            ),
            ai.filter.ComponentVulnerabilityFilter(
                name="vulnerability",
                description="Filter by Vulnerabilities.",
                landscape_components=landscape_components,
                db_session=db_session,
                client=client,
            ),
            ai.filter.ComponentMalwareFilter(
                name="malware",
                description="Filter by Malware.",
                landscape_components=landscape_components,
                db_session=db_session,
                client=client,
            ),
            ai.filter.ComponentResourcesFilter(
                name="resource",
                description="Filter by Resources.",
                landscape_components=landscape_components,
                db_session=db_session,
                client=client,
            ),
        ]
        self.landscape_components = landscape_components

    def run(self, question: str):
        print("-----------------------------")
        print(f"run component pypeline - question: {question}")
        chosen_filters = choose_filters(question, "component", self.available_filters)

        pprint.pprint(chosen_filters)

        result_dict = ai.base_filter.start_run_filters(
            whole_plan=chosen_filters,
            filter=chosen_filters.filter,
            available_filters=self.available_filters,
        )
        pprint.pprint(result_dict)
        print("-----------------------------")
        return result_dict


class PackagePypeline(ai.pipelines.BasePypeline):
    def __init__(
        self,
        landscape_components: list[gci.componentmodel.Component],
        db_session: sqlalchemy.orm.session.Session,
        pipeline_manager: ai.pipelines.PipelineManager,
    ) -> None:
        self.available_filters: list[ai.base_filter.BaseFilter] = [
            ai.filter.PackageIdFilter(
                name="package_name_and_version",
                description="Filter by Package name and optionally version.",
                landscape_components=landscape_components,
                db_session=db_session,
                client=client,
            ),
            ai.filter.PackageComponentFilter(
                name="component",
                description="Filter Packages by the components they are used in.",
                landscape_components=landscape_components,
                db_session=db_session,
                client=client,
            ),
            ai.filter.PackageVulnerabilityFilter(
                name="vulnerability",
                description="Filter Packages by their vulnerabilities.",
                landscape_components=landscape_components,
                db_session=db_session,
                client=client,
            ),
            ai.filter.PackageLicenseFilter(
                name="licenses",
                description="Filter Packages by their license.",
                landscape_components=landscape_components,
                db_session=db_session,
                client=client,
            ),
            ai.filter.PackageDataSourceFilter(
                name="data_source",
                description="Filter Packages by their Data Source.",
                landscape_components=landscape_components,
                db_session=db_session,
                client=client,
            ),
            ai.filter.PackageResourceFilter(
                name="resource",
                description="Filter Packages by the resource they are used in.",
                landscape_components=landscape_components,
                db_session=db_session,
                client=client,
                pipeline_manager=pipeline_manager,
            ),
        ]
        self.landscape_components = landscape_components

    def run(self, question: str):
        print("-----------------------------")
        print(f"run package pypeline - question: {question}")
        chosen_filters = choose_filters(question, "package", self.available_filters)
        result_dict = ai.base_filter.start_run_filters(
            whole_plan=chosen_filters,
            filter=chosen_filters.filter,
            available_filters=self.available_filters,
        )
        print("-----------------------------")
        return result_dict


class ResourcePypeline(ai.pipelines.BasePypeline):
    def __init__(
        self,
        landscape_components: list[gci.componentmodel.Component],
        db_session: sqlalchemy.orm.session.Session,
        pipeline_manager: ai.pipelines.PipelineManager,
    ) -> None:
        self.available_filters: list[ai.base_filter.BaseFilter] = [
            ai.filter.ResourceIDFilter(
                name="id",
                description="Filter Resources by the name and optionally version.",
                landscape_components=landscape_components,
                db_session=db_session,
                client=client,
            ),
            ai.filter.ResourceComponentsFilter(
                name="component",
                description="Filter Resources by the components they are used in.",
                landscape_components=landscape_components,
                db_session=db_session,
                client=client,
                pipeline_manager=pipeline_manager,
            ),
        ]
        self.landscape_components = landscape_components

    def run(self, question: str):
        print("-----------------------------")
        print(f"run package pypeline - question: {question}")
        chosen_filters = choose_filters(question, "package", self.available_filters)
        pprint.pprint(chosen_filters)
        result_dict = ai.base_filter.start_run_filters(
            whole_plan=chosen_filters,
            filter=chosen_filters.filter,
            available_filters=self.available_filters,
        )
        pprint.pprint(result_dict)
        print("-----------------------------")
        return result_dict


@middleware.auth.noauth
class AiEndpoint:
    def __init__(
        self,
        component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
        component_version_lookup: cnudie.retrieve.VersionLookupByComponent,
        github_api_lookup,
        eol_client: eol.EolClient,
        invalid_semver_ok: bool = False,
    ):
        self._component_descriptor_lookup = component_descriptor_lookup
        self._component_version_lookup = component_version_lookup
        self.github_api_lookup = github_api_lookup
        self._eol_client = eol_client
        self._invalid_semver_ok = invalid_semver_ok

    def on_post(self, req: falcon.Request, resp: falcon.Response):

        body = req.media
        question: str = body.get("question")
        root_component_identity_str: str = body.get("rootComponentIdentity")

        root_component_identity = gci.componentmodel.ComponentIdentity(
            name=root_component_identity_str.split(":")[0],
            version=root_component_identity_str.split(":")[1],
        )

        landscape_components = [
            component_node.component
            for component_node in components.resolve_component_dependencies(
                component_name=root_component_identity.name,
                component_version=root_component_identity.version,
                component_descriptor_lookup=self._component_descriptor_lookup,
                ctx_repo=None,
            )
        ]

        pipeline_manager = ai.pipelines.PipelineManager()
        pipeline_manager.add_pipeline(
            "component",
            ComponentPypeline(
                landscape_components, req.context.db_session, pipeline_manager
            ),
        )
        pipeline_manager.add_pipeline(
            "package",
            PackagePypeline(
                landscape_components, req.context.db_session, pipeline_manager
            ),
        )
        pipeline_manager.add_pipeline(
            "resource",
            ResourcePypeline(
                landscape_components, req.context.db_session, pipeline_manager
            ),
        )

        merged_result = ai.base_filter.combine_lists(
            pipeline_manager.decide_which_pipeline(question).run(question)
        )

        if merged_result is None:
            resp.media = []
        else:
            resp.media = [{"name": c.name, "version": c.version} for c in merged_result]
