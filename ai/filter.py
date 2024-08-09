'''
Contains the filters which can be assigend to different Filter Pilelines
'''

import itertools
import os
import pprint
import typing

import dso.model
import gci.componentmodel
import instructor
import pydantic
import sqlalchemy.dialects
import sqlalchemy.dialects.postgresql
import sqlalchemy.orm.session

import ai.base_filter
import ai.filter_json_structure
import ai.pipelines
import deliverydb.model
import deliverydb.util

class ComponentIdFilter(ai.base_filter.BaseFilter):
    def __init__(
        self,
        name,
        description,
        landscape_components: list[gci.componentmodel.Component],
        client: instructor.Instructor,
    ) -> None:
        self.landscape_components = landscape_components
        self.client = client
        super().__init__(name, description)

    def filter(
        self,
        question: str,
        path: list[str],
        whole_plan: ai.filter_json_structure.FilterJsonStruckture,
    ) -> set[gci.componentmodel.ComponentIdentity]:
        class ComponentID(pydantic.BaseModel):
            name: str = pydantic.Field(description="Name of the Component")
            version: typing.Optional[str] = pydantic.Field(
                None, description="Version of the component"
            )

        class ComponentIDList(pydantic.BaseModel):
            ids: list[ComponentID] = pydantic.Field(
                [], description="A list of ID objects to filter the components."
            )

        component_id_list = self.client.chat.completions.create(
            model=os.getenv("OPEN_AI_MODEL"),
            temperature=0.0,
            response_model=ComponentIDList,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "The current task is to filter a list of Components by its Id (name + version)."
                        " Please extract the needed information for filtering out of the Users Question.\n"
                        "\n"
                    ),
                },
                {"role": "user", "content": question},
            ],
        )

        component_ids: set[gci.componentmodel.ComponentIdentity] = set()
        for component_id in component_id_list.ids:
            if component_id.version is None:
                component_ids.update(
                    [
                        component.identity()
                        for component in self.landscape_components
                        if component.name == component_id.name
                    ]
                )
            else:
                component_ids.update(
                    [
                        component.identity()
                        for component in self.landscape_components
                        if component.name == component_id.name and component.version == component_id.version
                    ]
                )

        pprint.pprint(component_ids)
        return component_ids


class ComponentPackageFilter(ai.base_filter.BaseFilter):
    def __init__(
        self,
        name: str,
        description: str,
        landscape_components: list[gci.componentmodel.Component],
        db_session: sqlalchemy.orm.session.Session,
        client: instructor.Instructor,
        pipeline_manager: ai.pipelines.PipelineManager,
    ) -> None:
        self.landscape_components = landscape_components
        self.db_session = db_session
        self.client = client
        self.pipeline_manager = pipeline_manager
        super().__init__(name, description)

    def filter(
        self,
        question: str,
        path: list[str],
        whole_plan: ai.filter_json_structure.FilterJsonStruckture,
    ) -> set[gci.componentmodel.ComponentIdentity]:

        class Instruction(pydantic.BaseModel):
            instruction: str = pydantic.Field(
                description=(
                    'Instruction to obtain a set of specific packages. Start with: "A list of packages, which ..."'
                )
            )

        class SpecificPackagesMentionedReturn(pydantic.BaseModel):
            specific_packages_mentioned: bool = pydantic.Field(
                ...,
                description=(
                    "Indicate whether the packages to be filtered are specified by their name only or by both name and version:\n"
                    " - true: The packages are specified directly by name.\n"
                    " - false: The packages are not specified directly by name.\n"
                ),
            )
            data: list[ai.pipelines.PackageID] | Instruction = pydantic.Field(
                description=(
                    "If `specific_packages_mentioned` is `true`, fill the data field with a list of PackageID\n"
                    "If `specific_packages_mentioned` is `false`, fill the data field with an instruction that can be"
                    " used to obtain a list of specific packages for filtering."
                )
            )

        package_mentioned_return = self.client.chat.completions.create(
            model=os.getenv("OPEN_AI_MODEL"),
            temperature=0.0,
            response_model=SpecificPackagesMentionedReturn,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "The current task is to filter a list of Components based on their Packages."
                        " Are there any specific Packages mentioned that the user wants to filter for?\n"
                    ),
                },
                {"role": "user", "content": question},
            ],
        )
        packages: list[ai.pipelines.PackageID] = []
        if not package_mentioned_return.specific_packages_mentioned:
            if isinstance(package_mentioned_return.data, Instruction):
                packages = ai.base_filter.combine_lists(
                    self.pipeline_manager.run_pipeline(
                        "package", package_mentioned_return.data.instruction
                    )
                )
            else:
                raise RuntimeError("false Data return")
        else:
            if isinstance(package_mentioned_return.data, list):
                packages = package_mentioned_return.data
            else:
                raise RuntimeError("false Data return")

        pprint.pprint(packages)

        findings = (
            self.db_session.query(
                deliverydb.model.ArtefactMetaData.component_name,
                deliverydb.model.ArtefactMetaData.component_version,
            )
            .filter(
                deliverydb.model.ArtefactMetaData.type
                == dso.model.Datatype.STRUCTURE_INFO,
                sqlalchemy.or_(
                    deliverydb.util.ArtefactMetadataQueries.component_queries(
                        components=[
                            component.identity()
                            for component in self.landscape_components
                        ],
                    )
                ),
                sqlalchemy.or_(
                    *[
                        (
                            sqlalchemy.and_(
                                deliverydb.model.ArtefactMetaData.data.op("->>")(
                                    "package_name"
                                )
                                == package.name,
                                deliverydb.model.ArtefactMetaData.data.op("->>")(
                                    "package_version"
                                )
                                == package.version,
                            )
                            if package.version is not None
                            else sqlalchemy.and_(
                                deliverydb.model.ArtefactMetaData.data.op("->>")(
                                    "package_name"
                                )
                                == package.name,
                            )
                        )
                        for package in packages
                    ]
                ),
            )
            .group_by(
                deliverydb.model.ArtefactMetaData.component_name,
                deliverydb.model.ArtefactMetaData.component_version,
            )
            .all()
        )

        return {
            gci.componentmodel.ComponentIdentity(name=name, version=version)
            for name, version in findings
        }


class ComponentVulnerabilityFilter(ai.base_filter.BaseFilter):
    def __init__(
        self,
        name: str,
        description: str,
        landscape_components: list[gci.componentmodel.Component],
        db_session: sqlalchemy.orm.session.Session,
        client: instructor.Instructor,
    ) -> None:
        self.landscape_components = landscape_components
        self.db_session = db_session
        self.client = client
        super().__init__(name, description)

    def filter(
        self,
        question: str,
        path: list[str],
        whole_plan: ai.filter_json_structure.FilterJsonStruckture,
    ) -> set[gci.componentmodel.ComponentIdentity]:

        class VulnerbilitieInformation(pydantic.BaseModel):
            cve: str = pydantic.Field(description="Name of the cve.")

        class Instruction(pydantic.BaseModel):
            instruction: str = pydantic.Field(
                description=(
                    'Instruction to obtain a set of specific Vulnerabilities. Start with: "A list of Vulnerabilities, which ..."'
                )
            )

        class SpecificVulnerabilityMentionedReturn(pydantic.BaseModel):
            specific_cve_mentioned: bool = pydantic.Field(
                ...,
                description=(
                    "Indicate whether the Vulnerabilities to be filtered are directly specifies by cve:\n"
                    " - true: The vulnerabilities are specified directly by cve.\n"
                    " - false: The vulnerabilities are not specified directly by cve.\n"
                ),
            )
            data: list[VulnerbilitieInformation] | Instruction = pydantic.Field(
                description=(
                    "If `specific_cve_mentioned` is `true`, fill the data field with a list of VulnerbilitieInformation\n"
                    "If `specific_cve_mentioned` is `false`, fill the data field with an instruction that can be"
                    " used to obtain a list of specific Vulnerabilities for filtering."
                )
            )

        vulnerabilities_mentioned_return = self.client.chat.completions.create(
            model=os.getenv("OPEN_AI_MODEL"),
            temperature=0.0,
            response_model=SpecificVulnerabilityMentionedReturn,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "The current task is to filter a list of Components based on their Vulnerabilities."
                        " Are there any specific Vulnerabilities mentioned that the user wants to filter for?\n"
                    ),
                },
                {"role": "user", "content": question},
            ],
        )

        if not vulnerabilities_mentioned_return.specific_cve_mentioned:
            raise RuntimeError("Path Not Implemented 1")

        if not isinstance(vulnerabilities_mentioned_return.data, list):
            raise RuntimeError("false Data return")

        findings = (
            self.db_session.query(
                deliverydb.model.ArtefactMetaData.component_name,
                deliverydb.model.ArtefactMetaData.component_version,
            )
            .filter(
                deliverydb.model.ArtefactMetaData.type == dso.model.Datatype.VULNERABILITY,
                sqlalchemy.or_(
                    deliverydb.util.ArtefactMetadataQueries.component_queries(
                        components=[
                            component.identity()
                            for component in self.landscape_components
                        ],
                    )
                ),
                deliverydb.model.ArtefactMetaData.data.op("->>")("cve").in_(
                    [vul.cve for vul in vulnerabilities_mentioned_return.data]
                ),
            )
            .group_by(
                deliverydb.model.ArtefactMetaData.component_name,
                deliverydb.model.ArtefactMetaData.component_version,
            )
            .all()
        )

        return {
            gci.componentmodel.ComponentIdentity(name=name, version=version)
            for name, version in findings
        }

# TODO: Testing
class ComponentMalwareFilter(ai.base_filter.BaseFilter):
    def __init__(
        self,
        name: str,
        description: str,
        landscape_components: list[gci.componentmodel.Component],
        db_session: sqlalchemy.orm.session.Session,
        client: instructor.Instructor,
    ) -> None:
        self.landscape_components = landscape_components
        self.db_session = db_session
        self.client = client
        super().__init__(name, description)

    def filter(
        self,
        question: str,
        path: list[str],
        whole_plan: ai.filter_json_structure.FilterJsonStruckture,
    ) -> set[gci.componentmodel.ComponentIdentity]:

        class MalwareInformation(pydantic.BaseModel):
            name: str = pydantic.Field(description="Name of the malware.")

        class Instruction(pydantic.BaseModel):
            instruction: str = pydantic.Field(
                description=(
                    'Instruction to obtain a set of specific Malware. Start with: "A list of Malware, which ..."'
                )
            )

        class SpecificMalwareMentionedReturn(pydantic.BaseModel):
            specific_cve_mentioned: bool = pydantic.Field(
                ...,
                description=(
                    "Indicate whether the Malware to be filtered are directly specifies by name:\n"
                    " - true: The Malware are specified directly by name.\n"
                    " - false: The Malware are not specified directly by name.\n"
                ),
            )
            data: list[MalwareInformation] | Instruction = pydantic.Field(
                description=(
                    "If `specific_malware_mentioned` is `true`, fill the data field with a list of MalwareInformation\n"
                    "If `specific_malware_mentioned` is `false`, fill the data field with an instruction that can be"
                    " used to obtain a list of specific Malware for filtering."
                )
            )

        malware_mentioned_return = self.client.chat.completions.create(
            model=os.getenv("OPEN_AI_MODEL"),
            temperature=0.0,
            response_model=SpecificMalwareMentionedReturn,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "The current task is to filter a list of Components based on their Malware."
                        " Are there any specific Malware mentioned that the user wants to filter for?\n"
                    ),
                },
                {"role": "user", "content": question},
            ],
        )

        if not malware_mentioned_return.specific_cve_mentioned:
            raise RuntimeError("Path Not Implemented 1")

        if not isinstance(malware_mentioned_return.data, list):
            raise RuntimeError("False Data return")

        findings = (
            self.db_session.query(
                deliverydb.model.ArtefactMetaData.component_name,
                deliverydb.model.ArtefactMetaData.component_version,
                deliverydb.model.ArtefactMetaData.data,
            )
            .filter(
                deliverydb.model.ArtefactMetaData.type == dso.model.Datatype.MALWARE,
                sqlalchemy.or_(
                    deliverydb.util.ArtefactMetadataQueries.component_queries(
                        components=[
                            component.identity()
                            for component in self.landscape_components
                        ],
                    )
                ),
                deliverydb.model.ArtefactMetaData.data.op("->>")("findings") != "[]",
            )
            .group_by(
                deliverydb.model.ArtefactMetaData.component_name,
                deliverydb.model.ArtefactMetaData.component_version,
            )
            .all()
        )

        items_with_findings: list[gci.componentmodel.ComponentIdentity] = []
        for finding in findings:
            data = finding.data
            for item in data["findings"]:
                if item["name"] in [
                    malware.name for malware in malware_mentioned_return.data
                ]:
                    items_with_findings.append(
                        gci.componentmodel.ComponentIdentity(
                            name=finding.name, version=finding.version
                        )
                    )

        return set(items_with_findings)


class ComponentResourcesFilter(ai.base_filter.BaseFilter):
    def __init__(
        self,
        name: str,
        description: str,
        landscape_components: list[gci.componentmodel.Component],
        db_session: sqlalchemy.orm.session.Session,
        client: instructor.Instructor,
    ) -> None:
        self.landscape_components = landscape_components
        self.db_session = db_session
        self.client = client
        super().__init__(name, description)

    def filter(
        self,
        question: str,
        path: list[str],
        whole_plan: ai.filter_json_structure.FilterJsonStruckture,
    ) -> set[gci.componentmodel.ComponentIdentity]:

        class ResourceInformation(pydantic.BaseModel):
            name: str = pydantic.Field(description="Name of the resource.")
            version: typing.Optional[str] = pydantic.Field(
                description="Version of the resource."
            )

        class Instruction(pydantic.BaseModel):
            instruction: str = pydantic.Field(
                description=(
                    'Instruction to obtain a set of specific Resource. Start with: "A list of Resources, which ..."'
                )
            )

        class SpecificResourceMentionedReturn(pydantic.BaseModel):
            specific_resources_mentioned: bool = pydantic.Field(
                ...,
                description=(
                    "Indicate whether the Resource to be filtered are directly specifies by name:\n"
                    " - true: The Resource are specified directly by name.\n"
                    " - false: The Resource are not specified directly by name.\n"
                ),
            )
            data: list[ResourceInformation] | Instruction = pydantic.Field(
                description=(
                    "If `specific_resources_mentioned` is `true`, fill the data field with a list of ResourceInformation\n"
                    "If `specific_resources_mentioned` is `false`, fill the data field with an instruction that can be"
                    " used to obtain a list of specific Resources for filtering."
                )
            )

        resource_mentioned_return = self.client.chat.completions.create(
            model=os.getenv("OPEN_AI_MODEL"),
            temperature=0.0,
            response_model=SpecificResourceMentionedReturn,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "The current task is to filter a list of Components based on their Resources."
                        " Are there any specific Resources mentioned that the user wants to filter for?\n"
                    ),
                },
                {"role": "user", "content": question},
            ],
        )

        if not resource_mentioned_return.specific_resources_mentioned:
            raise RuntimeError("Path Not Implemented 1")

        if not isinstance(resource_mentioned_return.data, list):
            raise RuntimeError("False Data return")

        print(resource_mentioned_return)

        components_with_resource: set[gci.componentmodel.ComponentIdentity] = set()
        for resource_information in resource_mentioned_return.data:
            new_components_with_resource = [
                component
                for component in self.landscape_components
                if resource_information.name
                in [resource.name for resource in component.resources]
            ]

            if resource_information.version:
                new_components_with_resource = [
                    entry
                    for entry in new_components_with_resource
                    if entry.version == resource_information.version
                ]

            components_with_resource.update(
                [component.identity() for component in new_components_with_resource]
            )

        return components_with_resource


class PackageIdFilter(ai.base_filter.BaseFilter):
    def __init__(
        self,
        name: str,
        description: str,
        landscape_components: list[gci.componentmodel.Component],
        db_session: sqlalchemy.orm.session.Session,
        client: instructor.Instructor,
    ) -> None:
        self.landscape_components = landscape_components
        self.db_session = db_session
        self.client = client
        super().__init__(name, description)

    def filter(
        self,
        question: str,
        path: list[str],
        whole_plan: ai.filter_json_structure.FilterJsonStruckture,
    ) -> set[ai.pipelines.PackageID]:

        class PackageInformation(pydantic.BaseModel):
            name: str = pydantic.Field(description="Name of the package.")
            version: typing.Optional[str] = pydantic.Field(
                description="Version of the package."
            )

        class Instruction(pydantic.BaseModel):
            instruction: str = pydantic.Field(
                description=(
                    'Instruction to obtain a set of specific Package. Start with: "A list of Package, which ..."'
                )
            )

        class SpecificPackageMentionedReturn(pydantic.BaseModel):
            specific_packages_mentioned: bool = pydantic.Field(
                ...,
                description=(
                    "Indicate whether the Package to be filtered are directly specifies by name:\n"
                    " - true: The Package are specified directly by name.\n"
                    " - false: The Package are not specified directly by name.\n"
                ),
            )
            data: list[PackageInformation] | Instruction = pydantic.Field(
                description=(
                    "If `specific_packages_mentioned` is `true`, fill the data field with a list of PackageInformation\n"
                    "If `specific_packages_mentioned` is `false`, fill the data field with an instruction that can be"
                    " used to obtain a list of specific Package for filtering."
                )
            )

        package_mentioned_return = self.client.chat.completions.create(
            model=os.getenv("OPEN_AI_MODEL"),
            temperature=0.0,
            response_model=SpecificPackageMentionedReturn,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "The current task is to filter a list of Packages based on their id (name and optionally version)."
                        " Are there any specific Packages mentioned that the user wants to filter for?\n"
                    ),
                },
                {"role": "user", "content": question},
            ],
        )

        if not package_mentioned_return.specific_packages_mentioned:
            raise RuntimeError("Path Not Implemented 1")

        if not isinstance(package_mentioned_return.data, list):
            raise RuntimeError("False Data return")

        findings = (
            self.db_session.query(
                deliverydb.model.ArtefactMetaData.data.op("->>")("package_name"),
                deliverydb.model.ArtefactMetaData.data.op("->>")("package_version"),
            )
            .filter(
                deliverydb.model.ArtefactMetaData.type == dso.model.Datatype.STRUCTURE_INFO,
                sqlalchemy.or_(
                    deliverydb.util.ArtefactMetadataQueries.component_queries(
                        components=[
                            component.identity()
                            for component in self.landscape_components
                        ],
                    )
                ),
                sqlalchemy.or_(
                    *[
                        (
                            sqlalchemy.and_(
                                deliverydb.model.ArtefactMetaData.data.op("->>")(
                                    "package_name"
                                )
                                == package.name,
                                deliverydb.model.ArtefactMetaData.data.op("->>")(
                                    "package_version"
                                )
                                == package.version,
                            )
                            if package.version is not None
                            else sqlalchemy.and_(
                                deliverydb.model.ArtefactMetaData.data.op("->>")(
                                    "package_name"
                                )
                                == package.name,
                            )
                        )
                        for package in package_mentioned_return.data
                    ]
                ),
            )
            .all()
        )

        pprint.pprint(findings)

        return {
            ai.pipelines.PackageID(name=name, version=version)
            for name, version in findings
        }


class PackageComponentFilter(ai.base_filter.BaseFilter):
    """Filters the packages by the components they are used in."""

    def __init__(
        self,
        name: str,
        description: str,
        landscape_components: list[gci.componentmodel.Component],
        db_session: sqlalchemy.orm.session.Session,
        client: instructor.Instructor,
    ) -> None:
        self.landscape_components = landscape_components
        self.db_session = db_session
        self.client = client
        super().__init__(name, description)

    def filter(
        self,
        question: str,
        path: list[str],
        whole_plan: ai.filter_json_structure.FilterJsonStruckture,
    ) -> set[ai.pipelines.PackageID]:

        class ComponentInformation(pydantic.BaseModel):
            name: str = pydantic.Field(description="Name of the Component.")
            version: typing.Optional[str] = pydantic.Field(
                description="Version of the Component."
            )

        class Instruction(pydantic.BaseModel):
            instruction: str = pydantic.Field(
                description=(
                    'Instruction to obtain a set of specific Package. Start with: "A list of Package, which ..."'
                )
            )

        class SpecificComponentsMentionedReturn(pydantic.BaseModel):
            specific_components_mentioned: bool = pydantic.Field(
                ...,
                description=(
                    "Indicate whether the Components to be filtered are directly specifies by name:\n"
                    " - true: The Components are specified directly by name.\n"
                    " - false: The Components are not specified directly by name.\n"
                ),
            )
            data: list[ComponentInformation] | Instruction = pydantic.Field(
                description=(
                    "If `specific_components_mentioned` is `true`, fill the data field with a list of ComponentInformation\n"
                    "If `specific_components_mentioned` is `false`, fill the data field with an instruction that can be"
                    " used to obtain a list of specific Components for filtering."
                )
            )

        components_mentioned_return = self.client.chat.completions.create(
            model=os.getenv("OPEN_AI_MODEL"),
            temperature=0.0,
            response_model=SpecificComponentsMentionedReturn,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "The current task is to filter a list of Packages based on their id (name and optionally version)."
                        " Are there any specific Packages mentioned that the user wants to filter for?\n"
                    ),
                },
                {"role": "user", "content": question},
            ],
        )

        if not components_mentioned_return.specific_components_mentioned:
            raise RuntimeError("Path Not Implemented 1")

        if not isinstance(components_mentioned_return.data, list):
            raise RuntimeError("False Data return")

        components_of_interest: set[gci.componentmodel.ComponentIdentity] = set()
        for entry in components_mentioned_return.data:
            if entry.version is not None:
                components_of_interest.update(
                    [
                        component.identity()
                        for component in self.landscape_components
                        if component.name == entry.name
                    ]
                )
            else:
                components_of_interest.update(
                    [
                        component.identity()
                        for component in self.landscape_components
                        if component.name == entry.name
                        and component.version == entry.version
                    ]
                )

        findings = (
            self.db_session.query(
                deliverydb.model.ArtefactMetaData.data.op("->>")("package_name"),
                deliverydb.model.ArtefactMetaData.data.op("->>")("package_version"),
            )
            .filter(
                deliverydb.model.ArtefactMetaData.type == dso.model.Datatype.STRUCTURE_INFO,
                sqlalchemy.or_(
                    deliverydb.util.ArtefactMetadataQueries.component_queries(
                        components=components_of_interest,
                    )
                ),
            )
            .all()
        )

        return {
            ai.pipelines.PackageID(name=name, version=version)
            for name, version in findings
        }


class PackageVulnerabilityFilter(ai.base_filter.BaseFilter):
    """Filters the packages by their vulnerabilities."""

    def __init__(
        self,
        name: str,
        description: str,
        landscape_components: list[gci.componentmodel.Component],
        db_session: sqlalchemy.orm.session.Session,
        client: instructor.Instructor,
    ) -> None:
        self.landscape_components = landscape_components
        self.db_session = db_session
        self.client = client
        super().__init__(name, description)

    def filter(
        self,
        question: str,
        path: list[str],
        whole_plan: ai.filter_json_structure.FilterJsonStruckture,
    ) -> set[ai.pipelines.PackageID]:

        class VulnerabilityInformation(pydantic.BaseModel):
            cve: str = pydantic.Field(description="Specific CVE of the Vulnerability")

        class Instruction(pydantic.BaseModel):
            instruction: str = pydantic.Field(
                description=(
                    'Instruction to obtain a set of specific Vulnerabilities. Start with: "A list of Vulnerabilities, which ..."'
                )
            )

        class SpecificVulnerabilitiesMentionedReturn(pydantic.BaseModel):
            specific_vulnerabilities_mentioned: bool = pydantic.Field(
                ...,
                description=(
                    "Indicate whether the Vulnerabilities to be filtered are directly specifies by cve:\n"
                    " - true: The Vulnerabilities are specified directly by cve.\n"
                    " - false: The Vulnerabilities are not specified directly by cve.\n"
                ),
            )
            data: list[VulnerabilityInformation] | Instruction = pydantic.Field(
                description=(
                    "If `specific_vulnerabilities_mentioned` is `true`, fill the data field with a list of VulnerabilityInformation\n"
                    "If `specific_vulnerabilities_mentioned` is `false`, fill the data field with an instruction that can be"
                    " used to obtain a list of specific Vulnerabilities for filtering."
                )
            )

        components_mentioned_return = self.client.chat.completions.create(
            model=os.getenv("OPEN_AI_MODEL"),
            temperature=0.0,
            response_model=SpecificVulnerabilitiesMentionedReturn,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "The current task is to filter a list of Packages based on their vulnerabilities."
                        " Are there any specific vulnerabilities mentioned that the user wants to filter for?\n"
                    ),
                },
                {"role": "user", "content": question},
            ],
        )

        if not components_mentioned_return.specific_vulnerabilities_mentioned:
            raise RuntimeError("Path Not Implemented 1")

        if not isinstance(components_mentioned_return.data, list):
            raise RuntimeError("False Data return")

        print(components_mentioned_return.data)

        findings = (
            self.db_session.query(
                deliverydb.model.ArtefactMetaData.data.op("->>")("package_name"),
                deliverydb.model.ArtefactMetaData.data.op("->>")("package_version"),
            )
            .filter(
                deliverydb.model.ArtefactMetaData.type == dso.model.Datatype.VULNERABILITY,
                sqlalchemy.or_(
                    deliverydb.util.ArtefactMetadataQueries.component_queries(
                        components=[
                            component.identity()
                            for component in self.landscape_components
                        ],
                    )
                ),
                deliverydb.model.ArtefactMetaData.data.op("->>")("cve").in_(
                    [entry.cve for entry in components_mentioned_return.data]
                ),
            )
            .all()
        )

        return {
            ai.pipelines.PackageID(name=name, version=version)
            for name, version in findings
        }


class PackageLicenseFilter(ai.base_filter.BaseFilter):
    """Filters the packages by their license."""

    def __init__(
        self,
        name: str,
        description: str,
        landscape_components: list[gci.componentmodel.Component],
        db_session: sqlalchemy.orm.session.Session,
        client: instructor.Instructor,
    ) -> None:
        self.landscape_components = landscape_components
        self.db_session = db_session
        self.client = client
        super().__init__(name, description)

    def filter(
        self,
        question: str,
        path: list[str],
        whole_plan: ai.filter_json_structure.FilterJsonStruckture,
    ) -> set[ai.pipelines.PackageID]:

        class LicenseInformation(pydantic.BaseModel):
            license: str = pydantic.Field(description="A specific license.")

        class SpecificLicensesMentionedReturn(pydantic.BaseModel):
            specific_licenses_mentioned: bool = pydantic.Field(
                ...,
                description=(
                    "Indicate whether the Licenses to be filtered are directly specifies by name:\n"
                    " - true: The Licenses are specified directly by name.\n"
                    " - false: The Licenses are not specified directly by name.\n"
                ),
            )
            data: list[LicenseInformation] | None = pydantic.Field(
                description=(
                    "If `specific_licenses_mentioned` is `true`, fill the data field with a list of LicenseInformation\n"
                    "If `specific_licenses_mentioned` is `false`, fill the data field with None."
                )
            )

        licenses_mentioned_return = self.client.chat.completions.create(
            model=os.getenv("OPEN_AI_MODEL"),
            temperature=0.0,
            response_model=SpecificLicensesMentionedReturn,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "The current task is to filter a list of Packages based on their Licenses."
                        " Are there any specific licenses mentioned that the user wants to filter for?\n"
                    ),
                },
                {"role": "user", "content": question},
            ],
        )

        if not licenses_mentioned_return.specific_licenses_mentioned:
            raise RuntimeError("Path Not Implemented 1")

        if not isinstance(licenses_mentioned_return.data, list):
            raise RuntimeError("False Data return")

        license_subquery = (
            self.db_session.query(
                deliverydb.model.ArtefactMetaData.id,
                deliverydb.model.ArtefactMetaData.data.label("data"),
                sqlalchemy.func.jsonb_array_elements(
                    deliverydb.model.ArtefactMetaData.data["licenses"],
                ).label("license"),
            )
            .filter(
                deliverydb.model.ArtefactMetaData.type == dso.model.Datatype.STRUCTURE_INFO,
                sqlalchemy.or_(
                    deliverydb.util.ArtefactMetadataQueries.component_queries(
                        components=[
                            component.identity()
                            for component in self.landscape_components
                        ],
                    )
                ),
            )
            .subquery()
        )

        findings = (
            self.db_session.query(
                license_subquery.c.data.op("->>")("package_name"),
                license_subquery.c.data.op("->>")("package_version"),
            )
            .filter(
                license_subquery.c.license.op("->>")("name").in_(
                    [entity.license for entity in licenses_mentioned_return.data]
                )
            )
            .all()
        )

        return {
            ai.pipelines.PackageID(name=name, version=version)
            for name, version in findings
        }


class PackageDataSourceFilter(ai.base_filter.BaseFilter):
    """Filters the packages by the Datasource which detected it."""

    def __init__(
        self,
        name: str,
        description: str,
        landscape_components: list[gci.componentmodel.Component],
        db_session: sqlalchemy.orm.session.Session,
        client: instructor.Instructor,
    ) -> None:
        self.landscape_components = landscape_components
        self.db_session = db_session
        self.client = client
        super().__init__(name, description)

    def filter(
        self,
        question: str,
        path: list[str],
        whole_plan: ai.filter_json_structure.FilterJsonStruckture,
    ) -> set[ai.pipelines.PackageID]:

        class DataSourceInformation(pydantic.BaseModel):
            name: str = pydantic.Field(description="Specific Name of the Data Source")

        class SpecificDataSourceMentionedReturn(pydantic.BaseModel):
            specific_data_source_mentioned: bool = pydantic.Field(
                ...,
                description=(
                    "Indicate whether the Data Sources to be filtered are directly specifies by name:\n"
                    " - true: The Data Sources are specified directly by name.\n"
                    " - false: The Data Sources are not specified directly by name.\n"
                ),
            )
            data: list[DataSourceInformation] | None = pydantic.Field(
                description=(
                    "If `specific_data_source_mentioned` is `true`, fill the data field with a list of DataSourceInformation.\n"
                    "If `specific_data_source_mentioned` is `false`, fill the data field with None."
                )
            )

        data_sources_mentioned_return = self.client.chat.completions.create(
            model=os.getenv("OPEN_AI_MODEL"),
            temperature=0.0,
            response_model=SpecificDataSourceMentionedReturn,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "The current task is to filter a list of Packages based on their data sources."
                        " Are there any specific data sources mentioned that the user wants to filter for?\n"
                    ),
                },
                {"role": "user", "content": question},
            ],
        )

        if not data_sources_mentioned_return.specific_data_source_mentioned:
            raise RuntimeError("Path Not Implemented 1")

        if not isinstance(data_sources_mentioned_return.data, list):
            raise RuntimeError("False Data return")

        print(data_sources_mentioned_return.data)

        findings = (
            self.db_session.query(
                deliverydb.model.ArtefactMetaData.data.op("->>")("package_name"),
                deliverydb.model.ArtefactMetaData.data.op("->>")("package_version"),
            )
            .filter(
                deliverydb.model.ArtefactMetaData.type == dso.model.Datatype.STRUCTURE_INFO,
                sqlalchemy.or_(
                    deliverydb.util.ArtefactMetadataQueries.component_queries(
                        components=[
                            component.identity()
                            for component in self.landscape_components
                        ],
                    )
                ),
                deliverydb.model.ArtefactMetaData.datasource.in_(
                    [
                        data_source.name
                        for data_source in data_sources_mentioned_return.data
                    ]
                ),
            )
            .all()
        )

        return {
            ai.pipelines.PackageID(name=name, version=version)
            for name, version in findings
        }


class PackageResourceFilter(ai.base_filter.BaseFilter):
    """Filters the packages by the resource they are used in."""

    def __init__(
        self,
        name: str,
        description: str,
        landscape_components: list[gci.componentmodel.Component],
        db_session: sqlalchemy.orm.session.Session,
        client: instructor.Instructor,
        pipeline_manager: ai.pipelines.PipelineManager,
    ) -> None:
        self.landscape_components = landscape_components
        self.db_session = db_session
        self.client = client
        self.pipeline_manager = pipeline_manager
        super().__init__(name, description)

    def filter(
        self,
        question: str,
        path: list[str],
        whole_plan: ai.filter_json_structure.FilterJsonStruckture,
    ) -> set[ai.pipelines.PackageID]:

        class ResourceInformation(pydantic.BaseModel):
            name: str = pydantic.Field(description="Specific Name of the Resource")
            version: typing.Optional[str] = pydantic.Field(
                description="Specific Version of the Resource"
            )

        class Instruction(pydantic.BaseModel):
            instruction: str = pydantic.Field(
                description=(
                    'Instruction to obtain a set of specific Resources. Start with: "A list of Resources, which ..."'
                )
            )

        class SpecificResourcesMentionedReturn(pydantic.BaseModel):
            specific_resources_mentioned: bool = pydantic.Field(
                ...,
                description=(
                    "Indicate whether the Resources to be filtered are directly specifies by name:\n"
                    " - true: The Resources are specified directly by name.\n"
                    " - false: The Resources are not specified directly by name.\n"
                ),
            )
            data: list[ResourceInformation] | Instruction = pydantic.Field(
                description=(
                    "If `specific_data_source_mentioned` is `true`, fill the data field with a list of ResourceInformation.\n"
                    "If `specific_data_source_mentioned` is `false`, fill the data field with an instruction that can be"
                    " used to obtain a list of specific Vulnerabilities for filtering."
                )
            )

        mentioned_resources = self.client.chat.completions.create(
            model=os.getenv("OPEN_AI_MODEL"),
            temperature=0.0,
            response_model=SpecificResourcesMentionedReturn,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "The current task is to filter a list of packages based on the resources they are used in."
                        " Are there any specific resources mentioned that the user wants to filter for?\n"
                    ),
                },
                {"role": "user", "content": question},
            ],
        )

        if not mentioned_resources.specific_resources_mentioned:
            raise RuntimeError("Path Not Implemented 1")

        if not isinstance(mentioned_resources.data, list):
            raise RuntimeError("False Data return")

        print(mentioned_resources.data)

        findings = (
            self.db_session.query(
                deliverydb.model.ArtefactMetaData.data.op("->>")("package_name"),
                deliverydb.model.ArtefactMetaData.data.op("->>")("package_version"),
            )
            .filter(
                deliverydb.model.ArtefactMetaData.type
                == dso.model.Datatype.STRUCTURE_INFO,
                sqlalchemy.or_(
                    deliverydb.util.ArtefactMetadataQueries.component_queries(
                        components=[
                            component.identity()
                            for component in self.landscape_components
                        ],
                    )
                ),
                deliverydb.model.ArtefactMetaData.artefact_kind == "resource",
                sqlalchemy.or_(
                    *[
                        (
                            sqlalchemy.and_(
                                deliverydb.model.ArtefactMetaData.artefact_name
                                == resource.name,
                                deliverydb.model.ArtefactMetaData.artefact_version
                                == resource.version,
                            )
                            if resource.version is not None
                            else sqlalchemy.and_(
                                deliverydb.model.ArtefactMetaData.artefact_name
                                == resource.name,
                            )
                        )
                        for resource in mentioned_resources.data
                    ]
                ),
            )
            .all()
        )

        return {
            ai.pipelines.PackageID(name=name, version=version)
            for name, version in findings
        }


class ResourceIDFilter(ai.base_filter.BaseFilter):
    """Filters the Resources by name and optionally by version."""

    def __init__(
        self,
        name: str,
        description: str,
        landscape_components: list[gci.componentmodel.Component],
        db_session: sqlalchemy.orm.session.Session,
        client: instructor.Instructor,
    ) -> None:
        self.landscape_components = landscape_components
        self.db_session = db_session
        self.client = client
        super().__init__(name, description)

    def filter(
        self,
        question: str,
        path: list[str],
        whole_plan: ai.filter_json_structure.FilterJsonStruckture,
    ) -> set[ai.pipelines.ResourceID]:
        class ResourceInformation(pydantic.BaseModel):
            name: str = pydantic.Field(description="Specific Name of the Resource.")
            version: typing.Optional[str] = pydantic.Field(
                description="Specific Version of the Resource."
            )

        class SpecificResourcesMentionedReturn(pydantic.BaseModel):
            resource_names: list[ResourceInformation] = pydantic.Field(
                ...,
                description=(
                    "List of Resource Names the Resource list should be filtered with."
                ),
            )

        ai_data_extraction = self.client.chat.completions.create(
            model=os.getenv("OPEN_AI_MODEL"),
            temperature=0.0,
            response_model=SpecificResourcesMentionedReturn,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "The current task is to filter a list of resources based on resource names."
                        " Are there any specific resource names mentioned that the user wants to filter for?\n"
                    ),
                },
                {"role": "user", "content": question},
            ],
        )

        components_with_resource: set[gci.componentmodel.ComponentIdentity] = set()

        for resource_information in ai_data_extraction.resource_names:
            new_components_with_resource = [
                component
                for component in self.landscape_components
                if resource_information.name
                in [resource.name for resource in component.resources]
            ]

            if resource_information.version:
                new_components_with_resource = [
                    entry
                    for entry in new_components_with_resource
                    if entry.version == resource_information.version
                ]

            components_with_resource.update(
                [component.identity() for component in new_components_with_resource]
            )

        return {
            ai.pipelines.ResourceID(name=id.name, version=id.version)
            for id in components_with_resource
        }


class ResourceComponentsFilter(ai.base_filter.BaseFilter):
    """Filters the Resources by Components they are used in."""

    def __init__(
        self,
        name: str,
        description: str,
        landscape_components: list[gci.componentmodel.Component],
        db_session: sqlalchemy.orm.session.Session,
        client: instructor.Instructor,
        pipeline_manager: ai.pipelines.PipelineManager,
    ) -> None:
        self.landscape_components = landscape_components
        self.db_session = db_session
        self.client = client
        self.pipeline_manager = pipeline_manager
        super().__init__(name, description)

    def filter(
        self,
        question: str,
        path: list[str],
        whole_plan: ai.filter_json_structure.FilterJsonStruckture,
    ) -> set[ai.pipelines.ResourceID]:
        class ComponentInformation(pydantic.BaseModel):
            name: str = pydantic.Field(description="Specific Name of the Component.")
            version: typing.Optional[str] = pydantic.Field(
                description="Specific Version of the Component."
            )

        class Instruction(pydantic.BaseModel):
            instruction: str = pydantic.Field(
                description=(
                    'Instruction to obtain a set of specific Components. Start with: "A list of Components, which ..."'
                )
            )

        class SpecificComponentsMentionedReturn(pydantic.BaseModel):
            specific_component_mentioned: bool = pydantic.Field('Indicate whether the Components to be filtered are directly specifies by name\n')
            data: list[ComponentInformation] | Instruction = pydantic.Field(
                ...,
                description=(
                    'If `specific_component_mentioned` is `true`, fill the data field with a list of ComponentInformation.\n'
                    'If `specific_component_mentioned` is `false`, fill the data field with an instruction that can be'
                    ' used to obtain a list of specific components for filtering.'
                ),
            )

        ai_data_extraction = self.client.chat.completions.create(
            model=os.getenv("OPEN_AI_MODEL"),
            temperature=0.0,
            response_model=SpecificComponentsMentionedReturn,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "The current task is to filter a list of resources based on the components they are used in."
                        " Are there any specific components mentioned that the user wants to filter for?\n"
                    ),
                },
                {"role": "user", "content": question},
            ],
        )

        if isinstance(ai_data_extraction.data, Instruction):
            mentioned_components_ids: list[gci.componentmodel.ComponentIdentity] = (
                ai.base_filter.combine_lists(
                    self.pipeline_manager.run_pipeline(
                        "component", ai_data_extraction.data.instruction
                    )
                )
            )
            mentioned_components: list[gci.componentmodel.Component] = [
                next(
                    (
                        component
                        for component in self.landscape_components
                        if component.name == id.name and component.version == id.version
                    ),
                    None,
                )
                for id in mentioned_components_ids
            ]

        else:
            mentioned_components = list(
                itertools.chain(
                    *[
                        [
                            component
                            for component in self.landscape_components
                            if component.name == mentioned_component.name
                            and (
                                mentioned_component.version is None
                                or component.version == mentioned_component.version
                            )
                        ]
                        for mentioned_component in ai_data_extraction.data
                    ]
                )
            )

        resources: set[ai.pipelines.ResourceID] = (
            ai.pipelines.ResourceID(name=resource.name, version=resource.version)
            for component in mentioned_components
            for resource in component.resources
        )

        return resources