import datetime
import functools
from importlib.metadata import version
import inspect
import json
import math
import pprint
import re
import typing

import cnudie.retrieve
import cnudie.util
import dso.model
import gci.componentmodel
import langchain.tools
import langchain_core
import langchain_core.pydantic_v1
from langfuse import model
from pydantic.v1 import BaseModel
import sqlalchemy
import sqlalchemy.orm.query
import sqlalchemy.orm.session

import components
import deliverydb.model
import deliverydb.util
import eol
import features

def component_id_str_to_obj(c_id: str)->gci.componentmodel.ComponentIdentity:
    '''
    Takes a string in the format f"{component_name}:{component_version}" and
    converts it to a ComponentIdentity object. 
    '''
    parts = c_id.split(':')

    if len(parts) != 2:
        raise ValueError('componen_id string is not formatted in the right way.')

    return gci.componentmodel.ComponentIdentity(
        name=parts[0],
        version=parts[1],
    )

def component_id_obj_to_str(c_id: gci.componentmodel.ComponentIdentity)->str:   
    '''
    Takes a ComponentIdentity object and converts it to a string in the
    format f"{component_name}:{component_version}".
    '''
    return f'{c_id.name}:{c_id.version}'


class Parameters:
    def __init__(self) -> None:
        pass

    class component_id(langchain_core.pydantic_v1.BaseModel):
        component_id: str = langchain_core.pydantic_v1.Field(
            description=('''
                A component identity is always a concatenation of a
                'Component Name' and ':' and 'Component Version.'
            '''
            )
        )
    class component_information(langchain_core.pydantic_v1.BaseModel):
        component_information: list[typing.Literal[
            'componentName',
            'componentVersion',
            'sources',
            'componentReferences',
            'os',
            'resources',
        ]] = langchain_core.pydantic_v1.Field(
            description='Which information about the component will be returned.',
        )
    class component_name(langchain_core.pydantic_v1.BaseModel):
        component_name: str = langchain_core.pydantic_v1.Field(
            description='Name of the component.'
        )
    class resource_id(langchain_core.pydantic_v1.BaseModel):
        resource_id: str = langchain_core.pydantic_v1.Field(
            description=('''
                A resource identity is always a concatenation of a
                'component name' and ':' and 'Component Version.'
            '''
            )
        )
    class resource_name(langchain_core.pydantic_v1.BaseModel):
        resource_name: str = langchain_core.pydantic_v1.Field(
            description='A name of a specific resource.'
        )
    class resource_version(langchain_core.pydantic_v1.BaseModel):
        resource_version: str = langchain_core.pydantic_v1.Field(
            description='A version of a specific resource.'
        )
    class resource_version_optional(langchain_core.pydantic_v1.BaseModel):
        resource_version: typing.Optional[str] = langchain_core.pydantic_v1.Field(
            description='A version of a specific resource. This field is optional.',
            default=None,
        )
    class os_id(langchain_core.pydantic_v1.BaseModel):
        os_id: str = langchain_core.pydantic_v1.Field(
            description='Identifier for a specific os. e.g. "debian", "arch"',
        )
    class os_version(langchain_core.pydantic_v1.BaseModel):
        os_version: str = langchain_core.pydantic_v1.Field(
            description=(
                'Specific version of an operating system.'
            ),
        )
    class severities(langchain_core.pydantic_v1.BaseModel):
        severities: list[
            typing.Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        ] = langchain_core.pydantic_v1.Field(
            description='Severity levels for a finding.',
        )
    class discovery_days_back(langchain_core.pydantic_v1.BaseModel):
        discovery_days_back: int = langchain_core.pydantic_v1.Field(
            description=(
                'The number of days from the current date back to select entries discovered within this timeframe.' 
            ),
        )
    class package_name(langchain_core.pydantic_v1.BaseModel):
        package_name: str = langchain_core.pydantic_v1.Field(
            description='Name of a specific Package.',
        )
    class package_version_optional(langchain_core.pydantic_v1.BaseModel):
        package_version: typing.Optional[str] = langchain_core.pydantic_v1.Field(
            description='Version of a specific Package.',
            default=None,
        )
    class package_platform_optional(langchain_core.pydantic_v1.BaseModel):
        package_platform: typing.Optional[str] = langchain_core.pydantic_v1.Field(
            description='Platform for a specific Package. e.g. "amd64"',
            default=None,
        )
    

class AiTools:
    def __init__(
        self,
        root_component_id: gci.componentmodel.ComponentIdentity,
        component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
        component_version_lookup: cnudie.retrieve.VersionLookupByComponent,
        db_session: sqlalchemy.orm.session.Session,
        invalid_semver_ok: bool = False,
    ) -> None:
        
        self.landscape_components = [
            component_node.component
            for component_node
            in components.resolve_component_dependencies(
                component_name=root_component_id.name,
                component_version=root_component_id.version,
                component_descriptor_lookup=component_descriptor_lookup,
                ctx_repo=None,
            )
        ]

        self.component_descriptor_lookup = component_descriptor_lookup
        self.component_version_lookup = component_version_lookup
        self.db_session = db_session
        self.invalid_semver_ok = invalid_semver_ok


    def routing(
        self,
        routing_options: list[str],
    ) -> list[langchain.tools.BaseTool]:

        tools = []

        class RouteTool(langchain_core.pydantic_v1.BaseModel):
            next: str = langchain_core.pydantic_v1.Field(
                description='Next Node',
                anyOf=[{'enum': routing_options}]
            )
        def route_tool(self, next: str):
                return next

        tools.append(langchain.tools.StructuredTool.from_function(
            name = "route",
            description = "A tool to route requests based on the next step",
            args_schema = RouteTool,
            func=route_tool,
        ))

        return tools


    def components(self) -> list[langchain.tools.BaseTool]:
        tools = []

        #=============Function===================
        # Components of the Landscape
        #========================================

        def landscape_components():
            return [
                {
                    'name': component.name,
                    'verison': component.version,
                }
                for component
                in self.landscape_components
            ]
        tools.append(langchain.tools.StructuredTool.from_function(
            name = 'get_all_component_ids_in_landscape',
            description='Returns the component id of all components wihtin the landscape.',
            args_schema=langchain_core.pydantic_v1.BaseModel,
            func= landscape_components,
        ))

        #=============Function===================
        # Component Information
        #========================================

        class ComponentInfos(
            Parameters.component_id,
            Parameters.component_information,
            langchain_core.pydantic_v1.BaseModel,
        ):
            pass

        def component_infos(
            component_id: str,
            component_information: list[typing.Literal[
                'componentName',
                'componentVersion',
                'sources',
                'componentReferences_names',
                'componentReferences_identifications',
                'resources',
            ]]
        ):
            component_name = component_id.split(':')[0]
            component_version = component_id.split(':')[1]

            if component_version == 'greatest':
                component_version = components.greatest_version_if_none(
                    component_name=component_name,
                    version=None,
                    version_lookup=self.component_version_lookup,
                    version_filter=features.VersionFilter.RELEASES_ONLY,
                    invalid_semver_ok=self.invalid_semver_ok,
                )

            component = next((
                component
                for component
                in self.landscape_components
                if component.name == component_name
                   and component.version == component_version
            ), None)

            if component is None:
                return f'''
                    Querying the Component Descriptor with the following Name and
                    Version was not possible.

                    Name: {component_name}
                    Version: {component_version}

                    Thrown Exception:
                        component is not within the landscape
                '''
            result_map = {}

            if 'componentName' in component_information:
                result_map['componentName'] = component.name
            if 'componentVersion' in component_information:
                result_map['componentVersion'] = component.version
            if 'sources' in component_information:
                result_map['sources'] = component.sources
            if 'componentReferences_names' in component_information:
                result_map['componentReferences_names'] = [
                    reference.componentName
                    for reference
                    in component.componentReferences
                ]
            if 'componentReferences_identifications' in component_information:
                result_map['componentReferences_identifications'] = [
                    f'{reference.componentName}:{reference.version}'
                    for reference
                    in component.componentReferences
                ]
            if 'os' in component_information:
                os_query = self.db_session.query(
                    deliverydb.model.ArtefactMetaData.data.op('->>')('os_info'),
                ).filter(
                    deliverydb.model.ArtefactMetaData.type == dso.model.Datatype.OS_IDS,
                    sqlalchemy.or_(deliverydb.util.ArtefactMetadataQueries.component_queries(
                        components=[gci.componentmodel.ComponentIdentity(
                            name=component.name,
                            version=component.version,
                        )],
                    )),
                )
                result_map['os'] = os_query.first()
            if 'resources' in component_information:
                result_map['resources'] = [
                    {
                        'name': resource.name,
                        'version': resource.version,
                        'type': resource.type
                    }
                    for resource
                    in component.resources
                ]

            return result_map

        tools.append(langchain.tools.StructuredTool.from_function(
            name = 'get_component_information',
            description= 'Extracts specific information about a Component.',
            args_schema= ComponentInfos,
            func=component_infos,
        ))

        #=============Function===================
        # Components By Resource
        #========================================

        class ComponentsByResource(
            Parameters.resource_name,
            Parameters.resource_version_optional,
            langchain_core.pydantic_v1.BaseModel
        ):
            pass

        def components_by_resource(
            resource_name: str,
            resource_version: typing.Optional[str] = None,
        ):
            
            components_with_resource = [
                {
                    'component_name': component.name,
                    'component_version': component.version,
                    'resource_name': resource_name,
                    'resource_version': [
                        resource.version
                        for resource
                        in component.resources
                        if resource.name == resource_name
                    ]
                }
                for component
                in self.landscape_components
                if resource_name in [
                    resource.name
                    for resource
                    in component.resources
                ]
            ]

            if resource_version:
                components_with_resource = [
                    entry
                    for entry
                    in components_with_resource
                    if resource_version in entry['resource_version']
                ]
            if len(components_with_resource) > 0:
                return components_with_resource
            return f'''
                No component with the package {resource_name} 
                {f'version {resource_version}' if resource_version else ''} was found.
            '''

        tools.append(langchain.tools.StructuredTool.from_function(
            name='get_components_by_resource',
            description='Get all Components, which use a specific resource.',
            args_schema=ComponentsByResource,
            func=components_by_resource,
        ))

        
        #=============Function===================
        # Used Versions of Component
        #========================================

        class VersionsOfComponent(
            Parameters.component_name,
            langchain_core.pydantic_v1.BaseModel
        ):
            pass

        def versions_of_component(
            component_name: str,
        ):
            used_versions = [
                component.version
                for component
                in self.landscape_components
                if component.name == component_name
            ]
            if len(used_versions) > 0:
                return used_versions
            return f'Component {component_name} is not used within the landscspe.'

        tools.append(langchain.tools.StructuredTool.from_function(
            name='get_versions_of_component',
            description='Queries all the versions of a specific component, which appear the current Landscape.',
            args_schema=VersionsOfComponent,
            func=versions_of_component,
        ))

        return tools


    def resources(self) -> list[langchain.tools.BaseTool]:
        tools = []

        #=============Function===================
        # Used Resources in Landscape
        #========================================

        def resources_in_landscape():
            return set(
                {
                    'resource_name': resource.name,
                    'resource_version': resource.version,
                } 
                for component
                in self.landscape_components
                for resource
                in component.resources
            )
        tools.append(langchain.tools.StructuredTool.from_function(
            name='get_all_resource_ids_of_landscape',
            description='Queries the ID of all used Resources.',
            args_schema=langchain_core.pydantic_v1.BaseModel,
            func=resources_in_landscape,
        ))

        #=============Function===================
        # Resources With Specific OS
        #========================================

        class ResourcesByOs(
            Parameters.os_id,
            Parameters.os_version,
            langchain_core.pydantic_v1.BaseModel,
        ):
            pass

        def resources_by_os(os_id: str, os_version: str):

            landscape_component_ids = [
                component.identity()
                for component
                in self.landscape_components
            ]

            findings_query = self.db_session.query(
                deliverydb.model.ArtefactMetaData.artefact_name,
                deliverydb.model.ArtefactMetaData.artefact_version,
                deliverydb.model.ArtefactMetaData.data['os_info'].op('->>')('ID'),
                deliverydb.model.ArtefactMetaData.data['os_info'].op('->>')('VERSION_ID'),
            ).filter(
                sqlalchemy.or_(deliverydb.util.ArtefactMetadataQueries.component_queries(
                    components=landscape_component_ids
                )),
                deliverydb.model.ArtefactMetaData.type == dso.model.Datatype.OS_IDS,
                deliverydb.model.ArtefactMetaData.data['os_info'].op('->>')('ID') == os_id,
                deliverydb.model.ArtefactMetaData.data['os_info'].op('->>')('VERSION_ID').isnot(None)
                    if os_version is None or os_version == '' or os_version == '*'
                    else deliverydb.model.ArtefactMetaData.data['os_info'].op('->>')('VERSION_ID') == os_version
            ).distinct()

            findings = findings_query.all()

            return [{
                'name': finding[0],
                'version': finding[1],
                'os_id': finding[2],
                'os_version_id': finding[3],
            } for finding in findings]

        tools.append(langchain.tools.StructuredTool.from_function(
            name='get_resources_by_os',
            description='Queries all Resources, which are based on a specific os.',
            args_schema=ResourcesByOs,
            func=resources_by_os,
        ))

        #=============Function===================
        # Resources By Used Package
        #========================================

        class ResourcesByPackage(
            Parameters.package_name,
            Parameters.package_platform_optional,
            Parameters.package_version_optional,
            langchain_core.pydantic_v1.BaseModel
        ):
            pass
        
        def resources_by_package(
            package_name: str,
            package_version: typing.Optional[str] = None,
            package_platform: typing.Optional[str] = None,
        ):
            component_ids = tuple(
                component.identity()
                for component
                in self.landscape_components
            )

            findings_query = self.db_session.query(
                deliverydb.model.ArtefactMetaData.artefact_name,
                deliverydb.model.ArtefactMetaData.artefact_version,
                deliverydb.model.ArtefactMetaData.data.op('->>')('package_name'),
                deliverydb.model.ArtefactMetaData.data.op('->>')('package_version'),
            ).filter(
                deliverydb.model.ArtefactMetaData.type == dso.model.Datatype.STRUCTURE_INFO,
                sqlalchemy.or_(deliverydb.util.ArtefactMetadataQueries.component_queries(
                    components=component_ids,
                )),
                deliverydb.model.ArtefactMetaData.data.op('->>')('package_name') == package_name,
                deliverydb.model.ArtefactMetaData.data.op('->>')('package_version').isnot(None)
                    if package_version is None
                    else deliverydb.model.ArtefactMetaData.data.op('->>')('package_version') == package_version
            ).distinct()

            findings = findings_query.all()

            found_resources = [
                {
                    'resource_name': finding[0],
                    'resource_version': finding[1],
                    'package_name': finding[2],
                    'package_version': finding[3],
                } for finding
                in findings
            ]

            if len(found_resources) > 0:
                return found_resources

            findings_query = self.db_session.query(
                deliverydb.model.ArtefactMetaData.artefact_name,
                deliverydb.model.ArtefactMetaData.artefact_version,
                deliverydb.model.ArtefactMetaData.data.op('->>')('package_name'),
                deliverydb.model.ArtefactMetaData.data.op('->>')('package_version'),
            ).filter(
                deliverydb.model.ArtefactMetaData.type == dso.model.Datatype.STRUCTURE_INFO,
                sqlalchemy.or_(deliverydb.util.ArtefactMetadataQueries.component_queries(
                    components=component_ids,
                )),
                deliverydb.model.ArtefactMetaData.data.op('->>')('package_name').like(f'*{package_name}*'),
                deliverydb.model.ArtefactMetaData.data.op('->>')('package_version').isnot(None)
                    if package_version is None
                    else deliverydb.model.ArtefactMetaData.data.op('->>')('package_version') == package_version
            ).distinct()

            findings = findings_query.all()

            found_resources = [
                {
                    'resource_name': finding[0],
                    'resource_version': finding[1],
                    'package_name': finding[2],
                    'package_version': finding[3],
                } for finding
                in findings
            ]

            if len(found_resources) > 0:
                return f'''
                    There was no package with the exact name {package_name}.
                    But the following packages contain the given package_name:
                    {found_resources}
                '''

            return f'There is no resource with a package called {package_name}.'

        tools.append(langchain.tools.StructuredTool.from_function(
            name='get_resources_by_package',
            description='Returns all resources, which use a specific Package.',
            args_schema=ResourcesByPackage,
            func=resources_by_package,
        ))
        
        
        return tools

    def vulnerabilities(self)->list[langchain.tools.BaseTool]:
        tools = []

        #========================================
        # vulnerabilities for a Component
        #========================================

        class ComponentVulnerabilities(
            Parameters.component_id,
            Parameters.severities,
            Parameters.discovery_days_back,
            langchain_core.pydantic_v1.BaseModel,
        ):
            pass

        def component_vulnerabilities(
            component_id: str,
            severities: list[
                typing.Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
            ],
            discovery_days_back: int,
        ):
            component_identity = component_id_str_to_obj(component_id)

            findings_query = self.db_session.query(
                deliverydb.model.ArtefactMetaData.data.op('->>')('severity'),
                deliverydb.model.ArtefactMetaData.data.op('->>')('cve'),
            ).filter(
                deliverydb.model.ArtefactMetaData.type.__eq__(dso.model.Datatype.VULNERABILITY),
                sqlalchemy.or_(deliverydb.util.ArtefactMetadataQueries.component_queries(
                    components=[component_identity],
                )),
                deliverydb.model.ArtefactMetaData.data.op('->>')('severity').in_(severities),
                deliverydb.model.ArtefactMetaData.discovery_date > datetime.date.today() - datetime.timedelta(days=discovery_days_back)
            )

            findings = findings_query.all()

            return findings
            
        tools.append(langchain.tools.StructuredTool.from_function(
            name='get_component_vulnerabilities',
            description='Returns all vulnerability findings, filtered by the severity and the discovery_date, of a specific component.',
            args_schema=ComponentVulnerabilities,
            func=component_vulnerabilities,
        ))
        
        #=============Function===================
        # Resources with Finding
        #========================================

        class ResourcesWithFinding(
            Parameters.severities,
            Parameters.discovery_days_back,
            langchain_core.pydantic_v1.BaseModel,
        ):
            pass

        def resources_with_finding(
            severities: list[typing.Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']],
            discovery_days_back: int,
        ):
             
            landscape_component_ids = [
                component.identity()
                for component 
                in self.landscape_components
            ]

            findings_query = self.db_session.query(
                deliverydb.model.ArtefactMetaData.artefact_name,
                deliverydb.model.ArtefactMetaData.artefact_version,
                deliverydb.model.ArtefactMetaData.data.op('->>')('severity'),
                deliverydb.model.ArtefactMetaData.data.op('->>')('cve'),
            ).filter(
                deliverydb.model.ArtefactMetaData.type.__eq__(dso.model.Datatype.VULNERABILITY),
                sqlalchemy.or_(deliverydb.util.ArtefactMetadataQueries.component_queries(
                    components=landscape_component_ids,
                )),
                deliverydb.model.ArtefactMetaData.data.op('->>')('severity').in_(severities),
                deliverydb.model.ArtefactMetaData.discovery_date > datetime.date.today() - datetime.timedelta(days=discovery_days_back)
            )

            findings = findings_query.all()

            return set(
                json.dumps({
                    'resource_name': finding[0],
                    'resource_version': finding[1],
                    'finding_severity': finding[2],
                    'cve': finding[3],
                })
                for finding
                in findings
            )

        tools.append(langchain.tools.StructuredTool.from_function(
            name='get_resources_of_landscape_with_vulnerability',
            description='Queries and return all resources which have a vulnerability of one of the specified severities and discovery date.',
            args_schema=ResourcesWithFinding,
            func=resources_with_finding,
        ))


        #=============Function===================
        # Components with Finding
        #========================================

        class ComponentsWithFinding(
            Parameters.severities,
            Parameters.discovery_days_back,
            langchain_core.pydantic_v1.BaseModel,
        ):
            pass

        def components_with_finding(
            severities: list[typing.Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']],
            discovery_days_back: int,
        ):
             
            landscape_component_ids = [
                component.identity()
                for component 
                in self.landscape_components
            ]

            findings_query = self.db_session.query(
                deliverydb.model.ArtefactMetaData.artefact_name,
                deliverydb.model.ArtefactMetaData.artefact_version,
                deliverydb.model.ArtefactMetaData.data.op('->>')('severity'),
                deliverydb.model.ArtefactMetaData.data.op('->>')('cve'),
            ).filter(
                deliverydb.model.ArtefactMetaData.type.__eq__(dso.model.Datatype.VULNERABILITY),
                sqlalchemy.or_(deliverydb.util.ArtefactMetadataQueries.component_queries(
                    components=landscape_component_ids,
                )),
                deliverydb.model.ArtefactMetaData.data.op('->>')('severity').in_(severities),
                deliverydb.model.ArtefactMetaData.discovery_date > datetime.date.today() - datetime.timedelta(days=discovery_days_back)
            )

            findings = findings_query.all()

            return set(
                json.dumps({
                    'resource_name': finding[0],
                    'resource_version': finding[1],
                    'finding_severity': finding[2],
                    'cve': finding[3],
                })
                for finding
                in findings
            )

        tools.append(langchain.tools.StructuredTool.from_function(
            name='get_resources_of_landscape_with_vulnerability',
            description='Queries and return all components which have a vulnerability of one of the specified severities and discovery date.',
            args_schema=ComponentsWithFinding,
            func=components_with_finding,
        ))

        return tools
