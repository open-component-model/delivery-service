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
import sqlalchemy
import sqlalchemy.orm.query
import sqlalchemy.orm.session

import components
import deliverydb.model
import deliverydb.util
import eol
import features


def _get_component(
        component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
        component_version_lookup: cnudie.retrieve.VersionLookupByComponent,
        component_name: str,
        component_version: str,
        invalid_semver_ok: bool = False,
):
    if component_version == 'greatest':
        component_version = components.greatest_version_if_none(
            component_name=component_name,
            version=None,
            version_lookup=component_version_lookup,
            version_filter=features.VersionFilter.RELEASES_ONLY,
            invalid_semver_ok=invalid_semver_ok,
        )

    return component_descriptor_lookup(
        gci.componentmodel.ComponentIdentity(component_name, component_version),
        None,
    )


def get_ocm_tools(
        db_session: sqlalchemy.orm.session.Session,
        component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
        component_version_lookup: cnudie.retrieve.VersionLookupByComponent,
        github_api_lookup,
        landscape_components: list[gci.componentmodel.Component],
        invalid_semver_ok: bool = False,
) -> list[langchain.tools.BaseTool]:
    class GetComponentDescriptorInformationSchema(langchain_core.pydantic_v1.BaseModel):
        component_name: str = langchain_core.pydantic_v1.Field(
            description=(
                'The name of the OCM Component for which the Component Information should'
                ' be acquired.'
            )
        )
        component_version: str = langchain_core.pydantic_v1.Field(
            description=(
                'Version of the OCM Component. It should be a string following the semantic'
                ' versioning format (e.g., "2.1.1") or the string "greatest".'
            )
        )
        information: list[typing.Literal[
            'componentName',
            'componentVersion',
            'sources',
            'componentReferences_names',
            'componentReferences_identifications',
            'os',
            'resources',
        ]] = langchain_core.pydantic_v1.Field(
            description='Which information about the component will be returned.',
        )

    class GetComponentDescriptorInformation(langchain.tools.BaseTool):
        name = 'get_component_descriptor_information'
        description = (
            'A tool that Retrieves information about an OCM Component from within the landscape.'
        )
        args_schema: typing.Type[
                         langchain_core.pydantic_v1.BaseModel
                     ] | None = GetComponentDescriptorInformationSchema

        def _run(
                self,
                component_name: str,
                component_version: str,
                information: list[typing.Literal[
                    'componentName',
                    'componentVersion',
                    'sources',
                    'componentReferences_names',
                    'componentReferences_identifications',
                    'resources',
                ]]
        ):
            if component_version == 'greatest':
                component_version = components.greatest_version_if_none(
                    component_name=component_name,
                    version=None,
                    version_lookup=component_version_lookup,
                    version_filter=features.VersionFilter.RELEASES_ONLY,
                    invalid_semver_ok=invalid_semver_ok,
                )

            component = next((
                component
                for component
                in landscape_components
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

            if 'componentName' in information:
                result_map['componentName'] = component.name
            if 'componentVersion' in information:
                result_map['componentVersion'] = component.version
            if 'sources' in information:
                result_map['sources'] = component.sources
            if 'componentReferences_names' in information:
                result_map['componentReferences_names'] = [
                    reference.componentName
                    for reference
                    in component.componentReferences
                ]
            if 'componentReferences_identifications' in information:
                result_map['componentReferences_identifications'] = [
                    f'{reference.componentName}:{reference.version}'
                    for reference
                    in component.componentReferences
                ]
            if 'os' in information:
                os_query = db_session.query(
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
            if 'resources' in information:
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

    class GetComponentResourcesInfoSchema(langchain_core.pydantic_v1.BaseModel):
        component_name: str = langchain_core.pydantic_v1.Field(
            description=(
                'The name of the OCM Component for which the Resources Information should'
                ' be acquired.'
            )
        )
        component_version: str = langchain_core.pydantic_v1.Field(
            description=(
                'Version of the OCM Component. It should be a string following the semantic'
                ' versioning format (e.g., "2.1.1") or the string "greatest".'
            )
        )
        resource_names: list[str] = langchain_core.pydantic_v1.Field(
            description='Name of the resources.',
        )
        resource_info: list[typing.Literal[
            'os',
            'resource_type',
            'resource_access',
        ]] = langchain_core.pydantic_v1.Field(
            description='Selection, which information should be obtained'
        )

    class GetComponentResourcesInfo(langchain.tools.BaseTool):
        name = 'get_component_resources_info'
        description = (
            'A tool that Retrieves information about specific resources of an specific Component.'
        )
        args_schema: typing.Type[
            langchain_core.pydantic_v1.BaseModel
        ] | None = GetComponentResourcesInfoSchema

        def _run(
            self,
            component_name: str,
            component_version: str,
            resource_names: list[str],
            resource_info: list[typing.Literal[
                'resource_info',
                'resource_type',
                'resource_access',
            ]]
        ):
            if component_version == 'greatest':
                component_version = components.greatest_version_if_none(
                    component_name=component_name,
                    version=None,
                    version_lookup=component_version_lookup,
                    version_filter=features.VersionFilter.RELEASES_ONLY,
                    invalid_semver_ok=invalid_semver_ok,
                )
            component = next((
                component
                for component
                in landscape_components
                if component.name == component_name
                   and component.version == component_version
            ), None)

            if component is None:
                return '''
                Component could not be found within the landscape!
                '''

            results = []

            for resource in component.resources:
                if resource.name in resource_names:
                    resource_info_dict = {'name': resource.name, 'version': resource.version}
                    if 'os' in resource_info:
                        os_query = db_session.query(
                            deliverydb.model.ArtefactMetaData.data.op('->>')('os_info'),
                        ).filter(
                            deliverydb.model.ArtefactMetaData.type == dso.model.Datatype.OS_IDS,
                            sqlalchemy.or_(
                                deliverydb.util.ArtefactMetadataQueries.component_queries(
                                    components=[gci.componentmodel.ComponentIdentity(
                                        name=component.name,
                                        version=component.version,
                                    )],
                                )
                            ),
                            deliverydb.model.ArtefactMetaData.artefact_name == resource.name,
                            deliverydb.model.ArtefactMetaData.artefact_version == resource.version,
                        )
                        resource_info_dict['os'] = os_query.first()
                    if 'resource_type' in resource_info:
                        resource_info_dict['resource_type'] = resource.type
                    if 'resource_access' in resource_info:
                        resource_info_dict['resource_access'] = resource.access

                    results.append(resource_info_dict)
            return results

    class GetResourcesOfComponentByOSSchema(langchain_core.pydantic_v1.BaseModel):
        component_name: str = langchain_core.pydantic_v1.Field(
            description=(
                'The name of the OCM Component for which the Resources Information should'
                ' be acquired.'
            )
        )
        component_version: str = langchain_core.pydantic_v1.Field(
            description=(
                'Version of the OCM Component. It should be a string following the semantic'
                ' versioning format (e.g., "2.1.1") or the string "greatest".'
            )
        )
        os_ids: list[str] = langchain_core.pydantic_v1.Field(
            description='os id\'s by which the resources get filtered',
        )

    class GetResourcesOfComponentByOS(langchain.tools.BaseTool):
        name = 'get_resources_of_component_by_os'
        description = (
            'A tool that return all resource names and versions of resources which are'
            ' based on one of the given os id\'s.'
        )
        args_schema: typing.Type[
            langchain_core.pydantic_v1.BaseModel
        ] | None = GetResourcesOfComponentByOSSchema

        def _run(
            self,
            component_name: str,
            component_version: str,
            os_ids: list[str],
        ):
            if component_version == 'greatest':
                component_version = components.greatest_version_if_none(
                    component_name=component_name,
                    version=None,
                    version_lookup=component_version_lookup,
                    version_filter=features.VersionFilter.RELEASES_ONLY,
                    invalid_semver_ok=invalid_semver_ok,
                )

            component = next((
                component
                for component
                in landscape_components
                if component.name == component_name
                   and component.version == component_version
            ), None)

            if component is None:
                return '''
                Component could not be found within the landscape!
                '''

            component_id = gci.componentmodel.ComponentIdentity(
                name=component.name,
                version=component.version,
            )

            findings_query = db_session.query(
                deliverydb.model.ArtefactMetaData.artefact_name,
                deliverydb.model.ArtefactMetaData.artefact_version,
                deliverydb.model.ArtefactMetaData.data.op('->>')('os_info'),
            ).filter(
                deliverydb.model.ArtefactMetaData.type == dso.model.Datatype.OS_IDS,
                sqlalchemy.or_(
                    deliverydb.util.ArtefactMetadataQueries.component_queries(
                        components=[component_id],
                    )
                ),
                deliverydb.model.ArtefactMetaData.data.op('->')('os_info').op('->>')('ID').in_(os_ids),
            ).distinct()

            findings_raw = findings_query.all()
            findings = [
                {
                    'name': raw[0],
                    'version': raw[1],
                    'oc_info': raw[2],
                }
                for raw in findings_raw
            ]
            return findings

    class GetAllInLandscapeUsedOS(langchain.tools.BaseTool):
        name = 'get_all_in_landscape_used_os'
        description = (
            'A tool that returns all Operating Systems that are used in the landscape.'
        )
        args_schema: typing.Type[
            langchain_core.pydantic_v1.BaseModel
        ] | None = langchain_core.pydantic_v1.BaseModel

        def _run(self):

            landscape_component_ids = [
                gci.componentmodel.ComponentIdentity(
                    name=component.name,
                    version=component.version,
                )
                for component
                in landscape_components
            ]

            os_query = db_session.query(
                deliverydb.model.ArtefactMetaData.data['os_info'].op('->>')('ID'),
                deliverydb.model.ArtefactMetaData.data['os_info'].op('->>')('VERSION_ID'),
                deliverydb.model.ArtefactMetaData.data['os_info'].op('->>')('PRETTY_NAME'),
            ).filter(
                deliverydb.model.ArtefactMetaData.type == dso.model.Datatype.OS_IDS,
                sqlalchemy.or_(
                    deliverydb.util.ArtefactMetadataQueries.component_queries(
                        components=landscape_component_ids,
                    )
                ),
            ).distinct()

            os_raw = os_query.all()

            os_list = [
                {
                    'os_id': os[0],
                    'os_version_id': os[1],
                } for os in os_raw
            ]

            return os_list

    class SearchInLandscapeByNamesSchema(langchain_core.pydantic_v1.BaseModel):
        searched_component_names: list[str] = langchain_core.pydantic_v1.Field(
            description=(
                'Component names to be searched for in the component reference tree structure.'
            )
        )

    class SearchInLandscapeByNames(langchain.tools.BaseTool):
        name = 'search_in_landscape_by_names'
        description = (
            'A tool that uses names to search for components within the landscape.'
        )
        args_schema: typing.Type[
            langchain_core.pydantic_v1.BaseModel
        ] | None = SearchInLandscapeByNamesSchema

        def _run(
            self,
            searched_component_names: list[str],
        ):
            if len(searched_component_names) == 0:
                return 'You need to provide at least one valid name in searched_component_names!'

            filtered_components = [
                {
                    'name': component.name,
                    'version': component.version,
                }
                for component
                in landscape_components 
                if component.name in searched_component_names
            ]
            return {'components': filtered_components}

    class SearchComponentsInLandscapeByResourceWithSpecificOSSchema(langchain_core.pydantic_v1.BaseModel):
        searched_os_id: str = langchain_core.pydantic_v1.Field(
            description=(
                'Operating System id to be searched for in the resources of the components.'
            ),
        )
        searched_os_version_id: str = langchain_core.pydantic_v1.Field(
            description=(
                'Operating System version to be searched for in the resources of the components.'
            ),
        )

    class SearchComponentsInLandscapeByResourceWithSpecificOS(langchain.tools.BaseTool):
        name = 'search_components_in_landscape_by_resource_with_specific_os'
        description = (
            'A tool that searches for components within the landscape that have resources'
            ' with a specific operating system.'
        )
        args_schema: typing.Type[
            langchain_core.pydantic_v1.BaseModel
        ] | None = SearchComponentsInLandscapeByResourceWithSpecificOSSchema

        def _run(
                self,
                searched_os_id: str,
                searched_os_version_id: str,
        ):

            landscape_component_ids = [
                gci.componentmodel.ComponentIdentity(
                    name=component.name,
                    version=component.version,
                )
                for component
                in landscape_components
            ]

            findings_query = db_session.query(
                deliverydb.model.ArtefactMetaData.component_name,
                deliverydb.model.ArtefactMetaData.component_version,
                deliverydb.model.ArtefactMetaData.data['os_info'].op('->>')('ID'),
                deliverydb.model.ArtefactMetaData.data['os_info'].op('->>')('VERSION_ID'),
            ).filter(
                sqlalchemy.or_(deliverydb.util.ArtefactMetadataQueries.component_queries(
                    components=landscape_component_ids
                )),
                deliverydb.model.ArtefactMetaData.type == dso.model.Datatype.OS_IDS,
                deliverydb.model.ArtefactMetaData.data['os_info'].op('->>')('ID') == searched_os_id,
                deliverydb.model.ArtefactMetaData.data['os_info'].op('->>')('VERSION_ID').isnot(None)
                    if searched_os_version_id is None or searched_os_version_id == '' or searched_os_version_id == '*'
                    else deliverydb.model.ArtefactMetaData.data['os_info'].op('->>')('VERSION_ID') == searched_os_version_id
            ).distinct()

            findings = findings_query.all()

            return [{
                'name': finding[0],
                'version': finding[1],
                'os_id': finding[2],
                'os_version_id': finding[3],
            } for finding in findings]

    return [
        GetComponentDescriptorInformation(),
        GetComponentResourcesInfo(),
        GetResourcesOfComponentByOS(),
        SearchInLandscapeByNames(),
        SearchComponentsInLandscapeByResourceWithSpecificOS(),
        GetAllInLandscapeUsedOS(),
    ]


def create_routing_tools_list(
        routing_options: list[str],
) -> list[langchain.tools.BaseTool]:
    class RouteToolSchema(langchain_core.pydantic_v1.BaseModel):
        next: str = langchain_core.pydantic_v1.Field(
            description="Next Node",
            anyOf=[{"enum": routing_options}]
        )

    class RouteTool(langchain.tools.BaseTool):
        name = "route"
        description = "A tool to route requests based on the next step"
        args_schema: typing.Type[langchain_core.pydantic_v1.BaseModel] | None = RouteToolSchema

        def _run(self, next: str):
            print(f'Next Agent: {next}')
            return next

    return [RouteTool()]



def get_vulnerability_tools(
        db_session: sqlalchemy.orm.session.Session,
        component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
        component_version_lookup: cnudie.retrieve.VersionLookupByComponent,
        github_api_lookup,
        landscape_components: list[gci.componentmodel.Component],
        invalid_semver_ok: bool = False,
) -> list[langchain.tools.BaseTool]:
    class GetVulnerabilityFindingsForComponentsResourcesSchema(langchain_core.pydantic_v1.BaseModel):
        component_identities: list[str] = langchain_core.pydantic_v1.Field(
            description='''
                Component Identities: A component identity is always a concatenation of a
                'Component Name,' ':' and 'Component Version.'
            '''
        )

    class GetVulnerabilityFindingsForComponents(langchain.tools.BaseTool):
        name = 'get_vulnerability_findings_for_components_resources'
        description = (
            'A tool that returns the findings of a specific type or types for specific component'
        )
        args_schema: typing.Type[
                         langchain_core.pydantic_v1.BaseModel
                     ] | None = GetVulnerabilityFindingsForComponentsResourcesSchema

        def _run(
                self,
                component_identities: list[str]
        ):

            given_component_ids = [
                gci.componentmodel.ComponentIdentity(
                    name=component_identitie.split(':')[0],
                    version= components.greatest_version_if_none(
                        component_name=component_identitie.split(':')[0],
                        version=None,
                        version_lookup=component_version_lookup,
                        version_filter=features.VersionFilter.RELEASES_ONLY,
                        invalid_semver_ok=invalid_semver_ok,
                    ) if component_identitie.split(':')[1] == 'greatest' else component_identitie.split(':')[1]
                )
                for component_identitie
                in component_identities
            ]

            landscape_component_ids = [
                gci.componentmodel.ComponentIdentity(
                    name=component.name,
                    version=component.version,
                )
                for component 
                in landscape_components
            ]

            for component_id in given_component_ids:
                if component_id not in landscape_component_ids:
                    return f'''
                    There is no component with the component id {component_id.name}:{component_id.version} in the landscape. 
                    '''

            findings_query = db_session.query(deliverydb.model.ArtefactMetaData).filter(
                sqlalchemy.or_(deliverydb.util.ArtefactMetadataQueries.component_queries(
                    components=given_component_ids,
                )),
                deliverydb.model.ArtefactMetaData.type.__eq__(dso.model.Datatype.VULNERABILITY),
            )

            findings_raw = findings_query.all()
            findings = [
                deliverydb.util.db_artefact_metadata_to_dso(raw)
                for raw in findings_raw
            ]

            return [{
                f'{finding.artefact.component_name}:{finding.artefact.component_version}': finding.data
            } for finding in findings]

    class GetTransitiveReferencesWithVulnerabilitySchema(langchain_core.pydantic_v1.BaseModel):
        root_component_name: str = langchain_core.pydantic_v1.Field(
            description=(
                'Name of the component which serves as root for the component references Tree.'
            )
        )
        root_component_version: str = langchain_core.pydantic_v1.Field(
            description=(
                'Version of the component which serves as root for the component references Tree.'
                ' "greatest" for most recent version.'
            )
        )
        severities: list[
            typing.Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        ] = langchain_core.pydantic_v1.Field(
            description='Severity levels for which should be queried.',
        )

    class GetTransitiveReferencesWithVulnerability(langchain.tools.BaseTool):
        name = 'get_transitive_references_with_vulnerability'
        description = (
            'A tool that return all transitive references of a specific root component,'
            ' which have a security Vulnerability.'
        )
        args_schema: typing.Type[
                         langchain_core.pydantic_v1.BaseModel
                     ] | None = GetTransitiveReferencesWithVulnerabilitySchema

        def _run(
                self,
                root_component_name: str,
                root_component_version: str,
                severities: list[typing.Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']]
        ):
            if root_component_version == 'greatest':
                root_component_version = components.greatest_version_if_none(
                    component_name=root_component_name,
                    version=None,
                    version_lookup=component_version_lookup,
                    version_filter=features.VersionFilter.RELEASES_ONLY,
                    invalid_semver_ok=invalid_semver_ok,
                )

            component_references = components.resolve_component_dependencies(
                component_name=root_component_name,
                component_version=root_component_version,
                component_descriptor_lookup=component_descriptor_lookup,
                ctx_repo=None,
            )

            dependency_ids = tuple(
                gci.componentmodel.ComponentIdentity(
                    name=component.component.name,
                    version=component.component.version,
                )
                for component
                in component_references
            )

            findings_query = db_session.query(
                deliverydb.model.ArtefactMetaData.component_name,
                deliverydb.model.ArtefactMetaData.component_version,
                deliverydb.model.ArtefactMetaData.data.op('->>')('severity'),
            ).filter(
                deliverydb.model.ArtefactMetaData.type == dso.model.Datatype.VULNERABILITY,
                sqlalchemy.or_(deliverydb.util.ArtefactMetadataQueries.component_queries(
                    components=dependency_ids,
                )),
                deliverydb.model.ArtefactMetaData.data.op('->>')('severity').in_(severities)
            )

            findings_raw = findings_query.all()
            findings = set(
                f'name: {raw[0]} / version: {raw[1]} / severity: {raw[2]}'
                for raw in findings_raw
            )

            return findings

    class GetAllComponentsWithCVESchema(langchain_core.pydantic_v1.BaseModel):
        cve: str = langchain_core.pydantic_v1.Field(description='CVE of interest.')
        pagination_page: int = langchain_core.pydantic_v1.Field(
            description='Pagination page, starts at page 1',
            default=1
        )

    class GetAllComponentsWithCVE(langchain.tools.BaseTool):
        name = 'get_all_components_with_cve'
        description = (
            'A tool returns all components which are affected by a specific CVE.'
            ' For the sake of performance, it paginates the results in the size of 100 entries.'
        )
        args_schema: typing.Type[
                         langchain_core.pydantic_v1.BaseModel
                     ] | None = GetAllComponentsWithCVESchema

        def _run(
                self,
                cve: str,
                pagination_page,
        ):
            cve_pattern = r'^CVE-\d{4}-\d{1,}$'
            valid_pattern = bool(re.match(cve_pattern, cve))
            if not valid_pattern:
                return 'Please provide a valid CVE with the following pattern: ^CVE-\d{4}-\d{1,}$'

            total_results = db_session.query(
                deliverydb.model.ArtefactMetaData.component_name,
                deliverydb.model.ArtefactMetaData.component_version,
            ).filter(
                deliverydb.model.ArtefactMetaData.type == dso.model.Datatype.VULNERABILITY,
                deliverydb.model.ArtefactMetaData.data.op('->>')('cve') == cve,
            ).order_by(
                deliverydb.model.ArtefactMetaData.component_name,
            ).group_by(
                deliverydb.model.ArtefactMetaData.component_name,
                deliverydb.model.ArtefactMetaData.component_version,
            ).count()

            print(total_results)

            findings_query = db_session.query(
                deliverydb.model.ArtefactMetaData.component_name,
                deliverydb.model.ArtefactMetaData.component_version,
            ).filter(
                deliverydb.model.ArtefactMetaData.type == dso.model.Datatype.VULNERABILITY,
                deliverydb.model.ArtefactMetaData.data.op('->>')('cve') == cve,
            ).order_by(
                deliverydb.model.ArtefactMetaData.component_name,
            ).group_by(
                deliverydb.model.ArtefactMetaData.component_name,
                deliverydb.model.ArtefactMetaData.component_version,
            ).offset(
                100 * (pagination_page - 1),
            ).limit(
                100,
            )

            findings_raw = findings_query.all()
            pprint.pprint(findings_raw)

            return {
                'findings': findings_raw,
                'page': pagination_page,
                'total_pages': math.ceil(total_results / 100),
            }

    return [
        GetVulnerabilityFindingsForComponents(),
        GetAllComponentsWithCVE(),
        GetTransitiveReferencesWithVulnerability(),
    ]


def get_malware_tools(
        db_session: sqlalchemy.orm.session.Session,
        component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
        component_version_lookup: cnudie.retrieve.VersionLookupByComponent,
        github_api_lookup,
        invalid_semver_ok: bool = False,
) -> list[langchain.tools.BaseTool]:
    class GetMalwareFindingsForComponentSchema(langchain_core.pydantic_v1.BaseModel):
        component_name: str = langchain_core.pydantic_v1.Field(description="Component Name")
        component_version: str = langchain_core.pydantic_v1.Field(
            description="Component Version, 'greatest' for the newest one or a specific version"
        )

    class GetMalwareFindingsForComponent(langchain.tools.BaseTool):
        name = 'get_malware_findings_for_component'
        description = (
            'A tool that returns the findings of a specific type or types for specific component'
        )
        args_schema: typing.Type[
                         langchain_core.pydantic_v1.BaseModel
                     ] | None = GetMalwareFindingsForComponentSchema

        def _run(
                self,
                component_name: str,
                component_version: str,
        ):
            if component_version == 'greatest':
                component_version = components.greatest_version_if_none(
                    component_name=component_name,
                    version=None,
                    version_lookup=component_version_lookup,
                    version_filter=features.VersionFilter.RELEASES_ONLY,
                    invalid_semver_ok=invalid_semver_ok,
                )

            component_id = gci.componentmodel.ComponentIdentity(
                name=component_name,
                version=component_version,
            )

            findings_query = db_session.query(deliverydb.model.ArtefactMetaData).filter(
                sqlalchemy.or_(deliverydb.util.ArtefactMetadataQueries.component_queries(
                    components=(component_id,)
                )),
                deliverydb.model.ArtefactMetaData.type.__eq__(dso.model.Datatype.MALWARE),
            )

            findings_raw = findings_query.all()
            findings = [
                deliverydb.util.db_artefact_metadata_to_dso(raw)
                for raw in findings_raw
            ]

            return [{
                f'{finding.artefact.component_name}:{finding.artefact.component_version}': finding.data
            } for finding in findings]

    return [
        GetMalwareFindingsForComponent(),
    ]


def get_license_tools(
        db_session: sqlalchemy.orm.session.Session,
        component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
        component_version_lookup: cnudie.retrieve.VersionLookupByComponent,
        github_api_lookup,
        invalid_semver_ok: bool = False,
) -> list[langchain.tools.BaseTool]:
    class GetLicenseFindingsForComponentSchema(langchain_core.pydantic_v1.BaseModel):
        component_name: str = langchain_core.pydantic_v1.Field(description="Component Name")
        component_version: str = langchain_core.pydantic_v1.Field(
            description="Component Version, 'greatest' for the newest one or a specific version"
        )

    class GetLicenseFindingsForComponent(langchain.tools.BaseTool):
        name = 'get_license_findings_for_component'
        description = (
            'A tool that returns the findings of a specific type or types for specific component'
        )
        args_schema: typing.Type[
                         langchain_core.pydantic_v1.BaseModel
                     ] | None = GetLicenseFindingsForComponentSchema

        def _run(
                self,
                component_name: str,
                component_version: str,
        ):
            if component_version == 'greatest':
                component_version = components.greatest_version_if_none(
                    component_name=component_name,
                    version=None,
                    version_lookup=component_version_lookup,
                    version_filter=features.VersionFilter.RELEASES_ONLY,
                    invalid_semver_ok=invalid_semver_ok,
                )

            component_id = gci.componentmodel.ComponentIdentity(
                name=component_name,
                version=component_version,
            )

            findings_query = db_session.query(deliverydb.model.ArtefactMetaData).filter(
                sqlalchemy.or_(deliverydb.util.ArtefactMetadataQueries.component_queries(
                    components=(component_id,)
                )),
                deliverydb.model.ArtefactMetaData.type == dso.model.Datatype.LICENSE,
            )

            findings_raw = findings_query.all()
            findings = [
                deliverydb.util.db_artefact_metadata_to_dso(raw)
                for raw in findings_raw
            ]

            pprint.pprint([{
                f'{finding.artefact.component_name}:{finding.artefact.component_version}': finding.data
            } for finding in findings])

            return [{
                f'{finding.artefact.component_name}:{finding.artefact.component_version}': finding.data
            } for finding in findings]

    return [
        GetLicenseFindingsForComponent(),
    ]


def get_end_of_life_tools(
        db_session: sqlalchemy.orm.session.Session,
        component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
        component_version_lookup: cnudie.retrieve.VersionLookupByComponent,
        github_api_lookup,
        eol_client: eol.EolClient,
        landscape_components: list[gci.componentmodel.Component],
        invalid_semver_ok: bool = False,
) -> list[langchain.tools.BaseTool]:

    class GetEndOfLifeInformationForOSSchema(langchain_core.pydantic_v1.BaseModel):
        os_id: str = langchain_core.pydantic_v1.Field(
            description=f'Operating System ID, can have one of the following values: {eol_client.all_products}'
        )
        os_version_id: typing.Optional[str] = langchain_core.pydantic_v1.Field(
            description='Optional Parameter, Operating System Version ID.'
        )

    class GetEndOfLifeInformationForOS(langchain.tools.BaseTool):
        name = 'get_end_of_life_information_for_os'
        description = (
            'A tool that returns the end of life information for a specific Operating System.'
        )
        args_schema: typing.Type[
                         langchain_core.pydantic_v1.BaseModel
                     ] | None = GetEndOfLifeInformationForOSSchema

        def _run(
                self,
                os_id: str,
                os_version_id: str,
        ):
            if os_id not in eol_client.all_products():
                return f'OS ID: {os_id} is not in the list of supported OS ID\'s for the eol API.'

            if os_version_id is None or os_version_id == '':
                return eol_client.cycles(os_id)
            else:
                return eol_client.cycle(os_id, os_version_id)

    return [GetEndOfLifeInformationForOS()]
