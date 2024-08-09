import abc
import json
import os
import pprint
import typing

import langchain_core.output_parsers
import langchain_core.prompts
import langchain_core.pydantic_v1
import langchain_core.runnables
import langchain_openai
import langfuse.callback
import langgraph.graph
import sqlalchemy.orm.session

import ai.ai_constants
import ai.filter
import ai.filter_json_structure
import ai.graph
import ai.state
import cnudie.retrieve
import gci.componentmodel

OPEN_AI_MODEL: str = os.getenv('OPEN_AI_MODEL') # type: ignore
#-------------------------
# AGENT: ComponentAgent
#-------------------------

class ComponentState(typing.TypedDict):
  question: str
  chosen_filters: ai.filter_json_structure.FilterJsonStruckture|None

# filters = [
#         {'name': 'resource', 'description': 'Filter by the resource a component references.'},
#         {'name': 'vulnerability', 'description': 'Filter by specific vulnerabilities in components'},
#         {'name': 'malware', 'description': 'Filter by the presence of malware in components'},
#         {'name': 'package', 'description': 'Filter by packages, a components depends on.'},
#         {'name': 'id', 'description': 'Filter by component id, which consists of name and version.'},
#       ]
    
  
class _IdFilter(ai.filter.BaseFilter):
  def __init__(
    self, 
    name,
    description,
    landscape_components: list[gci.componentmodel.Component],
  ) -> None:
    self.name = name
    self.description = description
    self.landscape_components = landscape_components
    
  def filter(
    self,
    question: str
  ) -> set[gci.componentmodel.ComponentIdentity]:
    class IdFilterProp(langchain_core.pydantic_v1.BaseModel):
      name: str = langchain_core.pydantic_v1.Field(description='Name of the Component')
      version: typing.Optional[str] = langchain_core.pydantic_v1.Field(None, description='Version of the component')
    class IdFilterPropsList(langchain_core.pydantic_v1.BaseModel):
      ids: list[IdFilterProp] = langchain_core.pydantic_v1.Field([], description='A list of ID objects to filter the components.')
    
    json_parser = langchain_core.output_parsers.JsonOutputParser(pydantic_object=IdFilterPropsList)
    llm = langchain_openai.AzureChatOpenAI(
      model=OPEN_AI_MODEL,
      temperature=0.0,
    ).bind(
      response_format={"type": "json_object"}
    )
    prompt = langchain_core.prompts.ChatPromptTemplate.from_messages([
      (
        'system',
        'The current task is to filter a list of Components by its Id (name + version).'
        ' Please extract the needed information for filtering out of the Users Question.\n'
        '\n'
        'Format the response in valid JSON in the following format:\n'
        '{format_instructions}'
      ),
      (
        'human',
        '{question}'
      )
    ]).partial(
      format_instructions=json_parser.get_format_instructions(),
      question=question
    )
    
    chain = (
      prompt
      | llm
      | json_parser
    )
    
    id_filter_props_list = IdFilterPropsList(**chain.invoke({}))
    print(id_filter_props_list)
    
    component_ids = set()
    for id in id_filter_props_list.ids:
      if id.version == None:
        component_ids.update([component.identity() for component in self.landscape_components if component.name == id.name])
      else:
        component_ids.update([component.identity() for component in self.landscape_components if component.name == id.name and component.version == id.version])
    return component_ids
  
class _PackagesFilter(ai.filter.BaseFilter):
  def __init__(
    self, 
    name: str,
    description: str,
    landscape_components: list[gci.componentmodel.Component],
    db_session: sqlalchemy.orm.session.Session,
  ) -> None:
    self.name = name
    self.description = description
    self.landscape_components = landscape_components
    self.db_session = db_session
    
  def filter(self, question: str) -> set[gci.componentmodel.ComponentIdentity]:
    
    class PackageInformation(langchain_core.pydantic_v1.BaseModel):
      name: str = langchain_core.pydantic_v1.Field(description='')
    class Question(langchain_core.pydantic_v1.BaseModel):
      question: str = langchain_core.pydantic_v1.Field(
        description=(
          'A question, which helps finding the packages, the user refers to in his question for filtering.'
        )
      )
    class SpecificPackagesMentionedReturn(langchain_core.pydantic_v1.BaseModel):
      specific_packages_mentioned: bool = langchain_core.pydantic_v1.Field(
        ..., 
        description=(
          'Specifies, if the packages for which to filter are directly named by name (and version).\n'
          'true = The packages are directly specified by name.\n'
          'false = The packages are not directly specified by name.'
        )
      )
      data: list[PackageInformation] | Question = langchain_core.pydantic_v1.Field(
        description=(
          'If specific_packages_mentioned = true, fill the data field with a list of PackageInformation\n'
          'If specific_packages_mentioned = false, fill the data field with a question, which can be used to get a list of packages for filtering.'
        )
      )
    
    specific_packages_mentioned_json_parser = langchain_core.output_parsers.JsonOutputParser(pydantic_object=SpecificPackagesMentionedReturn)
    llm = langchain_openai.AzureChatOpenAI(
      model=OPEN_AI_MODEL,
      temperature=0.0,
    ).bind(
      response_format={"type": "json_object"}
    )
    specific_packages_mentioned_prompt = langchain_core.prompts.ChatPromptTemplate.from_messages([
      (
        'system',
        'The current task is to filter a list of Components by the packages, it depends on.'
        ' Are any specific Packages mentioned, the user wants to filter for?\n'
        '\n'
        'Format the response in valid JSON in the following format:\n'
        '{format_instructions}'
      ),
      (
        'human',
        '{question}'
      )
    ]).partial(
      format_instructions=specific_packages_mentioned_json_parser.get_format_instructions(),
      question=question
    )
    
    runnable_config = langchain_core.runnables.RunnableConfig(
          configurable={
              'thread_id': 1,
          },
          callbacks=[langfuse.callback.CallbackHandler()],
      )
    specific_packages_mentioned_return = SpecificPackagesMentionedReturn(
      **(specific_packages_mentioned_prompt | llm | specific_packages_mentioned_json_parser).invoke(input={}, config=runnable_config)
    )
    
    print(specific_packages_mentioned_return.json())
    
    return []

class _ChooseFilters:
    def __init__(
      self,
      available_filters: list[ai.filter.BaseFilter],
    ) -> None:
      json_parser = langchain_core.output_parsers.JsonOutputParser(pydantic_object=ai.filter_json_structure.FilterJsonStruckture)
      llm = langchain_openai.AzureChatOpenAI(
        model=OPEN_AI_MODEL,
        temperature=0.0,
      ).bind(
        response_format={"type": "json_object"}
      )
      
      filter_prompt = langchain_core.prompts.ChatPromptTemplate.from_messages([
        (
          'system',
          'The user has asked a question.'
          ' The goal of the question is a list of OCM (Open Component Model) components.\n'
          '\n'
          'The current list contains all OCM components, for the landscape.\n'
          '\n'
          'Please decide based on the users question, how this big list of OCM'
          ' components should be filtered. You can choose only one or several'
          ' filters and then decide, how the resulting lists of the different filters should'
          ' be merged.\n'
          'You have these different filtering options:\n'
          '<filter_options>\n'
          '{filter_options}\n'
          '</filter_options>\n'
          '\n'
          'Please return a JSON structure in the following format:\n'
          '{json_format}\n'
          '\n'
          '<example>\n'
          '  <question>Is there a component called "github.com/gardener/cc-utils"'
          ' in the landscape with version 1.2424.0 which depends on an package with'
          ' a vulnerability?</question>\n'
          '''  
            <answer>
              {{
                "filters": {{
                    "AND": [
                        {{
                            "question": "Is there a component called 'github.com/gardener/cc-utils' in the landscape with version 1.2424.0?",
                            "filter_name": "id"
                        }},
                        {{
                            "question": "Does this component 'github.com/gardener/cc-utils' depend on a package with a vulnerability?",
                            "filter_name": "packages"
                        }}
                    ]
                }}
            }}
            </answer>\n
          '''
          '</example>\n'
        ),
        (
          'human',
          '{question}'
        )
      ]).partial(
        filter_options=[filter.name for filter in available_filters],
        json_format=ai.filter_json_structure.generate_filter_json_structure([
          {
            'name': filter.name,
            'description': filter.description,
          } for filter in available_filters
        ])
      )
      
      self.runnable = (
        filter_prompt
        | llm
        | json_parser
      )
      
    def __call__(
      self,
      state: ComponentState
    ) -> ComponentState:
      langfuse_handler = langfuse.callback.CallbackHandler()
      runnable_config = langchain_core.runnables.RunnableConfig(
          configurable={
              'thread_id': 2,
          },
          callbacks=[langfuse_handler],
      )
      chosen_filters: ai.filter_json_structure.FilterJsonStruckture = ai.filter_json_structure.FilterJsonStruckture(
        **self.runnable.invoke(
          input={
            'question': state['question'],
          },
          config=runnable_config,
        )
      )
      return {
        'chosen_filters': chosen_filters,
        'question': state['question']
      } # type: ignore
    

class ComponentAgent():
  def __init__(
    self,
    landscape_components: list[gci.componentmodel.Component],
    db_session: sqlalchemy.orm.session.Session,
  ) -> None:
    self.available_filters: list[ai.filter.BaseFilter] = [
      _IdFilter(
        name='id',
        description='Filter by component id, which consists of name and version.',
        landscape_components=landscape_components,
      ),
      _PackagesFilter(
        name='packages',
        description='Filter by Packages.',
        landscape_components=landscape_components,
        db_session=db_session,
      )
    ]
    self.landscape_components = landscape_components
   
  def __call__(self, state: ai.state.State) -> ai.state.State:
    component_state = ComponentState(
      question=state['question'],
      chosen_filters=None
    )
    
    component_state = _ChooseFilters(available_filters=self.available_filters).__call__(component_state)
    filter_struckture = component_state['chosen_filters']
    if filter_struckture == None:
      raise ValueError('filter_struckture shoulb be set in Component State, but wasent!')
    
    result_dict = start_run_filters(
      filters_plan=filter_struckture.filter,
      available_filters=self.available_filters
    )
    pprint.pprint(result_dict)

    return state
  

#---------------------------------------
# Run Filters
#---------------------------------------
  
def add_to_dict(my_dict: dict, path: list[str], value: typing.Any):
    for key in path[:-1]:
        my_dict = my_dict.setdefault(key, {})
    my_dict[path[-1]] = value
    
def start_run_filters(
  filters_plan: ai.filter_json_structure.Conditions,
  available_filters: list[ai.filter.BaseFilter]
)->dict[str, str|list[gci.componentmodel.ComponentIdentity]]:
  result_dict:dict[str, str|list[gci.componentmodel.ComponentIdentity]] = {}
  if filters_plan.AND:
    recursive_run_filters(
      filters_plan=filters_plan.AND,
      available_filters=available_filters,
      path=['AND'],
      result_dict=result_dict,
    )
  elif filters_plan.OR:
    recursive_run_filters(
      filters_plan=filters_plan.OR,
      available_filters=available_filters,
      path=['OR'],
      result_dict=result_dict,
    )
  elif filters_plan.XOR:
    recursive_run_filters(
      filters_plan=filters_plan.XOR,
      available_filters=available_filters,
      path=['XOR'],
      result_dict=result_dict,
    ) 
  elif filters_plan.NOT:
    recursive_run_filters(
      filters_plan=filters_plan.NOT,
      available_filters=available_filters,
      path=['NOT'],
      result_dict=result_dict,
    )
  else:
    raise ValueError("filters_plan of type Condition has no valid condition selected!")
  
  return result_dict
  
def recursive_run_filters(
  filters_plan: list[ai.filter_json_structure.Conditions | ai.filter_json_structure.Filter],
  available_filters: list[ai.filter.BaseFilter],
  path: list[str],
  result_dict: dict[str, typing.Any]
):
  for operation in filters_plan:
    if isinstance(operation, ai.filter_json_structure.Filter):
      for available_filter in available_filters:
        if available_filter.name == operation.filter_name:
          filter_result = available_filter.filter(operation.question)
          add_to_dict(result_dict, path+[operation.filter_name], filter_result)
    elif isinstance(operation, ai.filter_json_structure.Conditions):
      if operation.AND:
        recursive_run_filters(
          filters_plan=operation.AND,
          available_filters=available_filters,
          path=path+['AND'],
          result_dict=result_dict,
        )
      if operation.OR:
        recursive_run_filters(
          filters_plan=operation.OR,
          available_filters=available_filters,
          path=path+['OR'],
          result_dict=result_dict,
        )
      
      if operation.XOR:
        recursive_run_filters(
          filters_plan=operation.XOR,
          available_filters=available_filters,
          path=path+['XOR'],
          result_dict=result_dict,
        )
        
      if operation.NOT:
        recursive_run_filters(
          filters_plan=operation.NOT,
          available_filters=available_filters,
          path=path+['NOT'],
          result_dict=result_dict,
        )
    else:
      raise ValueError("operation has no valid condition or filter selected!")
        