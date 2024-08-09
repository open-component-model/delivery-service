import asyncio
import datetime
import json
import os
import pprint
import re
import typing
import typing_extensions

import langgraph.checkpoint.sqlite
import langgraph.graph
import langgraph.graph.message
import langgraph.prebuilt
import langgraph.prebuilt.tool_node
import langgraph.utils
import langchain
import langchain.tools
import langchain_core.example_selectors
import langchain_core.messages
import langchain_core.messages.tool
import langchain_core.messages.ai
import langchain_core.messages.utils
import langchain_core.output_parsers
import langchain_core.prompts
import langchain_core.prompts.few_shot
import langchain_core.pydantic_v1
import langchain_core.runnables
import langchain_core.runnables.config
import langchain_core.tools
import langchain_chroma
import langchain_openai
import sqlalchemy.orm.session

import ai_assistant.ai_tools_new
import cnudie.retrieve
import components
import eol
import gci.componentmodel

import ai_assistant.ai_tools

OPEN_AI_MODEL = os.getenv('OPEN_AI_MODEL')

# #####
# State
# #####

class Step(langchain_core.pydantic_v1.BaseModel):
    description: str = langchain_core.pydantic_v1.Field(
        description='Description of the step and reason for him.'
    )
    tools_usage: list[str]= langchain_core.pydantic_v1.Field(
        description='List of tool names, which will be used within this step.'
    )

class Plan(langchain_core.pydantic_v1.BaseModel):
    steps: list[Step] | None = langchain_core.pydantic_v1.Field(
        description='List of steps, which have to be taken to answer the question.'
    )

class State(
    typing_extensions.TypedDict
):
    old_chat: list[langchain_core.messages.MessageLikeRepresentation]
    messages: typing.Annotated[
        list[langchain_core.messages.MessageLikeRepresentation],
        langgraph.graph.message.add_messages
    ]
    current_plan: Plan
    question: str
    answer: str
    next_step: str
    end: bool

# ######
# Agents
# ######


class PlanningAgent:
    def __init__(
        self,
        root_component_identity: gci.componentmodel.ComponentIdentity,
        ai_tools: ai_assistant.ai_tools_new.AiTools,
    ):

        self.json_parser = langchain_core.output_parsers.JsonOutputParser(pydantic_object=Plan)

        llm = langchain_openai.AzureChatOpenAI(
            model=OPEN_AI_MODEL,
            temperature=0.5,
        ).bind_tools(
            [
                *ai_tools.components(),
                *ai_tools.resources(),
                *ai_tools.vulnerabilities(),
            ],
            tool_choice='none',
        ).bind(
            response_format={"type": "json_object"}
        )
        
        examples = [
            {
                'question': 'Which versions of debian are used within this landscape?',
                'answer': '''{
                    "next_step": "Executing the plan step by step.",
                    "current_plan": {
                        "steps": [
                            {
                                "description": "Retrieve all packages used in the landscape to find out which versions of Debian are used.",
                                "tools_usage": [
                                    "functions.get_resources_by_os"
                                ]
                            },
                            {
                                "description": "",
                                "tools_usage": [
                                    "functions.get_resources_by_os"
                                ]
                            }
                        ]
                    }
                }'''.replace('{', '{{').replace('}', '}}'),
            },
            {
                'question': 'Which resources and components use the package openssh? Please output a table with the following fields: Component Name | Component Version | Artefact Name | Artefact Version | OpenSSH Versions',
                'answer': json.dumps({
                    "next_step": "Executing the plan step by step.",
                    "current_plan": {
                        "steps": [
                            {
                                "description": "Retrieve all resources that use the package openssh.",
                                "tools_usage": [
                                    "functions.get_resources_by_package"
                                ]
                            },
                            {
                                "description": "For each resource retrieved, get the components that use these resources.",
                                "tools_usage": [
                                    "functions.get_components_by_resource"
                                ]
                            },
                        ]
                    }
                }).replace('{', '{{').replace('}', '}}'),
            },
        ]
        
        example_selector = langchain_core.example_selectors.SemanticSimilarityExampleSelector.from_examples(
            # This is the list of examples available to select from.
            examples,
            # This is the embedding class used to produce embeddings which are used to measure semantic similarity.
            langchain_openai.AzureOpenAIEmbeddings(
                azure_endpoint=os.getenv('AZURE_OPENAI_EMBEDDING_ENDPOINT'),
                model=os.getenv('AZURE_OPENAI_EMBEDDING_MODEL'),
                api_key=os.getenv('AZURE_OPENAI_EMBEDDING_API_KEY'),
            ),
            # This is the VectorStore class that is used to store the embeddings and do a similarity search over.
            langchain_chroma.Chroma,
            # This is the number of examples to produce.
            k=1,
        )
        example_prompt_template = langchain_core.prompts.PromptTemplate(
            input_variables=["question", "answer"], template="Question: {question}\n{answer}"
        )
        self.few_shot_examples = langchain_core.prompts.few_shot.FewShotPromptTemplate(
            example_selector=example_selector,
            example_prompt=example_prompt_template,
            suffix="Question: {input}",
            input_variables=["input"],
        )

        chat_template = [
            (
                'system',
                '<your_role>\n'
                'You are an agent with the task to is to create a precise and brief plan to help another'
                ' agent answer the users question about the Landscape.\n'
                '</your_role>\n'
                ' \n'
                '<genetal_knowledge> \n'
                '# OCM Knowledge\n'
                ' OCM is an open standard designed to describe Software Bills of Delivery (SBOD) in'
                ' a technology-agnostic and machine-readable format. Your primary role is to assist'
                ' users by providing information and answering questions about OCM, including its'
                ' components, structure, and usage. Here is a comprehensive overview of the core'
                ' concepts and elements of OCM:\n'
                '## Overview of OCM:\n'
                '### Purpose:\n'
                '- OCM provides a standard to describe and manage software artifacts that must be'
                ' delivered for software products. It assigns globally unique identities to these'
                ' artifacts and makes them queryable for details like content, origin, and'
                ' authenticity.\n'
                '### Core Concepts:\n'
                '- Component Model: Represents software artifacts as components, which can be'
                ' versioned and uniquely identified. Components contain various artifacts necessary'
                ' for software delivery.\n'
                '- Component Versions: Each version of a component encapsulates a specific state'
                ' of the software artifacts.\n'
                '- Artifacts (Resources and Sources): Resources are the actual files or binaries,'
                ' while sources include the origin or the metadata associated with these'
                ' resources.\n'
                '- Repositories: OCM defines repositories to store and retrieve components and'
                ' their versions, supporting different types like OCI (Open Container Initiative)'
                ' and CTF (Common Transport Format).\n'
                '- Package: external Code Package, which was used in the development of a Resource.'
                ' (e.g. openssh)\n'
                '\n'
                '# Delivery Gear Infos\n'
                '- Delivery Gear is an application, which offers multiple services with the help of OCM.\n'
                '- It Scanns the Resources of the OCM Components of a Landscape for: \n'
                '  - Malware\n'
                '  - Vulnerabilities\n'
                '  - Licenses\n'
                '  - Structural infos (on which external Packages does a Resource Depend on)\n'
                '- It creates and manages these findings. Therefor it supports the following actions:\n'
                '  - Rescore the severity of a finding (Malware / Vulnerability / License)\n'
                '  - It creates Github issues for findings\n'
                '</general_knowledge> \n'
                ' \n'
                '<landscape_information>\n'
                ' <landscape_root_component_name>{root_component_name}</landscape_root_component_name>\n'
                ' <landscape_root_component_version>{root_component_version}</landscape_root_component_version>\n'
                '</landscape_information>\n'
                '\n'
                '<general_information>\n'
                '   <current_date>\n{current_date}\n</current_date>\n'
                '</general_information>\n'
                '\n'
                '<return_format_instructions_for_output>\n'
                '   <JSON>\n{format_instructions}\n</JSON>\n'
                '</return_format_instructions_for_output>\n'
                '\n'
                '<examples>\n'
                '{examples}\n'
                '</examples>\n'
            ),
            (
                'placeholder',
                '{old_chat}'
            ),
            (
                'human',
                '<question>'
                '{question}'
                '</question>'
            ),
        ]

        assistant_prompt = langchain_core.prompts.ChatPromptTemplate.from_messages(
            chat_template
        ).partial(
            root_component_name=root_component_identity.name,
            root_component_version=root_component_identity.version,
            current_date=datetime.datetime.now().strftime("%Y-%m-%d"),
            format_instructions=self.json_parser.get_format_instructions(),
        )

        planning_chain = (
            assistant_prompt
            | llm
            | self.json_parser
        )

        self.runnable = planning_chain

    def __call__(
        self,
        state: State
    ) -> State:
        
        print(self.few_shot_examples.format(input=state['question']))
        plan: Plan = Plan(
            **self.runnable.invoke({
                'question': state['question'],
                'old_chat': state['old_chat'],
                'examples': self.few_shot_examples.format(input=state['question']),
            })
        )

        return {
            'current_plan': plan,
            'next_step': 'Executing the plan step by step.',
        }


class ExecutionAgent:
    def __init__(

        self,
        root_component_identity: gci.componentmodel.ComponentIdentity,
        ai_tools: ai_assistant.ai_tools_new.AiTools,
    ):
        llm = langchain_openai.AzureChatOpenAI(
            model=OPEN_AI_MODEL,
            streaming=True,
        ).bind_tools(
            [
                *ai_tools.components(),
                *ai_tools.resources(),
                *ai_tools.vulnerabilities(),
            ]
        )

        assistant_prompt = langchain_core.prompts.ChatPromptTemplate.from_messages(
            [
                (
                    'system',
                    'You are the Plan Executioner. Execute the following plan to solve the question:\n'
                    ' <plan>{current_plan}</plan>\n'
                    '\n'
                    'This plan was created by the Planning Agent for the question:\n'
                    ' <question>{question}</question>\n'
                    '\n'
                    'Currently selected root component:\n'
                    ' <root_component_name>{root_component_name}</root_component_name>\n'
                    ' <root_component_version>{root_component_version}</root_component_version>\n'
                    ''
                    'Respond only if you can execute the plan correctly; otherwise, acknowledge uncertainty.'
                ),
                (
                    'placeholder',
                    '{messages}'
                ),
                (
                    'human',
                    'Answer the question by executing the not already taken steps of the plan using your tools.'
                    ' Once executed, provide a precise answer to the user\'s question, including all important information.'
                    ' Do not include explanations of your steps in the answer.'
                    '\n\n'
                    '# Return Format:'
                    '- Answer in valid Markdown'
                    '- Use tables if applicable.'
                    '- End your answer with a table outlining the steps taken and tools used.'
                    '\n'
                    '| Step | Action | Tool Used |\n|------|--------|-----------|\n'
                )
            ]
        ).partial(
            root_component_name=root_component_identity.name,
            root_component_version=root_component_identity.version,
        )

        executor_chain = (
            assistant_prompt
            | llm
        )

        self.runnable = executor_chain

    def __call__(self, state: State) -> State:
        llm_message = self.runnable.invoke({
            'current_plan': state["current_plan"].dict(),
            'question': state['question'],
            'messages': state['messages'],
        })
        if llm_message.content == '':
            tool_calls = [
                f'{tool_call['function']['name']} with args: {json.dumps(tool_call['function']['arguments'])}\n'
                for tool_call
                in llm_message.additional_kwargs['tool_calls']
            ]
            next_step = f'''
                calling tool(s):\n 
                {
                   tool_calls 
                }
            '''
        else:
            next_step = 'Summarizing'

        return {
            'messages': [llm_message],
            'next_step': next_step,
        }


# #####
# Nodes
# #####

def handle_tool_error(state) -> dict:
    error = state.get('error')
    tool_calls = state['messages'][-1].tool_calls
    return {
        'messages':[
            langchain_core.messages.ToolMessage(
                content=f'Error: {repr(error)}\n please fix your mistakes.',
                tool_call_id=tc['id'],
            )
            for tc in tool_calls
        ]
    }


def create_tool_node_with_fallback(
        tools: list[langchain.tools.BaseTool]
) -> langchain_core.runnables.RunnableWithFallbacks:
    return ToolNode(tools).with_fallbacks(
        [langchain_core.runnables.RunnableLambda(handle_tool_error)], exception_key="error"
    )


class ToolNode(langgraph.utils.RunnableCallable):
    '''
    A node that runs the tools requested in the last AIMessage. It can be used
    either in StateGraph with a "messages" key or in MessageGraph. If multiple
    tool calls are requested, they will be run in parallel. The output will be
    a list of ToolMessages, one for each tool call.
    '''

    def __init__(
        self,
        tools: typing.Sequence[typing.Union[langchain.tools.BaseTool, typing.Callable]],
        *,
        name: str = 'tools',
        tags: typing.Optional[list[str]] = None,
    ) -> None:
        super().__init__(self._func, self._afunc, name=name, tags=tags, trace=False)
        self.tools_by_name: typing.Dict[str, langchain.tools.BaseTool] = {}
        for tool_ in tools:
            if not isinstance(tool_, langchain.tools.BaseTool):
                tool_ = langchain_core.tools.tool(tool_)
            self.tools_by_name[tool_.name] = tool_

    def _func(
        self, state: State, config: langchain_core.runnables.RunnableConfig
    ) -> typing.Any:

        if messages := state.get('messages', []):
            output_type = 'dict'
            last_message = messages[-1]
        else:
            raise ValueError('No message found in input')

        if not isinstance(last_message, langchain_core.messages.ai.AIMessage):
            raise ValueError('Last message is not an AIMessage')

        def run_one(call:  langchain_core.messages.tool.ToolCall):
            output = self.tools_by_name[call['name']].invoke(call['args'], config)
            return  langchain_core.messages.tool.ToolMessage(
                content=langgraph.prebuilt.tool_node.str_output(output),
                name=call['name'],
                tool_call_id=call['id'],
            )

        with langchain_core.runnables.config.get_executor_for_config(config) as executor:
            outputs = [*executor.map(run_one, last_message.tool_calls)]
            if output_type == 'list':
                return outputs
            return {
                'messages': outputs,
                'next_step': 'Executing the plan step by step.'
            }

    async def _afunc(
        self, state: State, config: langchain_core.runnables.RunnableConfig
    ) -> typing.Any:

        if messages := state.get('messages', []):
            output_type = 'dict'
            last_message = messages[-1]
        else:
            raise ValueError('No message found in input')

        if not isinstance(last_message, langchain_core.messages.ai.AIMessage):
            raise ValueError('Last message is not an AIMessage')

        async def run_one(call: langchain_core.messages.tool.ToolCall):
            output = await self.tools_by_name[call['name']].ainvoke(
                call['args'], config
            )
            return langchain_core.messages.tool.ToolMessage(
                content=langgraph.prebuilt.tool_node.str_output(output),
                name=call['name'],
                tool_call_id=call['id'],
            )

        outputs = await asyncio.gather(*(run_one(call) for call in last_message.tool_calls))
        if output_type == 'list':
            return outputs
        return {'messages': outputs}

class EndNode:
    def __call__(
        self,
        state: State
    ):
        print('EndNode')
        return {
            'answer': state['messages'][-1].content,
            'end': True,
        }



# #####
# Edges
# #####

def tool_router(state: State) -> typing.Literal['tools', 'end_node']:
    '''
    Use in the conditional_edge to route to the ToolNode if the last Message has tool calls,
    otherwise, routes back to the __end__.
    '''
    if messages := state.get('messages', []):
        last_message = messages[-1]
    else:
        raise ValueError(f'No messages found in input state to tool edge: {state}')

    if hasattr(last_message, "tool_calls") and len(last_message.tool_calls) > 0:
        print(f'\n -> tools\n')
        return 'tools'

    print('\n -> end_node \n')
    return 'end_node'


# #####
# Graph
# #####

def create_custom_graph(
    component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
    component_version_lookup: cnudie.retrieve.VersionLookupByComponent,
    github_api_lookup,
    root_component_identity: gci.componentmodel.ComponentIdentity,
    db_session: sqlalchemy.orm.session.Session,
    eol_client: eol.EolClient,
    invalid_semver_ok: bool = False,
):

    ai_tools = ai_assistant.ai_tools_new.AiTools(
        root_component_id=root_component_identity,
        component_version_lookup=component_version_lookup,
        component_descriptor_lookup=component_descriptor_lookup,
        db_session=db_session, 
        invalid_semver_ok=invalid_semver_ok,
    )

    builder = langgraph.graph.StateGraph(State)

    builder.add_node(
        'planning_agent',
        PlanningAgent(
            root_component_identity=root_component_identity,
            ai_tools=ai_tools,
        )
    )

    builder.add_node('execution_agent', ExecutionAgent(
        root_component_identity=root_component_identity,
        ai_tools=ai_tools,
    ))

    builder.add_node("tools", create_tool_node_with_fallback(
        [
            *ai_tools.components(),
            *ai_tools.resources(),
            *ai_tools.vulnerabilities(),
        ]
    ))
    
    builder.add_node('end_node', EndNode())

    builder.set_entry_point('planning_agent')
    builder.set_finish_point('end_node')

    builder.add_edge(
        'planning_agent',
        'execution_agent'
    )

    builder.add_conditional_edges(
        'execution_agent',
        tool_router,
    )

    builder.add_edge(
        'tools',
        'execution_agent',
    )

    #memory = langgraph.checkpoint.sqlite.SqliteSaver.from_conn_string("checkpoints.sqlite")
    memory = langgraph.checkpoint.sqlite.SqliteSaver.from_conn_string(":memory:")

    graph = builder.compile(checkpointer=memory)
    print('==========Graph Created==========')
    print(graph.get_graph().draw_mermaid())
    print('=================================')
    return graph
