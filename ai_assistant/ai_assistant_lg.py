import json
import os

import falcon
import langchain_core
import langchain_core.messages
import langchain_core.runnables
import langfuse.callback

import components
import cnudie.retrieve
import eol
import features
import gci.componentmodel

import ai_assistant.langgraph_graph_simple
import middleware.auth

DEFAULT_API_VERSION = os.getenv('DEFAULT_API_VERSION')
MICROSOFT_AZURE_OPENAI_API_KEY = os.getenv('MICROSOFT_AZURE_OPENAI_API_KEY')
MICROSOFT_AZURE_OPENAI_API_ENDPOINT = os.getenv('MICROSOFT_AZURE_OPENAI_API_ENDPOINT')
OPEN_AI_MODEL = os.getenv('OPEN_AI_MODEL')


@middleware.auth.noauth
class AiAssistantChatLG:
    def __init__(
        self,
        component_descriptor_lookup: cnudie.retrieve.ComponentDescriptorLookupById,
        component_version_lookup: cnudie.retrieve.VersionLookupByComponent,
        github_api_lookup,
        eol_client: eol.EolClient,
        invalid_semver_ok: bool=False,
    ):
        self._component_descriptor_lookup = component_descriptor_lookup
        self._component_version_lookup = component_version_lookup
        self.github_api_lookup = github_api_lookup
        self._eol_client = eol_client
        self._invalid_semver_ok = invalid_semver_ok

    def on_post(self, req: falcon.Request, resp: falcon.Response):
        '''
        responds with chat message to question

        **expected request body:**
            - question: <str> \n
            - oldMessages: <array> of <object> \n
                - origin: <str> \n
                - messageText: <str> \n
            - rootComponentIdentity: <str> \n
            - currentComponentIdentity: <str> | None \n
            - threadId: <int> \n
        '''

        def generate_response():
            body = req.media
            old_messages: list[langchain_core.messages.MessageLikeRepresentation] = body.get('oldMessages')
            question: str = body.get('question')
            root_component_identity_str: str = body.get('rootComponentIdentity')
            current_component_identity_str: str = body.get('currentComponentIdentity')
            thread_id: int = body.get('threadId')

            root_component_identity = gci.componentmodel.ComponentIdentity(
                name=root_component_identity_str.split(':')[0],
                version=root_component_identity_str.split(':')[1],
            )

            current_component_identity = gci.componentmodel.ComponentIdentity(
                name=current_component_identity_str.split(':')[0],
                version=current_component_identity_str.split(':')[1],
            )

            ai_graph = ai_assistant.langgraph_graph_simple.create_custom_graph(
                component_descriptor_lookup=self._component_descriptor_lookup,
                component_version_lookup=self._component_version_lookup,
                github_api_lookup=self.github_api_lookup,
                root_component_identity=root_component_identity,
                invalid_semver_ok=self._invalid_semver_ok,
                eol_client=self._eol_client,
                db_session=req.context.db_session,
            )

            langfuse_handler = langfuse.callback.CallbackHandler()

            runnable_config = langchain_core.runnables.RunnableConfig(
                configurable={
                    'thread_id': thread_id,
                },
                callbacks=[langfuse_handler],
            )

            for state in ai_graph.stream(
                input={
                    'old_chat': old_messages,
                    'question': question,
                    'messages': [],
                    'answer': '',
                    'current_plan': ai_assistant.langgraph_graph_simple.Plan(steps=None),
                    'next_step': 'Creating a step by step Plan.',
                    'end': False,
                },
                config=runnable_config,
                stream_mode='values',
            ):
                yield f'''data: {
                    json.dumps({
                        'nextStep': state.get('next_step'),
                        'step': 0,
                        'end': state.get('end'),
                        'answer': state['answer'],
                        'plan': state['current_plan'].dict(),
                    })
                }\n\n'''.encode('utf-8')


        resp.content_type = 'text/event-stream'
        resp.cache_control = 'no-cache'
        resp.append_header('Connection', 'keep-alive')

        stream = generate_response()
        resp.stream = stream
