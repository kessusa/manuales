# -*- coding: utf-8 -*-
"""
LLM connector for the corporate PromptGate gateway (OpenAI compatible).

Same pattern as the other API_cnx connectors: one class, connection_args,
methods that return the API payload (dict / str) or None on failure.

    from API_cnx.llm_api import LlmApi

    llm = LlmApi()
    answer = llm.ask('Classify this WAF event ...', system='You are a WAF analyst')
    message = llm.chat(messages, model='reasoner', tools=schemas)
"""
import json
import logging

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

# Qwen on PromptGate: only 'minimal' disables thinking ('none' returns 422)
NO_THINK = 'minimal'


class LlmApi:

    def __init__(self):
        self.base_url = settings.LLM_API_URL.rstrip('/')
        self.models = settings.LLM_MODELS
        self.connection_args = {
            'headers': {
                'Authorization': f'Bearer {settings.LLM_API_KEY}',
                'Content-Type': 'application/json',
            },
            'verify': getattr(settings, 'LLM_VERIFY_SSL', True),
            'timeout': getattr(settings, 'LLM_TIMEOUT', 60),
        }

    def get_model(self, model):
        return self.models.get(model, model)

    def list_models(self):
        try:
            response = requests.get(f'{self.base_url}/models', **self.connection_args)
            response.raise_for_status()
            return [item['id'] for item in response.json().get('data', [])]
        except (requests.RequestException, ValueError, KeyError) as error:
            logger.error(f'LLM list_models error: {error}')
            return None

    def chat(self, messages, model='default', tools=None, temperature=0,
             max_tokens=None, reasoning_effort=None, json_mode=False, extra=None):
        """
        Returns the assistant message dict:
        {'role': 'assistant', 'content': ..., 'tool_calls': [...]} or None.
        Tool call arguments are returned already parsed (dict).
        """
        params = {
            'model': self.get_model(model),
            'messages': messages,
            'temperature': temperature,
        }
        if max_tokens:
            params['max_tokens'] = max_tokens
        if tools:
            params['tools'] = tools
            params['tool_choice'] = 'auto'
        if reasoning_effort:
            params['reasoning_effort'] = reasoning_effort
        if json_mode:
            params['response_format'] = {'type': 'json_object'}
        if extra:
            params.update(extra)

        self.connection_args['json'] = params
        try:
            response = requests.post(f'{self.base_url}/chat/completions', **self.connection_args)
        except requests.RequestException as error:
            logger.error(f'LLM chat request error: {error}')
            return None
        finally:
            self.connection_args.pop('json', None)

        if response.status_code != 200:
            logger.error(f'LLM chat HTTP {response.status_code}: {response.text[:300]}')
            return None

        try:
            data = response.json()
            usage = data.get('usage', {})
            logger.info(
                f"LLM chat model={params['model']} "
                f"prompt_tokens={usage.get('prompt_tokens')} "
                f"completion_tokens={usage.get('completion_tokens')}"
            )
            message = data['choices'][0]['message']
        except (ValueError, KeyError, IndexError) as error:
            logger.error(f'LLM chat invalid response: {error}')
            return None

        message['content'] = message.get('content') or ''
        for tool_call in message.get('tool_calls') or []:
            arguments = tool_call['function'].get('arguments') or '{}'
            if isinstance(arguments, str):
                try:
                    tool_call['function']['arguments'] = json.loads(arguments)
                except ValueError:
                    logger.error(f'LLM tool call with invalid arguments: {arguments[:200]}')
                    return None
        return message

    def ask(self, prompt, system=None, model='default', **kwargs):
        """Single turn helper. Returns the answer text or None."""
        messages = []
        if system:
            messages.append({'role': 'system', 'content': system})
        messages.append({'role': 'user', 'content': prompt})
        message = self.chat(messages, model=model, **kwargs)
        return message['content'] if message else None

    def ask_json(self, prompt, system=None, model='default', **kwargs):
        """Single turn helper that expects a JSON answer. Returns dict/list or None."""
        content = self.ask(prompt, system=system, model=model, json_mode=True, **kwargs)
        if content is None:
            return None
        content = content.strip()
        if content.startswith('```'):
            content = content.strip('`')
            if content.lower().startswith('json'):
                content = content[4:]
        try:
            return json.loads(content)
        except ValueError:
            logger.error(f'LLM ask_json invalid JSON: {content[:200]}')
            return None

    @staticmethod
    def tool_result_message(tool_call_id, result):
        """Message to send a tool result back to the model."""
        content = result if isinstance(result, str) else json.dumps(result, default=str)
        return {'role': 'tool', 'tool_call_id': tool_call_id, 'content': content}

    @staticmethod
    def assistant_message(message):
        """Serialize a chat() message so it can be appended to the history."""
        history_message = {'role': 'assistant', 'content': message['content'] or None}
        if message.get('tool_calls'):
            history_message['tool_calls'] = [
                {
                    'id': tool_call['id'],
                    'type': 'function',
                    'function': {
                        'name': tool_call['function']['name'],
                        'arguments': json.dumps(tool_call['function']['arguments']),
                    },
                }
                for tool_call in message['tool_calls']
            ]
        return history_message
