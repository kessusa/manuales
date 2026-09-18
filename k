# -*- coding: utf-8 -*-
"""
LLM gateway connector (OpenAI compatible API).

    llm = LlmApi()
    llm.ask('question')                          -> str or None
    llm.ask_json('question')                     -> dict / list or None
    llm.chat(messages, tools=...)                -> message dict or None
    llm.run_tools(messages, tools, handlers)     -> final message dict or None

Every method returns the payload or None, the error is always logged.
Gateway errors (429 / 502 / 503 / 504, timeouts) are retried here, so the
use cases never implement their own retry logic.
"""
import json
import logging
import time

import requests
import urllib3

from bookmark.settings import LLM_API_KEY, LLM_BASE_URL, LLM_MODELS, LLM_TIMEOUT, LLM_VERIFY

logger = logging.getLogger(__name__)

NO_THINK = 'minimal'
RETRY_STATUS = (429, 502, 503, 504)
MAX_RETRIES = 3
RETRY_WAIT = 10
JSON_RETRIES = 2
JSON_FEEDBACK = 'Your previous answer was not valid JSON. Return ONLY the JSON, no markdown.'
MAX_AGENT_STEPS = 8
TOOL_RESULT_TRUNC = 4000

if not LLM_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class LlmApi:

    def __init__(self):
        self.base_url = LLM_BASE_URL.rstrip('/')
        self.models = LLM_MODELS
        self.session = requests.Session()
        self.connection_args = {
            'headers': {
                'Authorization': f'Bearer {LLM_API_KEY}',
                'Content-Type': 'application/json',
            },
            'verify': LLM_VERIFY,
            'timeout': LLM_TIMEOUT,
        }

    def get_model(self, model):
        return self.models.get(model, model)

    def list_models(self):
        try:
            response = self.session.get(f'{self.base_url}/models', **self.connection_args)
            response.raise_for_status()
            return [item['id'] for item in response.json().get('data', [])]
        except (requests.RequestException, ValueError, KeyError) as error:
            logger.error(f'LLM list_models error: {error}')
            return None

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------
    def post_chat(self, params, timeout=None, stream=False):
        """POST /chat/completions retrying gateway errors. Returns the 200 response or None."""
        # Copy per call: the instance is shared between threads
        request_args = dict(self.connection_args, json=params, stream=stream)
        if timeout:
            request_args['timeout'] = timeout

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                response = self.session.post(f'{self.base_url}/chat/completions', **request_args)
            except requests.RequestException as error:
                logger.error(f'LLM chat request error (attempt {attempt}/{MAX_RETRIES}): {error}')
            else:
                if response.status_code == 200:
                    return response
                logger.error(
                    f'LLM chat HTTP {response.status_code} (attempt {attempt}/{MAX_RETRIES}): {response.text[:300]}'
                )
                if response.status_code not in RETRY_STATUS:
                    return None
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_WAIT * attempt)
        return None

    @staticmethod
    def log_usage(model, usage):
        usage = usage or {}
        logger.info(
            f'LLM chat model={model} '
            f"prompt_tokens={usage.get('prompt_tokens')} "
            f"completion_tokens={usage.get('completion_tokens')}"
        )

    def consume_stream(self, response, model):
        """Join the SSE chunks into a regular message dict. Returns None on a broken stream."""
        content = []
        usage = {}
        try:
            for line in response.iter_lines(decode_unicode=True):
                if not line or not line.startswith('data:'):
                    continue
                data = line[len('data:'):].strip()
                if data == '[DONE]':
                    break
                chunk = json.loads(data)
                usage = chunk.get('usage') or usage
                for choice in chunk.get('choices') or []:
                    content.append((choice.get('delta') or {}).get('content') or '')
        except (requests.RequestException, ValueError) as error:
            logger.error(f'LLM chat stream error: {error}')
            return None
        self.log_usage(model, usage)
        return {'role': 'assistant', 'content': ''.join(content)}

    # ------------------------------------------------------------------
    # Chat
    # ------------------------------------------------------------------
    def chat(self, messages, model='default', tools=None, temperature=0, max_tokens=None,
             reasoning_effort=None, json_mode=False, timeout=None, stream=False, extra=None):
        """
        Returns the assistant message dict ({'content': str, 'tool_calls': [...]}) or None.
        Tool call arguments are returned already parsed (dict).
        timeout overrides LLM_TIMEOUT for this call: seconds or (connect, read).
        stream=True consumes the SSE response (long generations behind a gateway
        timeout); tool calls are not supported in streaming mode.
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
        if stream:
            params['stream'] = True
            params['stream_options'] = {'include_usage': True}
        if extra:
            params.update(extra)

        response = self.post_chat(params, timeout=timeout, stream=stream)
        if response is None:
            return None
        if stream:
            return self.consume_stream(response, params['model'])

        try:
            data = response.json()
            self.log_usage(params['model'], data.get('usage'))
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

    @staticmethod
    def build_messages(prompt, system=None):
        messages = [{'role': 'system', 'content': system}] if system else []
        messages.append({'role': 'user', 'content': prompt})
        return messages

    def ask(self, prompt, system=None, model='default', **kwargs):
        """Single turn helper. Returns the answer text or None."""
        message = self.chat(self.build_messages(prompt, system), model=model, **kwargs)
        return message['content'] if message else None

    @staticmethod
    def parse_json(content):
        """Parse a JSON answer, tolerating markdown fences and text around it. Returns None if invalid."""
        starts = [index for index in (content.find('{'), content.find('[')) if index != -1]
        end = max(content.rfind('}'), content.rfind(']'))
        if not starts or end == -1:
            return None
        try:
            return json.loads(content[min(starts):end + 1])
        except ValueError:
            return None

    def ask_json(self, prompt, system=None, model='default', **kwargs):
        """
        Single turn helper that expects a JSON answer. Returns dict / list or None.
        An invalid JSON answer is sent back to the model with feedback (JSON_RETRIES
        times). A failed call returns None right away: chat() already retried it.
        """
        messages = self.build_messages(prompt, system)
        for attempt in range(1, JSON_RETRIES + 2):
            message = self.chat(messages, model=model, **kwargs)
            if message is None:
                return None
            result = self.parse_json(message['content'])
            if result is not None:
                return result
            logger.error(f"LLM ask_json invalid JSON (attempt {attempt}): {message['content'][:200]}")
            messages.append({'role': 'assistant', 'content': message['content']})
            messages.append({'role': 'user', 'content': JSON_FEEDBACK})
        return None

    # ------------------------------------------------------------------
    # Agents
    # ------------------------------------------------------------------
    def run_tools(self, messages, tools, handlers, model='default', max_steps=MAX_AGENT_STEPS, **kwargs):
        """
        Agent loop: chat -> run the requested tools -> chat ... until the model answers.
        handlers = {tool_name: callable(**arguments)} is the allowlist: a tool without
        handler is never executed.
        The full history (tool calls and results) is appended to `messages` in place.
        Returns the final assistant message or None (failed call / max_steps reached).
        """
        for step in range(1, max_steps + 1):
            message = self.chat(messages, model=model, tools=tools, **kwargs)
            if message is None:
                return None
            messages.append(self.assistant_message(message))
            if not message.get('tool_calls'):
                return message

            for tool_call in message['tool_calls']:
                name = tool_call['function']['name']
                logger.info(f'LLM agent step={step} tool={name}')
                messages.append(self.tool_result_message(tool_call['id'], self.run_handler(handlers, tool_call)))

        logger.error(f'LLM agent stopped: max_steps={max_steps} reached')
        return None

    @staticmethod
    def run_handler(handlers, tool_call):
        """Run one tool. Errors go back to the model as the tool result, never raised."""
        name = tool_call['function']['name']
        handler = handlers.get(name)
        if handler is None:
            logger.error(f'LLM agent unknown tool: {name}')
            return {'error': f'Unknown tool: {name}'}
        try:
            return handler(**tool_call['function']['arguments'])
        except Exception as error:
            logger.error(f'LLM agent tool {name} error: {error}')
            return {'error': f'Tool {name} failed: {error}'}

    @staticmethod
    def tool_result_message(tool_call_id, result):
        content = result if isinstance(result, str) else json.dumps(result, default=str)
        return {'role': 'tool', 'tool_call_id': tool_call_id, 'content': content[:TOOL_RESULT_TRUNC]}

    @staticmethod
    def assistant_message(message):
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
