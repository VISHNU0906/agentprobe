"""Adapter for an OpenAI-style chat endpoint, using only urllib.

It enforces the scope guard before every request, sets timeouts, and normalises
the response into a ``Response``. The same normalisation works for the mock
agent and for any endpoint that returns the standard chat completion shape.
"""

import json
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse

from .. import scope
from .base import Response, Target


class OpenAIChatAdapter(Target):
    kind = "openai"

    def __init__(self, base_url, authorized=False, scope_hosts=None, timeout=15):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        host = urlparse(base_url).hostname or ""
        scope.enforce(host, authorized=authorized, scope_hosts=scope_hosts or set())

    def _post(self, path, payload):
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _get(self, path):
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def chat(self, messages):
        raw = self._post("/v1/chat/completions", {"messages": messages})
        message = {}
        choices = raw.get("choices") or []
        if choices:
            message = choices[0].get("message", {})
        text = message.get("content", "")
        tool_calls = []
        for call in message.get("tool_calls") or []:
            fn = call.get("function", {})
            args = fn.get("arguments", "{}")
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except ValueError:
                    args = {"_raw": args}
            tool_calls.append(
                {
                    "name": fn.get("name"),
                    "arguments": args,
                    "status": call.get("status", "executed"),
                    "result": call.get("result", ""),
                }
            )
        return Response(text, tool_calls, raw)

    def tools_schema(self):
        return self._get("/v1/tools")
