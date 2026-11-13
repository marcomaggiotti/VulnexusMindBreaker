"""Connectors: how the engine talks to the application under test."""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import json
import socket
from typing import Any
from urllib.parse import urlparse

import httpx

from .demo_target import DemoBot
from .models import TargetConfig

Message = dict[str, str]  # {"role": "user" | "assistant", "content": "..."}


class ConnectorError(Exception):
    """The target could not be reached or returned something unusable."""


class Connector:
    async def send(self, messages: list[Message]) -> str:  # pragma: no cover - interface
        """Send the conversation so far (ending with a user turn); return the reply."""
        raise NotImplementedError

    async def aclose(self) -> None:
        return None


async def _refuse_link_local(url: str) -> None:
    """Block link-local destinations (cloud metadata services).

    Private ranges stay allowed: internal applications are legitimate targets.
    """
    host = urlparse(url).hostname or ""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ConnectorError(f"cannot resolve target host '{host}': {exc}") from exc
    for info in infos:
        address = ipaddress.ip_address(info[4][0].split("%")[0])
        if address.is_link_local:
            raise ConnectorError(f"target host '{host}' resolves to a link-local address; refused")


class _HttpConnector(Connector):
    def __init__(self, target: TargetConfig):
        self.target = target
        self._client = httpx.AsyncClient(timeout=target.timeout_seconds, headers=target.headers)
        self._checked = False

    async def _post(self, body: dict[str, Any]) -> httpx.Response:
        if not self._checked:
            await _refuse_link_local(self.target.endpoint or "")
            self._checked = True
        last: Exception | None = None
        for attempt in range(3):
            try:
                response = await self._client.post(self.target.endpoint or "", json=body)
            except httpx.HTTPError as exc:
                last = ConnectorError(f"request failed: {exc!r}")
            else:
                if response.status_code == 429 or response.status_code >= 500:
                    last = ConnectorError(f"target returned HTTP {response.status_code}")
                elif response.status_code >= 400:
                    raise ConnectorError(
                        f"target returned HTTP {response.status_code}: {response.text[:300]}"
                    )
                else:
                    return response
            await asyncio.sleep(1.5 * (attempt + 1))
        assert last is not None
        raise last

    async def aclose(self) -> None:
        await self._client.aclose()


class OpenAIChatConnector(_HttpConnector):
    """Any OpenAI-compatible chat completions endpoint (full URL)."""

    def __init__(self, target: TargetConfig, system_prompt: str | None):
        super().__init__(target)
        self.system_prompt = system_prompt

    async def send(self, messages: list[Message]) -> str:
        payload: list[Message] = []
        if self.system_prompt:
            payload.append({"role": "system", "content": self.system_prompt})
        payload += messages
        response = await self._post({"model": self.target.model, "messages": payload})
        try:
            content = response.json()["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ConnectorError(f"unexpected response shape: {response.text[:300]}") from exc
        return content or ""


def _substitute(node: Any, values: dict[str, str]) -> Any:
    if isinstance(node, str):
        for key, value in values.items():
            node = node.replace("{{" + key + "}}", value)
        return node
    if isinstance(node, list):
        return [_substitute(item, values) for item in node]
    if isinstance(node, dict):
        return {key: _substitute(value, values) for key, value in node.items()}
    return node


def _extract(data: Any, path: str) -> Any:
    for part in path.split("."):
        if isinstance(data, list):
            data = data[int(part)]
        else:
            data = data[part]
    return data


class HttpJsonConnector(_HttpConnector):
    """Black-box JSON API. Stateless: only the latest user turn is sent."""

    async def send(self, messages: list[Message]) -> str:
        values = {
            "prompt": messages[-1]["content"],
            "system_prompt": self.target.system_prompt or "",
        }
        body = _substitute(copy.deepcopy(self.target.request_template), values)
        response = await self._post(body)
        if not self.target.response_path:
            return response.text
        try:
            value = _extract(response.json(), self.target.response_path)
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ConnectorError(
                f"response_path '{self.target.response_path}' not found in: {response.text[:300]}"
            ) from exc
        return value if isinstance(value, str) else json.dumps(value)


class DemoConnector(Connector):
    def __init__(self, target: TargetConfig, system_prompt: str | None):
        self.bot = DemoBot(target.demo_profile, system_prompt or "", target.secrets)

    async def send(self, messages: list[Message]) -> str:
        return self.bot.reply([m["content"] for m in messages if m["role"] == "user"])


def build_connector(target: TargetConfig, system_prompt: str | None) -> Connector:
    """system_prompt is what the engine sends (already includes the canary)."""
    if target.connector == "demo":
        return DemoConnector(target, system_prompt)
    if target.connector == "openai_chat":
        return OpenAIChatConnector(target, system_prompt if target.send_system_prompt else None)
    return HttpJsonConnector(target)
