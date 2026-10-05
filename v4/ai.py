"""Server-only proxy for a private Timeweb AI Agent OpenAI-compatible endpoint."""
import json
import os
from typing import Iterable

import requests


class AIError(RuntimeError):
    pass


def _config():
    url = os.environ.get("TIMEWEB_AI_OPENAI_URL", "").strip()
    token = os.environ.get("TIMEWEB_AI_API_TOKEN", "").strip()
    if not url or not token:
        raise AIError("AI is not configured")
    if not url.startswith("https://"):
        raise AIError("AI endpoint must use HTTPS")
    # Timeweb UI may provide either the full completion URL or its OpenAI /v1 base.
    url = url.rstrip("/")
    if not url.endswith("/chat/completions"):
        url += "/chat/completions"
    return url, token


def configured():
    _config()


def validate_messages(messages):
    if not isinstance(messages, list) or not 1 <= len(messages) <= 20:
        raise AIError("invalid chat history")
    clean = []
    total = 0
    for message in messages:
        if not isinstance(message, dict) or message.get("role") not in {"user", "assistant"}:
            raise AIError("invalid chat message")
        content = message.get("content")
        if not isinstance(content, str) or not content.strip() or len(content) > 4000:
            raise AIError("invalid chat message")
        total += len(content)
        clean.append({"role": message["role"], "content": content.strip()})
    if total > 24000 or clean[-1]["role"] != "user":
        raise AIError("invalid chat history")
    return clean


def stream(messages) -> Iterable[str]:
    """Yield OpenAI-compatible SSE deltas; secrets never leave this module."""
    url, token = _config()
    body = {
        "model": os.environ.get("TIMEWEB_AI_MODEL", "agent"),
        "messages": validate_messages(messages),
        "stream": True,
    }
    try:
        response = requests.post(url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, json=body, stream=True, timeout=(10, 180))
        if response.status_code >= 400:
            raise AIError(f"AI upstream returned HTTP {response.status_code}")
        for raw_line in response.iter_lines(decode_unicode=False):
            line = raw_line.decode("utf-8", errors="replace") if isinstance(raw_line, bytes) else raw_line
            if not line or not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload == "[DONE]":
                return
            try:
                item = json.loads(payload)
                delta = item.get("choices", [{}])[0].get("delta", {}).get("content", "")
            except (IndexError, TypeError, json.JSONDecodeError):
                continue
            if isinstance(delta, str) and delta:
                yield delta
    except requests.RequestException as error:
        raise AIError(f"AI upstream is unavailable ({type(error).__name__})") from error
