"""Optional remote AI providers. Keys stay in memory or Secret Service, never on disk."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from urllib.parse import urlsplit

class AiError(Exception):
    pass

PROVIDERS = {
    "openai": {"label": "OpenAI", "model": "gpt-4o-mini"},
    "anthropic": {"label": "Anthropic", "model": "claude-sonnet-4-5"},
    "gemini": {"label": "Google Gemini", "model": "gemini-2.5-flash"},
    "openai-compatible": {"label": "OpenAI-compatible HTTPS", "model": ""},
}


class SessionStore:
    """Process memory only. Closing Control Centre drops these keys."""

    def __init__(self) -> None:
        self._keys: dict[str, str] = {}

    def put(self, provider: str, key: str) -> None:
        if provider not in PROVIDERS:
            raise AiError("Unknown provider.")
        if not key.strip():
            raise AiError("Enter an API key first.")
        self._keys[provider] = key.strip()

    def get(self, provider: str) -> str:
        return self._keys.get(provider, "")

    def delete(self, provider: str) -> None:
        self._keys.pop(provider, None)

    def masked(self, provider: str) -> str:
        key = self.get(provider)
        if not key:
            return ""
        if len(key) < 8:
            return "••••"
        return f"{key[:3]}…{key[-2:]}"


def validate_https_endpoint(url: str) -> str:
    parts = urlsplit(url.strip())
    if parts.scheme != "https" or not parts.hostname:
        raise AiError("The endpoint must be an https URL with a hostname.")
    if parts.username or parts.password:
        raise AiError("The endpoint must not contain a username or password.")
    return url.strip().rstrip("/")


def _redact(text: str, key: str) -> str:
    if key and key in text:
        return text.replace(key, "[redacted]")
    return text


def _request(url: str, payload: dict, headers: dict, key: str, timeout: int = 30) -> dict:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:300]
        raise AiError(_redact(f"The provider returned HTTP {exc.code}: {body}", key)) from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise AiError(_redact(f"The provider could not be reached: {exc}", key)) from None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        raise AiError("The provider returned a response that was not JSON.") from None
    if not isinstance(parsed, dict):
        raise AiError("The provider returned an unexpected response.")
    return parsed


def complete(provider: str, model: str, key: str, prompt: str, endpoint: str = "", timeout: int = 30) -> str:
    if provider not in PROVIDERS:
        raise AiError("Unknown provider.")
    if not key.strip():
        raise AiError("No API key is saved for this session.")
    if not prompt.strip():
        raise AiError("Enter a message first.")
    if not model.strip():
        raise AiError("Enter a model name.")
    key = key.strip()
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if provider in {"openai", "openai-compatible"}:
        base = "https://api.openai.com/v1" if provider == "openai" else validate_https_endpoint(endpoint)
        headers["Authorization"] = f"Bearer {key}"
        payload = {"model": model.strip(), "messages": [{"role": "user", "content": prompt}]}
        parsed = _request(f"{base}/chat/completions", payload, headers, key, timeout)
        try:
            return str(parsed["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError):
            raise AiError("The provider response did not include a message.") from None
    if provider == "anthropic":
        headers["x-api-key"] = key
        headers["anthropic-version"] = "2023-06-01"
        payload = {"model": model.strip(), "max_tokens": 1024, "messages": [{"role": "user", "content": prompt}]}
        parsed = _request("https://api.anthropic.com/v1/messages", payload, headers, key, timeout)
        try:
            return str(parsed["content"][0]["text"])
        except (KeyError, IndexError, TypeError):
            raise AiError("The provider response did not include a message.") from None
    headers["x-goog-api-key"] = key
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model.strip()}:generateContent"
    parsed = _request(url, {"contents": [{"parts": [{"text": prompt}]}]}, headers, key, timeout)
    try:
        return str(parsed["candidates"][0]["content"]["parts"][0]["text"])
    except (KeyError, IndexError, TypeError):
        raise AiError("The provider response did not include a message.") from None


def secret_service_status() -> str:
    try:
        import secretstorage
    except ImportError:
        return "Secret Service library is not installed. Keys can be kept for this session only."
    try:
        bus = secretstorage.dbus_init()
        collection = secretstorage.get_default_collection(bus)
    except Exception:
        return "Secret Service is not available. Keys can be kept for this session only."
    try:
        if collection.is_locked():
            return "The keyring is locked. Unlock it in the desktop session before saving a key there."
    except Exception:
        return "Secret Service did not answer. Keys can be kept for this session only."
    return "Secret Service is available."


def save_to_secret_service(provider: str, key: str) -> None:
    import secretstorage
    bus = secretstorage.dbus_init()
    collection = secretstorage.get_default_collection(bus)
    if collection.is_locked():
        raise AiError("The keyring is locked, so the key was not saved.")
    attributes = {"application": "traceos", "provider": provider}
    for item in collection.search_items(attributes):
        item.delete()
    collection.create_item(f"TraceOS {provider}", attributes, key.encode("utf-8"), replace=False)


def load_from_secret_service(provider: str) -> str:
    import secretstorage
    bus = secretstorage.dbus_init()
    collection = secretstorage.get_default_collection(bus)
    if collection.is_locked():
        raise AiError("The keyring is locked.")
    for item in collection.search_items({"application": "traceos", "provider": provider}):
        secret = item.get_secret().decode("utf-8", errors="replace")
        if secret:
            return secret
    return ""


def delete_from_secret_service(provider: str) -> None:
    import secretstorage
    bus = secretstorage.dbus_init()
    collection = secretstorage.get_default_collection(bus)
    if collection.is_locked():
        raise AiError("The keyring is locked, so the saved key was not removed.")
    for item in collection.search_items({"application": "traceos", "provider": provider}):
        item.delete()
