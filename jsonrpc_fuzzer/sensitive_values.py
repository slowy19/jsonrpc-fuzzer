import json
from typing import Any, Optional
from collections.abc import Mapping

SENSITIVE_KEYS = {
    "user", "cookie", "token", "access_token",
    "set-cookie", "authorization", "jwt",
    "password", "auth", "api_key", "api-key",
}

_SENSITIVE_VALUES: set[str] = set()


def _mask(value, key=None):
    if key is not None and str(key).lower() in SENSITIVE_KEYS:
        return "[REDACTED]"
    if isinstance(value, dict):
        return {k: _mask(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask(v) for v in value]
    if isinstance(value, str):
        s = value.lstrip()
        if s.startswith(("{", "[")):
            try:
                parsed = json.loads(value)
            except (ValueError, TypeError):
                return value
            if isinstance(parsed, (dict, list)):
                return json.dumps(_mask(parsed), ensure_ascii=False)
    return value


def mask_keys(obj: Any) -> Any:
    return _mask(obj)


def mask_response_text(text: Optional[str]) -> Any:
    if text is None:
        return None
    try:
        return mask_keys(json.loads(text))
    except Exception:
        return text


def register_sensitive_value(v: Any) -> None:
    if isinstance(v, str):
        _SENSITIVE_VALUES.add(v)


def _mask_str(text: Optional[str]) -> Optional[str]:
    if not text:
        return text
    for v in _SENSITIVE_VALUES:
        text = text.replace(v, "[REDACTED]")
    return text

def mask_value(value: Optional[Any]) -> Optional[Any]:
    if not value:
        return value

    if isinstance(value, str):
        return _mask_str(value)
    if isinstance(value, Mapping):
        return {k: mask_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [mask_value(v) for v in value]

    return value


def try_json(text):
    if not isinstance(text, str):
        return text
    try:
        return json.loads(text)
    except Exception:
        return text