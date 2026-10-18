"""Sanitize recorded API responses before they become fixtures, and check that no secret-like value is left.

Sensitive keys and secret-like strings (emails, bearer tokens, key prefixes, long key-like tokens) become
"REDACTED". Response ids such as "chatcmpl-..." become "REDACTED" too. Model ids (org/name), usage numbers,
content text and finish reasons are kept. Key names compare case-insensitively with "-" read as "_".
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

REDACTED = "REDACTED"

SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "api_key",
        "apikey",
        "x_api_key",
        "token",
        "access_token",
        "refresh_token",
        "secret",
        "client_secret",
        "password",
        "cookie",
        "set_cookie",
        "private_key",
        "project_id",
        "organization",
        "org_id",
        "user",
        "email",
    }
)

# Keys whose string value may be a model id such as "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B".
MODEL_KEYS = frozenset({"id", "model", "root"})

MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\-]*/[A-Za-z0-9][A-Za-z0-9._\-]*")
EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
BEARER = re.compile(r"\bbearer\s+\S+", re.IGNORECASE)
KEY_PREFIX = re.compile(r"\b(?:sk|nvapi|ghp|gho|tvly|xox[abprs])[-_][A-Za-z0-9_\-]{8,}")
LONG_TOKEN = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")


def _norm(key: str) -> str:
    return key.lower().replace("-", "_")


def _key_name(key: Any) -> str:
    if not isinstance(key, str):
        raise TypeError(f"JSON object keys must be str, not {type(key).__name__}")
    return key


def _secret_string(key: str | None, value: str) -> bool:
    """True when a string value must be redacted. `key` is the normalized key it sits under, if any."""
    if value == REDACTED:
        return False
    if EMAIL.search(value) or BEARER.search(value) or KEY_PREFIX.search(value):
        return True
    if key in MODEL_KEYS and MODEL_ID.fullmatch(value):
        return False
    if key == "id":
        return True  # response ids such as chatcmpl-... are not kept
    return LONG_TOKEN.search(value) is not None


def _clean(key: str | None, value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for raw_key, item in value.items():
            name = _norm(_key_name(raw_key))
            out[raw_key] = REDACTED if name in SENSITIVE_KEYS else _clean(name, item)
        return out
    if isinstance(value, list):
        return [_clean(key, item) for item in value]
    if isinstance(value, str):
        return REDACTED if _secret_string(key, value) else value
    if value is None or isinstance(value, (bool, int, float)):
        return REDACTED if key == "id" and value is not None else value
    raise TypeError(f"not JSON-like: {type(value).__name__}")


def sanitize(obj: Any) -> Any:
    """Return a sanitized deep copy of a JSON-like structure. The input is never modified."""
    return _clean(None, obj)


def _leaks(key: str | None, value: Any, path: tuple[str, ...]) -> Iterator[tuple[str, ...]]:
    if isinstance(value, dict):
        for raw_key, item in value.items():
            name = _key_name(raw_key)
            here = (*path, name)
            if _norm(name) in SENSITIVE_KEYS:
                if item != REDACTED:
                    yield here
            else:
                yield from _leaks(_norm(name), item, here)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from _leaks(key, item, (*path, str(i)))
    elif isinstance(value, str):
        if _secret_string(key, value):
            yield path
    elif value is None or isinstance(value, (bool, int, float)):
        if key == "id" and value is not None:
            yield path
    else:
        raise TypeError(f"not JSON-like: {type(value).__name__}")


def assert_clean(obj: Any) -> None:
    """Raise ValueError if any secret-like value remains. The message names key paths, never values."""
    leaks = list(_leaks(None, obj, ()))
    if leaks:
        where = "; ".join("/".join(path) or "<root>" for path in leaks[:10])
        raise ValueError(f"secret-like values remain at: {where}")
