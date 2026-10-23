"""Sanitize recorded API responses before they become fixtures, and check that no secret-like value is left.

Sensitive keys and secret-like strings become "REDACTED". A key is sensitive when its normalized name contains a
credential word (key, token, secret, password, passwd, auth, cookie, session, credential, email) or equals one of
a few identity names (user, org_id, project_id, request_id, ip, host, ...). Values are secret-like when they hold
an email, bearer token, key prefix, JWT, AWS key id, URL with credentials, secret query parameter, base64 or long
key-like run, or a local home path. Dict key names are scanned too, so a secret used as a key is replaced as well.
Response ids such as "chatcmpl-..." become "REDACTED" too.

Kept as they are: model ids (org/name), usage counters (prompt_tokens and friends), non-secret content text,
finish reasons, and null or empty values, which carry no secret. Key names compare case-insensitively with "-"
read as "_".
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from typing import Any

REDACTED = "REDACTED"
# Path element used in assert_clean errors in place of a key name that is itself secret-like.
SECRET_KEY_LABEL = "<secret-key>"

# A normalized key is sensitive when it contains one of these words, or equals one of SENSITIVE_NAMES.
SENSITIVE_SUBSTRINGS = (
    "key",
    "token",
    "secret",
    "password",
    "passwd",
    "auth",
    "cookie",
    "session",
    "credential",
    "email",
)
SENSITIVE_NAMES = frozenset(
    {
        "user",
        "user_id",
        "account_id",
        "org_id",
        "organization",
        "project_id",
        "tenant",
        "workspace",
        "request_id",
        "trace_id",
        "ip",
        "host",
    }
)
# Usage counters such as prompt_tokens or completion_tokens_details hold numbers, not secrets.
COUNTER_SUFFIXES = ("_tokens", "tokens_details")

# Keys whose string value may be a model id such as "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B".
MODEL_KEYS = frozenset({"id", "model", "root"})
MODEL_ID = re.compile(r"[A-Za-z0-9_.\-]+/[A-Za-z0-9_.:\-]+")
# Model-shaped values that start with these are local paths, not model ids.
PATH_PREFIXES = ("home/", "Users/")

EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
BEARER = re.compile(r"\bbearer\s+\S+", re.IGNORECASE)
KEY_PREFIX = re.compile(r"\b(?:sk|nvapi|ghp|gho|tvly|xox[abprs])[-_][A-Za-z0-9_\-]{8,}")
JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
AWS_KEY_ID = re.compile(r"AKIA[0-9A-Z]{16}")
URL_CREDENTIALS = re.compile(r"://[^/\s:@]+:[^@\s]+@")
QUERY_SECRET = re.compile(r"[?&](?:token|key|api_key|access_token|sig|signature)=", re.IGNORECASE)
LOCAL_PATH = re.compile(r"/Users/|/home/|[A-Za-z]:\\", re.IGNORECASE)
LONG_TOKEN = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")
# Base64 runs. Only runs holding +, / or a trailing = count here; pure alphanumeric runs are LONG_TOKEN.
BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")

_ALWAYS_SECRET = (EMAIL, BEARER, KEY_PREFIX, JWT, AWS_KEY_ID, URL_CREDENTIALS, QUERY_SECRET, LOCAL_PATH)


def _norm(key: str) -> str:
    return key.lower().replace("-", "_")


def _key_name(key: Any) -> str:
    if not isinstance(key, str):
        raise TypeError(f"JSON object keys must be str, not {type(key).__name__}")
    return key


def _always_secret(text: str) -> bool:
    return any(pattern.search(text) for pattern in _ALWAYS_SECRET)


def _long_run(text: str) -> bool:
    if LONG_TOKEN.search(text):
        return True
    return any(any(ch in "+/=" for ch in run.group()) for run in BASE64_RUN.finditer(text))


def _secret_string(key: str | None, value: str) -> bool:
    """True when a string value must be redacted. `key` is the normalized key it sits under, if any."""
    if value == REDACTED:
        return False
    if _always_secret(value):
        return True
    if key in MODEL_KEYS and MODEL_ID.fullmatch(value):
        return value.startswith(PATH_PREFIXES)
    if key == "id":
        return True  # response ids such as chatcmpl-... are not kept
    return _long_run(value)


def _secret_key(name: str) -> bool:
    """Dict key names are scanned like model-id values, because map keys such as price tables hold model ids."""
    return _secret_string("model", name)


def _is_empty(value: Any) -> bool:
    """Null and empty values carry no secret, so they are kept as they are."""
    return value is None or (isinstance(value, (str, list, dict)) and not value)


def _is_counter(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, dict):
        return all(item is None or _is_counter(item) for item in value.values())
    return False


def _sensitive(name: str, value: Any) -> bool:
    """True when the whole value under a normalized key must be replaced by REDACTED."""
    if _is_empty(value):
        return False
    if name not in SENSITIVE_NAMES and not any(part in name for part in SENSITIVE_SUBSTRINGS):
        return False
    return not (name.endswith(COUNTER_SUFFIXES) and _is_counter(value))


def _unique_key(taken: dict[str, Any], base: str) -> str:
    candidate, n = base, 1
    while candidate in taken:
        n += 1
        candidate = f"{base}_{n}"
    return candidate


def _clean(key: str | None, value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for raw_key, item in value.items():
            name = _key_name(raw_key)
            norm = _norm(name)
            safe = REDACTED if _secret_key(name) else name
            out[_unique_key(out, safe)] = REDACTED if _sensitive(norm, item) else _clean(norm, item)
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
            if _secret_key(name):
                yield (*path, SECRET_KEY_LABEL)  # the secret key text itself is never reported
                continue
            norm = _norm(name)
            here = (*path, name)
            if _sensitive(norm, item):
                if item != REDACTED:
                    yield here
            else:
                yield from _leaks(norm, item, here)
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
    """Raise ValueError if any secret-like value or key remains. The message names key paths, never values."""
    leaks = list(_leaks(None, obj, ()))
    if leaks:
        where = "; ".join("/".join(path) or "<root>" for path in leaks[:10])
        raise ValueError(f"secret-like values remain at: {where}")


MAX_QUERY_CHARS = 300  # a web search query (sent and traced) is cut to this
TAVILY_KEY_ENV = "TAVILY_API_KEY"
_MIN_SECRET_CHARS = 4  # a shorter configured secret is not matched verbatim: it would shred ordinary text
_PRECAP_CHARS = 64_000  # bounds the whole-string passes; far above any limit * 4 the callers use
# `password=hunter2`, `api_key: abc`, `token=...`: a name with a credential word, a separator and a value. The value is
# a whole word, so a space-separated secret after `password =` is still caught by the word pass only if secret-like.
SECRET_ASSIGNMENT = re.compile(
    r"[\w.\-]*(?:password|passwd|secret|token|api[_\-]?key|key|auth)[\w.\-]*\s*[=:]\s*\S+", re.IGNORECASE
)


def clean_text(text: str, limit: int, secrets: tuple[str, ...] = ()) -> str:
    """Free text as one line of at most limit chars. For a web search query or a result snippet, where replacing the
    whole string would lose it.

    The whole string comes first: the TAVILY_API_KEY value (read from the environment here, never stored or printed)
    and every value in secrets are replaced verbatim, then `Bearer <token>` and `name=value` credential patterns. Then
    the text is cut at limit * 4, split into words, and each word is checked on its own (a secret-like word becomes
    REDACTED and the words around it stay). The result is cut at limit."""
    text = text[:_PRECAP_CHARS]
    for value in (*secrets, os.environ.get(TAVILY_KEY_ENV, "")):
        if len(value) >= _MIN_SECRET_CHARS:
            text = text.replace(value, REDACTED)
    text = BEARER.sub(REDACTED, text)
    text = SECRET_ASSIGNMENT.sub(REDACTED, text)
    words = text[: max(limit, 0) * 4].split()
    return " ".join(sanitize(word) for word in words)[: max(limit, 0)]
