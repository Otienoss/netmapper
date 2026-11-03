"""Log ve dışa giden job payload'ları için merkezi hassas veri maskeleme."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

REDACTED = "[REDACTED]"

_SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "pass", "token", "secret", "authorization",
    "hash", "hashes", "nt_hash", "lm_hash", "credential", "credentials",
    "ticket", "ccache",
}
_AUTH_RE = re.compile(
    r"(?i)(authorization\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]+")
_KV_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|api[_-]?token|secret|hash|nt_hash|lm_hash)"
    r"\b(\s*[:=]\s*)([^\s,;]+)"
)
_KRB_HASH_RE = re.compile(r"(?i)\$krb5[a-z0-9$*@._/+=:-]+")
_NTLM_PAIR_RE = re.compile(
    r"(?i)(?<![0-9a-f])[0-9a-f]{32}:[0-9a-f]{32}(?![0-9a-f])"
)


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return (
        normalized in _SENSITIVE_KEYS
        or normalized.endswith("_password")
        or normalized.endswith("_token")
        or normalized.endswith("_secret")
        or normalized.endswith("_hash")
    )


def collect_secret_values(payload: Any) -> list[str]:
    """Yalnızca hassas anahtarların metin değerlerini toplar (maskeleme için)."""
    found: list[str] = []

    def _walk(value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                name = str(child_key)
                if _is_sensitive_key(name) and isinstance(child, str) and child:
                    found.append(child)
                _walk(child, name)
        elif isinstance(value, (list, tuple)):
            for child in value:
                _walk(child, key)

    _walk(payload)
    return found


def sanitize_text(text: str, secrets: Iterable[str] = ()) -> str:
    """Bilinen sırları ve yaygın token/hash/parola kalıplarını maskeler."""
    result = str(text)
    known = {
        value for value in secrets
        if isinstance(value, str) and len(value) >= 4
    }
    # Uzun değer önce: parçalı değerin tam sırrı ezmesi engellenir.
    for secret in sorted(known, key=len, reverse=True):
        result = result.replace(secret, REDACTED)
    result = _AUTH_RE.sub(lambda m: m.group(1) + REDACTED, result)
    result = _BEARER_RE.sub("Bearer " + REDACTED, result)
    result = _KRB_HASH_RE.sub(REDACTED, result)
    result = _NTLM_PAIR_RE.sub(REDACTED, result)
    return _KV_RE.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", result
    )


def sanitize_payload(value: Any, secrets: Iterable[str] = ()) -> Any:
    """Nested dict/list payload'ı kopyalayarak hassas alanları maskeler."""
    if isinstance(value, dict):
        return {
            key: (
                REDACTED if _is_sensitive_key(str(key))
                else sanitize_payload(child, secrets)
            )
            for key, child in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [sanitize_payload(child, secrets) for child in value]
    if isinstance(value, str):
        return sanitize_text(value, secrets)
    return value
