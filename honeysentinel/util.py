from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key"}
SENSITIVE_KEYS = {"password", "passwd", "token", "secret", "apikey", "api_key"}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def preview_bytes(data: bytes, max_len: int) -> str:
    return safe_decode(data[:max_len])


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADERS:
            cleaned[key] = "[REDACTED]"
        else:
            cleaned[key] = value[:512]
    return cleaned


def _is_sensitive_key(key: str) -> bool:
    lk = key.lower()
    return lk in SENSITIVE_KEYS or any(part in lk for part in ("pass", "token", "secret"))


def redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in data.items():
        if _is_sensitive_key(key):
            out[key] = "[REDACTED]"
        elif isinstance(value, dict):
            out[key] = redact_mapping(value)
        else:
            out[key] = value
    return out


def redact_body(content_type: str, body: bytes, preview_bytes_len: int = 256) -> dict[str, Any]:
    body = body[:4096]
    preview = safe_decode(body[:preview_bytes_len])
    redacted_preview = preview
    if "json" in content_type:
        try:
            parsed = json.loads(preview)
            if isinstance(parsed, dict):
                redacted_preview = json.dumps(redact_mapping(parsed))
        except json.JSONDecodeError:
            pass
    elif "x-www-form-urlencoded" in content_type:
        redacted_preview = re.sub(
            r"(?i)(password|passwd|token|secret|api[_-]?key)=([^&\s]+)",
            r"\1=[REDACTED]",
            preview,
        )
    return {
        "content_type": content_type,
        "body_len": len(body),
        "sha256": sha256_hex(body),
        "preview": redacted_preview,
    }


def redact_telnet_password(_: str) -> str:
    return "[REDACTED]"
