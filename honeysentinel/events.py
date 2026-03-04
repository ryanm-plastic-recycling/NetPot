from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from honeysentinel.util import utc_now_iso


EVENT_DISPOSITIONS = (
    "OPEN",
    "TEST",
    "FALSE_POSITIVE",
    "KNOWN_SCANNER",
    "MALICIOUS",
    "UNKNOWN",
    "BENIGN",
    "NEEDS_REVIEW",
)


def normalize_disposition(value: str) -> str:
    return value.strip().upper().replace("-", "_")


@dataclass(slots=True)
class Event:
    event_type: str
    src_ip: str
    src_port: int
    dst_port: int
    listener: str
    session_id: str
    message: str
    data: dict[str, Any] = field(default_factory=dict)
    ts: str = field(default_factory=utc_now_iso)
    disposition: str = "OPEN"
    id: int | None = None
