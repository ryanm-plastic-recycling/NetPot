from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from honeysentinel.util import utc_now_iso


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
    id: int | None = None
