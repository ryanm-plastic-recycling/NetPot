from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from honeysentinel.events import Event
from honeysentinel.util import utc_now_iso

MAX_SLEEP = 0.5


def parse_suricata_eve_line(line: str) -> Event | None:
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None

    src_ip = str(payload.get("src_ip", ""))
    if not src_ip:
        return None

    signature = str(payload.get("alert", {}).get("signature", "")).strip()
    event_type = str(payload.get("event_type", "unknown"))
    msg = signature or f"Suricata {event_type} event"
    return Event(
        event_type="suricata_eve",
        src_ip=src_ip,
        src_port=int(payload.get("src_port", 0) or 0),
        dst_port=int(payload.get("dest_port", 0) or 0),
        listener="suricata",
        session_id=f"suricata-{payload.get('flow_id', 'n/a')}",
        message=msg,
        data={
            "event_type": event_type,
            "dest_ip": str(payload.get("dest_ip", "")),
            "proto": str(payload.get("proto", "")),
            "signature": signature,
        },
        ts=str(payload.get("timestamp") or utc_now_iso()),
    )


def parse_zeek_conn_line(line: str) -> Event | None:
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None

    src_ip = str(payload.get("id.orig_h", ""))
    if not src_ip:
        return None

    return Event(
        event_type="zeek_conn",
        src_ip=src_ip,
        src_port=int(payload.get("id.orig_p", 0) or 0),
        dst_port=int(payload.get("id.resp_p", 0) or 0),
        listener="zeek",
        session_id=f"zeek-{payload.get('uid', 'n/a')}",
        message=f"Zeek conn {payload.get('proto', 'unknown')} {payload.get('service', '-')}",
        data={
            "proto": str(payload.get("proto", "")),
            "service": str(payload.get("service", "")),
            "duration": payload.get("duration"),
            "orig_bytes": payload.get("orig_bytes"),
            "resp_bytes": payload.get("resp_bytes"),
            "ts": payload.get("ts"),
        },
        ts=utc_now_iso(),
    )


class JsonLineTailer:
    def __init__(
        self,
        source_key: str,
        path_getter: Callable[[], Path | None],
        parser: Callable[[str], Event | None],
        get_state: Callable[[str], asyncio.Future[tuple[int, int] | None] | Any],
        set_state: Callable[[str, int, int], asyncio.Future[None] | Any],
        handle_event: Callable[[Event], asyncio.Future[None] | Any],
        max_line_bytes: int,
    ) -> None:
        self.source_key = source_key
        self.path_getter = path_getter
        self.parser = parser
        self.get_state = get_state
        self.set_state = set_state
        self.handle_event = handle_event
        self.max_line_bytes = max_line_bytes
        self._stop = asyncio.Event()

    async def stop(self) -> None:
        self._stop.set()

    async def run(self) -> None:
        while not self._stop.is_set():
            path = self.path_getter()
            if path is None or not path.exists():
                await asyncio.sleep(MAX_SLEEP)
                continue

            stat = path.stat()
            inode = int(stat.st_ino)
            state = await self.get_state(self.source_key)
            offset = 0
            if state is not None:
                saved_inode, saved_offset = state
                if saved_inode == inode and saved_offset <= stat.st_size:
                    offset = saved_offset

            with path.open("rb") as handle:
                handle.seek(offset)
                while not self._stop.is_set():
                    pos = handle.tell()
                    line = handle.readline(self.max_line_bytes + 1)
                    if not line:
                        await self.set_state(self.source_key, inode, pos)
                        await asyncio.sleep(MAX_SLEEP)
                        current = path.stat()
                        if int(current.st_ino) != inode or current.st_size < pos:
                            break
                        continue

                    if len(line) > self.max_line_bytes:
                        await self.set_state(self.source_key, inode, handle.tell())
                        continue

                    try:
                        parsed = self.parser(line.decode("utf-8", errors="replace").strip())
                    except Exception:
                        parsed = None
                    if parsed is not None:
                        await self.handle_event(parsed)
                    await self.set_state(self.source_key, inode, handle.tell())
