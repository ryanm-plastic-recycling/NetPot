from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import aiosqlite

from honeysentinel.events import Event


class Database:
    def __init__(self, path: str) -> None:
        self.path = path
        self.conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = await aiosqlite.connect(self.path)
        await self.conn.execute("PRAGMA journal_mode=WAL")
        await self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                event_type TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL,
                listener TEXT NOT NULL,
                session_id TEXT NOT NULL,
                message TEXT NOT NULL,
                data_json TEXT NOT NULL
            )
            """
        )
        for idx in ("ts", "src_ip", "listener", "event_type"):
            await self.conn.execute(f"CREATE INDEX IF NOT EXISTS idx_events_{idx} ON events ({idx})")
        await self.conn.commit()

    async def close(self) -> None:
        if self.conn is not None:
            await self.conn.close()

    async def insert_event(self, event: Event) -> int:
        assert self.conn is not None
        cursor = await self.conn.execute(
            """
            INSERT INTO events (ts,event_type,src_ip,src_port,dst_port,listener,session_id,message,data_json)
            VALUES (?,?,?,?,?,?,?,?,?)
            """,
            (
                event.ts,
                event.event_type,
                event.src_ip,
                event.src_port,
                event.dst_port,
                event.listener,
                event.session_id,
                event.message,
                json.dumps(event.data, separators=(",", ":")),
            ),
        )
        await self.conn.commit()
        return int(cursor.lastrowid)

    async def query_events(self, filters: dict[str, Any]) -> list[dict[str, Any]]:
        assert self.conn is not None
        sql = (
            "SELECT id,ts,event_type,src_ip,src_port,dst_port,listener,session_id,message,data_json "
            "FROM events WHERE 1=1"
        )
        params: list[Any] = []
        if since_ts := filters.get("since_ts"):
            sql += " AND ts >= ?"
            params.append(since_ts)
        for key in ("src_ip", "event_type", "listener"):
            if value := filters.get(key):
                sql += f" AND {key} = ?"
                params.append(value)
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([int(filters.get("limit", 100)), int(filters.get("offset", 0))])
        rows = await self.conn.execute_fetchall(sql, params)
        events: list[dict[str, Any]] = []
        for row in rows:
            events.append(
                {
                    "id": row[0],
                    "ts": row[1],
                    "event_type": row[2],
                    "src_ip": row[3],
                    "src_port": row[4],
                    "dst_port": row[5],
                    "listener": row[6],
                    "session_id": row[7],
                    "message": row[8],
                    "data": json.loads(row[9]),
                }
            )
        return events
