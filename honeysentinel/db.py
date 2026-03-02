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
        await self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ingest_state (
                source_key TEXT PRIMARY KEY,
                inode INTEGER NOT NULL,
                offset INTEGER NOT NULL
            )
            """
        )
        for idx in ("ts", "src_ip", "listener", "event_type"):
            await self.conn.execute(f"CREATE INDEX IF NOT EXISTS idx_events_{idx} ON events ({idx})")
        await self.conn.commit()

    async def close(self) -> None:
        if self.conn:
            await self.conn.close()

    async def insert_event(self, event: Event) -> int:
        if not self.conn:
            raise RuntimeError("database not connected")
        cur = await self.conn.execute(
            """
            INSERT INTO events (ts, event_type, src_ip, src_port, dst_port, listener, session_id, message, data_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                json.dumps(event.data, ensure_ascii=False),
            ),
        )
        await self.conn.commit()
        return int(cur.lastrowid)

    async def get_ingest_state(self, source_key: str) -> tuple[int, int] | None:
        if not self.conn:
            raise RuntimeError("database not connected")
        row = await (
            await self.conn.execute(
                "SELECT inode, offset FROM ingest_state WHERE source_key = ?", (source_key,)
            )
        ).fetchone()
        if row is None:
            return None
        return int(row[0]), int(row[1])

    async def set_ingest_state(self, source_key: str, inode: int, offset: int) -> None:
        if not self.conn:
            raise RuntimeError("database not connected")
        await self.conn.execute(
            """
            INSERT INTO ingest_state (source_key, inode, offset)
            VALUES (?, ?, ?)
            ON CONFLICT(source_key) DO UPDATE SET inode = excluded.inode, offset = excluded.offset
            """,
            (source_key, inode, offset),
        )
        await self.conn.commit()

    async def query_events(self, filters: dict[str, Any]) -> list[dict[str, Any]]:
        if not self.conn:
            raise RuntimeError("database not connected")

        clauses: list[str] = []
        args: list[Any] = []

        if filters.get("since_ts"):
            clauses.append("ts >= ?")
            args.append(filters["since_ts"])
        if filters.get("src_ip"):
            clauses.append("src_ip = ?")
            args.append(filters["src_ip"])
        if filters.get("event_type"):
            clauses.append("event_type = ?")
            args.append(filters["event_type"])
        if filters.get("listener"):
            clauses.append("listener = ?")
            args.append(filters["listener"])
        if filters.get("event_id") is not None:
            clauses.append("id = ?")
            args.append(int(filters["event_id"]))

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        limit = int(filters.get("limit", 100))
        offset = int(filters.get("offset", 0))

        q = f"""
            SELECT id, ts, event_type, src_ip, src_port, dst_port, listener, session_id, message, data_json
            FROM events
            {where}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """
        args.extend([limit, offset])

        rows = await (await self.conn.execute(q, args)).fetchall()
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
