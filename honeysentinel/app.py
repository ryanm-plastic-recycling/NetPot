from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from honeysentinel.alerting import Alerter
from honeysentinel.config import AppConfig, load_config
from honeysentinel.db import Database
from honeysentinel.events import Event
from honeysentinel.ingest import JsonLineTailer, parse_suricata_eve_line, parse_zeek_conn_line
from honeysentinel.listeners.http import RawHttpListener
from honeysentinel.listeners.tcp import TcpListener
from honeysentinel.rules import RuleEngine


class AppState:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.db = Database(config.db_path)
        self.rules = RuleEngine(config.rules)
        self.alerter = Alerter(config.alerts)
        self.listeners: list[TcpListener | RawHttpListener] = []
        self.ingest_tasks: list[asyncio.Task[None]] = []
        self.ingestors: list[JsonLineTailer] = []

    async def handle_event(self, event: Event) -> None:
        event_id = await self.db.insert_event(event)
        for alert in self.rules.evaluate(event):
            alert.context.setdefault("listener", event.listener)
            alert.context.setdefault("event_id", event_id)
            await self.alerter.send(alert)


def create_app(config_path: str = "config.yaml") -> FastAPI:
    cfg = load_config(config_path)
    state = AppState(cfg)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await state.db.connect()
        for tcp_cfg in cfg.tcp_listeners:
            listener = TcpListener(tcp_cfg, cfg.privacy, state.handle_event)
            await listener.start()
            state.listeners.append(listener)
        raw_http = RawHttpListener(cfg.http_listener, state.handle_event)
        await raw_http.start()
        state.listeners.append(raw_http)

        if cfg.ingest.suricata.enabled:
            suricata_tailer = JsonLineTailer(
                source_key="suricata",
                path_getter=lambda: Path(cfg.ingest.suricata.eve_path),
                parser=parse_suricata_eve_line,
                get_state=state.db.get_ingest_state,
                set_state=state.db.set_ingest_state,
                handle_event=state.handle_event,
                max_line_bytes=cfg.ingest.suricata.max_line_bytes,
            )
            state.ingestors.append(suricata_tailer)
            state.ingest_tasks.append(asyncio.create_task(suricata_tailer.run()))

        if cfg.ingest.zeek.enabled:
            def _zeek_path() -> Path | None:
                primary = Path(cfg.ingest.zeek.log_dir) / "conn.log"
                fallback = Path(cfg.ingest.zeek.fallback_log_dir) / "conn.log"
                if primary.exists():
                    return primary
                if fallback.exists():
                    return fallback
                return None

            zeek_tailer = JsonLineTailer(
                source_key="zeek_conn",
                path_getter=_zeek_path,
                parser=parse_zeek_conn_line,
                get_state=state.db.get_ingest_state,
                set_state=state.db.set_ingest_state,
                handle_event=state.handle_event,
                max_line_bytes=cfg.ingest.zeek.max_line_bytes,
            )
            state.ingestors.append(zeek_tailer)
            state.ingest_tasks.append(asyncio.create_task(zeek_tailer.run()))
        try:
            yield
        finally:
            for ingestor in state.ingestors:
                await ingestor.stop()
            await asyncio.gather(*state.ingest_tasks, return_exceptions=True)
            await asyncio.gather(
                *(listener.stop() for listener in state.listeners),
                return_exceptions=True,
            )
            await state.db.close()

    app = FastAPI(title="HoneySentinel", lifespan=lifespan)
    app.state.hs = state

    async def require_api_key(
        request: Request, x_api_key: str = Header(default="")
    ) -> None:
        key = request.app.state.hs.config.security.api_key
        if key and key != x_api_key:
            raise HTTPException(status_code=401, detail="Unauthorized")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    async def dashboard() -> str:
        return (
            "<html><body><h1>HoneySentinel</h1>"
            "<p>Use /api/events and /api/info for JSON output.</p>"
            "</body></html>"
        )

    @app.get("/api/info", dependencies=[Depends(require_api_key)])
    async def info() -> dict[str, Any]:
        return {
            "db_path": str(Path(cfg.db_path).resolve()),
            "tcp_listeners": [asdict(listener) for listener in cfg.tcp_listeners],
            "http_listener": asdict(cfg.http_listener),
            "privacy": asdict(cfg.privacy),
            "ingest": asdict(cfg.ingest),
        }

    @app.get("/api/events", dependencies=[Depends(require_api_key)])
    async def events(
        limit: int = Query(100, ge=1, le=500),
        offset: int = Query(0, ge=0),
        since_ts: str | None = None,
        src_ip: str | None = None,
        event_type: str | None = None,
        listener: str | None = None,
        event_id: int | None = Query(default=None, ge=1),
    ) -> dict[str, Any]:
        rows = await state.db.query_events(
            {
                "limit": limit,
                "offset": offset,
                "since_ts": since_ts,
                "src_ip": src_ip,
                "event_type": event_type,
                "listener": listener,
                "event_id": event_id,
            }
        )
        return {"items": rows, "count": len(rows)}

    return app
