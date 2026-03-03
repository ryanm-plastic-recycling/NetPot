from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

from honeysentinel.alerting import Alert
from honeysentinel.app import AppState
from honeysentinel.config import AppConfig, NoiseConfig
from honeysentinel.events import Event


def _event(src_ip: str) -> Event:
    return Event(
        event_type="test",
        src_ip=src_ip,
        src_port=4444,
        dst_port=12222,
        listener="ssh-decoy",
        session_id="s",
        message="msg",
    )


def test_allowlisted_source_is_stored_but_suppresses_alerts(tmp_path) -> None:
    async def run() -> None:
        cfg = AppConfig(db_path=str(tmp_path / "honeysentinel.db"), noise=NoiseConfig(allowlist=["198.51.100.0/24"]))
        state = AppState(cfg)
        await state.db.connect()
        state.rules.evaluate = lambda event: [Alert("portscan", "high", event.src_ip, "detected")]
        state.alerter.send = AsyncMock()

        await state.handle_event(_event("198.51.100.10"))

        rows = await state.db.query_events({"src_ip": "198.51.100.10", "limit": 10})
        assert len(rows) == 1
        state.alerter.send.assert_not_called()
        await state.db.close()

    asyncio.run(run())


def test_non_allowlisted_source_still_alerts(tmp_path) -> None:
    async def run() -> None:
        cfg = AppConfig(db_path=str(tmp_path / "honeysentinel.db"), noise=NoiseConfig(allowlist=["192.0.2.10"]))
        state = AppState(cfg)
        await state.db.connect()
        state.rules.evaluate = lambda event: [Alert("portscan", "high", event.src_ip, "detected", context={})]
        state.alerter.send = AsyncMock()

        await state.handle_event(_event("203.0.113.5"))

        rows = await state.db.query_events({"src_ip": "203.0.113.5", "limit": 10})
        assert len(rows) == 1
        state.alerter.send.assert_called_once()
        sent_alert = state.alerter.send.call_args.args[0]
        assert sent_alert.context["dst_port"] == 12222
        assert sent_alert.context["src_port"] == 4444
        await state.db.close()

    asyncio.run(run())
