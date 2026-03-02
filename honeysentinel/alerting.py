from __future__ import annotations

import asyncio
import json
import socket
from dataclasses import dataclass, field
from typing import Any

import httpx

from honeysentinel.config import AlertsConfig
from honeysentinel.util import utc_now_iso


@dataclass(slots=True)
class Alert:
    rule: str
    severity: str
    src_ip: str
    message: str
    context: dict[str, Any] = field(default_factory=dict)
    ts: str = field(default_factory=utc_now_iso)


class Alerter:
    def __init__(self, cfg: AlertsConfig) -> None:
        self.cfg = cfg

    async def send(self, alert: Alert) -> None:
        payload = {
            "ts": alert.ts,
            "rule": alert.rule,
            "severity": alert.severity,
            "src_ip": alert.src_ip,
            "message": alert.message,
            "context": alert.context,
        }
        await asyncio.gather(
            self._send_slack(payload),
            self._send_webhook(payload),
            self._send_syslog(payload),
            return_exceptions=True,
        )

    async def _send_slack(self, payload: dict[str, Any]) -> None:
        cfg = self.cfg.slack
        if not (cfg.enabled and cfg.webhook_url):
            return
        text = f"[{payload['severity']}] {payload['rule']} from {payload['src_ip']}: {payload['message']}"
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(cfg.webhook_url, json={"text": text})

    async def _send_webhook(self, payload: dict[str, Any]) -> None:
        cfg = self.cfg.webhook
        if not (cfg.enabled and cfg.url):
            return
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(cfg.url, json=payload)

    async def _send_syslog(self, payload: dict[str, Any]) -> None:
        cfg = self.cfg.syslog
        if not cfg.enabled:
            return
        data = json.dumps(payload).encode("utf-8")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(data, (cfg.host, cfg.port))
        finally:
            sock.close()
