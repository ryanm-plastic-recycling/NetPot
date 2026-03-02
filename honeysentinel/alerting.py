from __future__ import annotations

import asyncio
import json
import smtplib
import socket
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Any

import httpx

from honeysentinel.config import AlertsConfig
from honeysentinel.util import utc_now_iso

_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


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
            self._send_email(payload),
            self._send_twilio(payload),
            self._send_webhook(payload),
            self._send_syslog(payload),
            return_exceptions=True,
        )

    def _format_email(self, payload: dict[str, Any]) -> EmailMessage:
        cfg = self.cfg.email
        listener = str(payload.get("context", {}).get("listener", "unknown"))
        event_id = payload.get("context", {}).get("event_id")
        event_path = f"/api/events?event_id={event_id}" if event_id is not None else "/api/events"
        msg = EmailMessage()
        msg["Subject"] = f"HoneySentinel [{payload['severity']}] {payload['rule']}"
        msg["From"] = cfg.from_addr
        msg["To"] = ", ".join(cfg.to_addrs)
        body = (
            f"Severity: {payload['severity']}\n"
            f"Rule: {payload['rule']}\n"
            f"Source IP: {payload['src_ip']}\n"
            f"Listener: {listener}\n"
            f"Message: {payload['message']}\n"
            f"Dashboard event view: {event_path}\n"
        )
        msg.set_content(body)
        return msg

    async def _send_email(self, payload: dict[str, Any]) -> None:
        cfg = self.cfg.email
        if not (cfg.enabled and cfg.smtp_host and cfg.to_addrs):
            return

        message = self._format_email(payload)

        def _send() -> None:
            with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=5) as server:
                if cfg.use_starttls:
                    server.starttls()
                if cfg.username and cfg.password:
                    server.login(cfg.username, cfg.password)
                server.send_message(message)

        await asyncio.to_thread(_send)

    def _twilio_message_body(self, payload: dict[str, Any]) -> str:
        listener = str(payload.get("context", {}).get("listener", "unknown"))
        return (
            f"HoneySentinel {payload['severity'].upper()}: {payload['rule']} from "
            f"{payload['src_ip']} on {listener}."
        )

    async def _send_twilio(self, payload: dict[str, Any]) -> None:
        cfg = self.cfg.twilio
        if not (
            cfg.enabled
            and cfg.account_sid
            and cfg.auth_token
            and cfg.from_number
            and cfg.to_numbers
        ):
            return

        if _SEVERITY_ORDER.get(payload["severity"], 0) < _SEVERITY_ORDER.get(
            cfg.min_severity, _SEVERITY_ORDER["high"]
        ):
            return

        url = f"https://api.twilio.com/2010-04-01/Accounts/{cfg.account_sid}/Messages.json"
        body = self._twilio_message_body(payload)
        async with httpx.AsyncClient(timeout=5.0) as client:
            for to_number in cfg.to_numbers:
                await client.post(
                    url,
                    data={"From": cfg.from_number, "To": to_number, "Body": body},
                    auth=(cfg.account_sid, cfg.auth_token),
                )

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
