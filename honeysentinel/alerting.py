from __future__ import annotations

import asyncio
import json
import logging
import smtplib
import socket
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Any

import httpx

from honeysentinel.config import AlertsConfig
from honeysentinel.util import redact_mapping, utc_now_iso

_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
logger = logging.getLogger(__name__)


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

    def _top_context_fields(self, payload: dict[str, Any]) -> list[tuple[str, Any]]:
        context = payload.get("context", {})
        if not isinstance(context, dict):
            return []
        clean_context = redact_mapping(context)
        preferred = ["listener", "dst_port", "dest_port", "event_type", "proto", "source"]
        keys = [key for key in preferred if key in clean_context]
        keys.extend(sorted(k for k in clean_context if k not in keys))
        return [(key, clean_context[key]) for key in keys[:3]]

    def _format_email(self, payload: dict[str, Any]) -> EmailMessage:
        cfg = self.cfg.email
        listener = str(payload.get("context", {}).get("listener", "unknown"))
        subject = (
            f"[HoneySentinel][{str(payload['severity']).upper()}]"
            f"[{payload['rule']}] {payload['src_ip']} -> {listener}"
        )
        context = payload.get("context", {})
        to_override = context.get("to_override") if isinstance(context, dict) else None
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = cfg.from_addr
        msg["To"] = to_override if isinstance(to_override, str) and to_override else ", ".join(cfg.to_addrs)
        summary = str(payload.get("message", ""))[:240]
        top_fields = self._top_context_fields(payload)
        top_lines = "\n".join(f"- {key}: {value}" for key, value in top_fields) or "- (none)"
        body = (
            f"ts: {payload['ts']}\n"
            f"severity: {payload['severity']}\n"
            f"rule: {payload['rule']}\n"
            f"src_ip: {payload['src_ip']}\n"
            f"listener: {listener}\n"
            f"dst_port/listener: {payload.get('context', {}).get('dst_port', listener)}\n"
            f"summary: {summary}\n"
            "top_fields:\n"
            f"{top_lines}\n"
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

        try:
            await asyncio.to_thread(_send)
        except Exception:
            logger.warning("SMTP alert delivery failed", exc_info=True)

    def _twilio_message_body(self, payload: dict[str, Any]) -> str:
        listener = str(payload.get("context", {}).get("listener", "unknown"))
        headline = (
            f"HoneySentinel {str(payload['severity']).upper()} {payload['rule']} "
            f"from {payload['src_ip']} on {listener}."
        )
        return f"{headline}\nts={payload['ts']}"

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
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                context = payload.get("context", {})
                to_override = context.get("to_override") if isinstance(context, dict) else None
                to_numbers = [to_override] if isinstance(to_override, str) and to_override else cfg.to_numbers
                for to_number in to_numbers:
                    await client.post(
                        url,
                        data={"From": cfg.from_number, "To": to_number, "Body": body},
                        auth=(cfg.account_sid, cfg.auth_token),
                    )
        except Exception:
            logger.warning("Twilio alert delivery failed", exc_info=True)

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
