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


def _safe_text(value: Any, max_len: int = 500) -> str:
    text = str(value).replace("\n", " ").replace("\r", " ").strip()
    if len(text) > max_len:
        return f"{text[:max_len]}…"
    return text


def format_alert_human(alert: "Alert") -> tuple[str, str]:
    severity = str(alert.severity).upper()
    source = _safe_text(alert.src_ip, max_len=120) or "unknown"
    subject = f"[HoneySentinel][{severity}] {alert.rule} from {source}"

    clean_context = redact_mapping(alert.context if isinstance(alert.context, dict) else {})
    context_lines = "\n".join(
        f"  {key}: {_safe_text(value)}" for key, value in sorted(clean_context.items())
    ) or "  (none)"
    body = (
        "HoneySentinel Alert\n"
        f"Severity: {severity}\n"
        f"Rule: {_safe_text(alert.rule, max_len=200)}\n"
        f"Source: {source}\n"
        f"Time (UTC): {_safe_text(alert.ts, max_len=120)}\n"
        f"Message: {_safe_text(alert.message)}\n\n"
        "Context:\n"
        f"{context_lines}"
    )
    return subject, body


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
            self._send_email(alert, payload),
            self._send_twilio(alert, payload),
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

    def _format_email(self, alert: Alert, payload: dict[str, Any]) -> EmailMessage:
        cfg = self.cfg.email
        subject, body_text = format_alert_human(alert)
        raw_json = _safe_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), max_len=1500)
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = cfg.from_addr
        msg["To"] = ", ".join(cfg.to_addrs)
        body = (
            f"{body_text}\n\n"
            "Raw JSON (truncated):\n"
            f"{raw_json}"
        )
        msg.set_content(body)
        return msg

    async def _send_email(self, alert: Alert, payload: dict[str, Any]) -> None:
        cfg = self.cfg.email
        if not (cfg.enabled and cfg.smtp_host and cfg.to_addrs):
            return

        message = self._format_email(alert, payload)

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

    def _twilio_message_body(self, alert: Alert) -> str:
        _, body_text = format_alert_human(alert)
        compact = body_text.replace("\n\n", "\n")
        if len(compact) > 1400:
            return f"{compact[:1400]}…"
        return compact

    async def _send_twilio(self, alert: Alert, payload: dict[str, Any]) -> None:
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
        body = self._twilio_message_body(alert)
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                for to_number in cfg.to_numbers:
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
