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

    @staticmethod
    def _top_context_fields_from_context(clean_context: dict[str, Any]) -> list[tuple[str, Any]]:
        preferred = ["listener", "dst_port", "dest_port", "event_type", "proto", "source"]
        keys = [key for key in preferred if key in clean_context]
        keys.extend(sorted(k for k in clean_context if k not in keys))
        return [(key, clean_context[key]) for key in keys[:3]]

    def _format_email(self, alert: Alert, payload: dict[str, Any]) -> EmailMessage:
        cfg = self.cfg.email
        clean_context = redact_mapping(alert.context if isinstance(alert.context, dict) else {})
        listener = _safe_text(clean_context.get("listener", "unknown"), max_len=120) or "unknown"
        dst_port = clean_context.get("dst_port", 0)
        try:
            dst_port = int(dst_port)
        except (TypeError, ValueError):
            dst_port = 0
        top_fields = [name for name, _ in self._top_context_fields_from_context(clean_context)]
        severity_upper = _safe_text(str(alert.severity).upper(), max_len=16)
        severity_lower = _safe_text(str(alert.severity).lower(), max_len=16)
        rule = _safe_text(alert.rule, max_len=200)
        source = _safe_text(alert.src_ip, max_len=120) or "unknown"

        msg = EmailMessage()
        msg["Subject"] = f"[HoneySentinel][{severity_upper}][{rule}] {source} -> {listener}"
        msg["From"] = cfg.from_addr
        msg["To"] = ", ".join(cfg.to_addrs)
        msg.set_content(
            "\n".join(
                [
                    f"ts: {_safe_text(alert.ts, max_len=120)}",
                    f"severity: {severity_lower}",
                    f"rule: {rule}",
                    f"src_ip: {source}",
                    f"dst_port/listener: {dst_port}",
                    f"message: {_safe_text(alert.message)}",
                    f"top_fields: {top_fields}",
                ]
            )
        )
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
        severity = _safe_text(str(alert.severity).upper(), max_len=16)
        rule = _safe_text(alert.rule, max_len=64)
        src_ip = _safe_text(alert.src_ip, max_len=120) or "unknown"
        listener = _safe_text(alert.context.get("listener", "unknown"), max_len=64)
        return f"HoneySentinel {severity} {rule} from {src_ip} on {listener}. ts={_safe_text(alert.ts, max_len=120)}"

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
