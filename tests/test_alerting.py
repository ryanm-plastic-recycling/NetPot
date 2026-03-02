from __future__ import annotations

from email.message import EmailMessage
from unittest.mock import AsyncMock, patch

import pytest

from honeysentinel.alerting import Alert, Alerter
from honeysentinel.config import AlertEmailConfig, AlertsConfig, AlertTwilioConfig


def test_email_formatting_contains_required_fields() -> None:
    cfg = AlertsConfig(
        email=AlertEmailConfig(
            enabled=True,
            from_addr="hs@example.org",
            to_addrs=["soc@example.org"],
        )
    )
    alerter = Alerter(cfg)
    msg = alerter._format_email(
        {
            "severity": "high",
            "rule": "portscan",
            "src_ip": "1.2.3.4",
            "message": "detected",
            "context": {"listener": "ssh-decoy", "event_id": 7},
        }
    )
    assert isinstance(msg, EmailMessage)
    body = msg.get_content()
    assert "Severity: high" in body
    assert "Rule: portscan" in body
    assert "Source IP: 1.2.3.4" in body
    assert "Listener: ssh-decoy" in body
    assert "/api/events?event_id=7" in body


@pytest.mark.asyncio
async def test_send_email_uses_smtp_without_auth_if_empty_creds() -> None:
    cfg = AlertsConfig(
        email=AlertEmailConfig(
            enabled=True,
            smtp_host="smtp.example.org",
            smtp_port=25,
            username="",
            password="",
            from_addr="hs@example.org",
            to_addrs=["soc@example.org"],
        )
    )
    alerter = Alerter(cfg)
    with patch("honeysentinel.alerting.smtplib.SMTP") as smtp_cls:
        smtp = smtp_cls.return_value.__enter__.return_value
        await alerter.send(Alert("rule", "high", "1.1.1.1", "message"))
        smtp.send_message.assert_called_once()
        smtp.login.assert_not_called()


@pytest.mark.asyncio
async def test_twilio_message_formatting_and_threshold() -> None:
    cfg = AlertsConfig(
        twilio=AlertTwilioConfig(
            enabled=True,
            account_sid="AC123",
            auth_token="token",
            from_number="+15551230000",
            to_numbers=["+15551230001"],
            min_severity="high",
        )
    )
    alerter = Alerter(cfg)
    with patch("honeysentinel.alerting.httpx.AsyncClient") as client_cls:
        client = client_cls.return_value.__aenter__.return_value
        client.post = AsyncMock()

        await alerter.send(Alert("burst", "medium", "5.5.5.5", "noise", context={"listener": "tcp"}))
        client.post.assert_not_called()

        await alerter.send(Alert("portscan", "high", "5.5.5.5", "scan", context={"listener": "tcp"}))
        client.post.assert_called_once()
        kwargs = client.post.call_args.kwargs
        assert "Messages.json" in client.post.call_args.args[0]
        assert "HoneySentinel HIGH: portscan from 5.5.5.5 on tcp." == kwargs["data"]["Body"]
