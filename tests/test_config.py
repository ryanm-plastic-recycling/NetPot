from pathlib import Path

from honeysentinel.config import load_config


def test_load_example_config() -> None:
    cfg = load_config(Path("config.example.yaml"))
    assert cfg.privacy.store_tcp_payload_preview is False
    assert cfg.http_listener.port >= 1024
    assert all(listener.port >= 1024 for listener in cfg.tcp_listeners)
    assert cfg.alerts.email.enabled is False
    assert cfg.alerts.twilio.enabled is False
    assert cfg.ingest.suricata.enabled is False
    assert cfg.ingest.zeek.enabled is False
    assert any(listener.mode == "rdp" and listener.port == 33890 for listener in cfg.tcp_listeners)


def test_load_config_expands_env_vars(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SMTP_USERNAME", "smtp-user")
    monkeypatch.setenv("SMTP_PASSWORD", "smtp-pass")
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "ACENV")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "twilio-token")
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
alerts:
  email:
    enabled: true
    smtp_host: smtp.example.com
    username: "${SMTP_USERNAME}"
    password: "${SMTP_PASSWORD}"
  twilio:
    enabled: true
    account_sid: "${TWILIO_ACCOUNT_SID}"
    auth_token: "${TWILIO_AUTH_TOKEN}"
listeners:
  http:
    port: 18080
""",
        encoding="utf-8",
    )

    cfg = load_config(config_path)

    assert cfg.alerts.email.username == "smtp-user"
    assert cfg.alerts.email.password == "smtp-pass"
    assert cfg.alerts.twilio.account_sid == "ACENV"
    assert cfg.alerts.twilio.auth_token == "twilio-token"
