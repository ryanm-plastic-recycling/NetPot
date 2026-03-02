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
