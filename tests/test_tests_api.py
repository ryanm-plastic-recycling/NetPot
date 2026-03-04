from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

import honeysentinel.app as app_module


def _write_config(tmp_path: Path) -> Path:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        """
db_path: ./data/test.db
security:
  api_key: ""
listeners:
  tcp: []
  http:
    host: 127.0.0.1
    port: 18080
tests:
  enable_zap: false
  reports_dir: "./prove-risk/reports"
  request_timeout_seconds: 15
  zap_timeout_seconds: 300
""".strip()
    )
    return cfg


def test_api_tests_headers_returns_structured_json(tmp_path, monkeypatch) -> None:
    config_path = _write_config(tmp_path)

    async def _noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr(app_module.RawHttpListener, "start", _noop)
    monkeypatch.setattr(app_module.RawHttpListener, "stop", _noop)

    monkeypatch.setattr(
        app_module._HEADERS_CHECKS,
        "check_headers_for_url",
        lambda url, timeout: {
            "url": url,
            "status": "ok",
            "present": {"Strict-Transport-Security": True, "Content-Security-Policy": False},
            "values": {"Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": ""},
        },
    )

    app = app_module.create_app(str(config_path))
    with TestClient(app) as client:
        resp = client.post("/api/tests/headers", json={"url": "https://example.com"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["present"]["Strict-Transport-Security"] is True
    assert data["present"]["Content-Security-Policy"] is False


def test_api_tests_tls_returns_days_remaining(tmp_path, monkeypatch) -> None:
    config_path = _write_config(tmp_path)

    async def _noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr(app_module.RawHttpListener, "start", _noop)
    monkeypatch.setattr(app_module.RawHttpListener, "stop", _noop)

    monkeypatch.setattr(
        app_module._TLS_CHECKS,
        "check_tls_expiry_for_url",
        lambda url, timeout: {
            "url": url,
            "status": "ok",
            "host": "example.com",
            "port": 443,
            "expires_at_utc": "2030-01-01T00:00:00+00:00",
            "days_remaining": 365,
            "warning_threshold_days": 30,
            "critical_threshold_days": 7,
            "health": "ok",
        },
    )

    app = app_module.create_app(str(config_path))
    with TestClient(app) as client:
        resp = client.post("/api/tests/tls", json={"url": "https://example.com"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["days_remaining"] == 365
    assert data["warning_threshold_days"] == 30
