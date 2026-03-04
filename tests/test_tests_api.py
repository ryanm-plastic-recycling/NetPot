from __future__ import annotations

import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

import honeysentinel.app as app_module


def _write_config(tmp_path: Path, *, enable_zap: bool = False) -> Path:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        f"""
db_path: {tmp_path / 'test.db'}
security:
  api_key: ""
listeners:
  tcp: []
  http:
    host: 127.0.0.1
    port: 18080
tests:
  enable_zap: {'true' if enable_zap else 'false'}
  reports_dir: "./prove-risk/reports"
  request_timeout_seconds: 15
  zap_timeout_seconds: 300
""".strip()
    )
    return cfg


def _seed_events(db_path: Path) -> None:
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            event_type TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            src_port INTEGER NOT NULL,
            dst_port INTEGER NOT NULL,
            listener TEXT NOT NULL,
            session_id TEXT NOT NULL,
            message TEXT NOT NULL,
            data_json TEXT NOT NULL,
            disposition TEXT NOT NULL DEFAULT 'OPEN'
        )
        """
    )
    conn.execute(
        "INSERT INTO events (ts,event_type,src_ip,src_port,dst_port,listener,session_id,message,data_json,disposition) VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("2025-01-01T00:00:00Z", "tcp_connect", "10.0.0.1", 1, 2, "l", "s1", "m1", "{}", "OPEN"),
    )
    conn.execute(
        "INSERT INTO events (ts,event_type,src_ip,src_port,dst_port,listener,session_id,message,data_json,disposition) VALUES (?,?,?,?,?,?,?,?,?,?)",
        ("2025-01-01T00:00:01Z", "tcp_connect", "10.0.0.2", 1, 2, "l", "s2", "m2", "{}", "MALICIOUS"),
    )
    conn.commit()
    conn.close()


def _build_client(tmp_path: Path, monkeypatch, *, enable_zap: bool = False) -> TestClient:
    config_path = _write_config(tmp_path, enable_zap=enable_zap)

    async def _noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr(app_module.RawHttpListener, "start", _noop)
    monkeypatch.setattr(app_module.RawHttpListener, "stop", _noop)

    app = app_module.create_app(str(config_path))
    return TestClient(app)


def test_events_default_open_filter_and_multi_filter(tmp_path, monkeypatch) -> None:
    _seed_events(tmp_path / "test.db")
    with _build_client(tmp_path, monkeypatch) as client:
        resp_default = client.get("/api/events")
        assert resp_default.status_code == 200
        items_default = resp_default.json()["items"]
        assert len(items_default) == 1
        assert items_default[0]["disposition"] == "OPEN"

        resp_multi = client.get("/api/events?disposition=OPEN,MALICIOUS")
        assert resp_multi.status_code == 200
        assert {x["disposition"] for x in resp_multi.json()["items"]} == {"OPEN", "MALICIOUS"}

        resp_all = client.get("/api/events?include_all=true")
        assert resp_all.status_code == 200
        assert len(resp_all.json()["items"]) == 2


def test_patch_event_disposition_validation(tmp_path, monkeypatch) -> None:
    _seed_events(tmp_path / "test.db")
    with _build_client(tmp_path, monkeypatch) as client:
        bad = client.patch("/api/events/1", json={"disposition": "NOT_A_REAL_VALUE"})
        assert bad.status_code == 400
        assert bad.json()["error"] == "INVALID_DISPOSITION"

        ok = client.patch("/api/events/1", json={"disposition": "malicious"})
        assert ok.status_code == 200
        assert ok.json()["item"]["disposition"] == "MALICIOUS"


def test_api_tests_tls_rejects_http_target(tmp_path, monkeypatch) -> None:
    with _build_client(tmp_path, monkeypatch) as client:
        resp = client.post("/api/tests/tls", json={"url": "example.com"})
    assert resp.status_code == 400
    assert resp.json()["error"] == "TLS_HTTP_TARGET"


def test_api_tests_headers_accepts_http_target(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        app_module._HEADERS_CHECKS,
        "check_headers_for_url",
        lambda url, timeout: {
            "url": url,
            "status": "ok",
            "present": {"Strict-Transport-Security": False},
            "values": {"Strict-Transport-Security": ""},
        },
    )

    with _build_client(tmp_path, monkeypatch) as client:
        resp = client.post("/api/tests/headers", json={"url": "example.com"})
    assert resp.status_code == 200
    assert resp.json()["url"].startswith("http://")


def test_api_tests_zap_disabled_returns_structured_response(tmp_path, monkeypatch) -> None:
    with _build_client(tmp_path, monkeypatch, enable_zap=False) as client:
        resp = client.post("/api/tests/zap-baseline", json={"url": "https://example.com"})
    assert resp.status_code == 409
    data = resp.json()
    assert data["error"] == "ZAP_DISABLED"
    assert "config_hint" in data["details"]
