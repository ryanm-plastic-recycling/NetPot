from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(slots=True)
class PrivacyConfig:
    store_tcp_payload_preview: bool = False
    tcp_payload_preview_bytes: int = 256


@dataclass(slots=True)
class SecurityConfig:
    api_key: str = ""


@dataclass(slots=True)
class AlertSlackConfig:
    enabled: bool = False
    webhook_url: str = ""


@dataclass(slots=True)
class AlertWebhookConfig:
    enabled: bool = False
    url: str = ""


@dataclass(slots=True)
class AlertSyslogConfig:
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 5140


@dataclass(slots=True)
class AlertsConfig:
    slack: AlertSlackConfig = field(default_factory=AlertSlackConfig)
    webhook: AlertWebhookConfig = field(default_factory=AlertWebhookConfig)
    syslog: AlertSyslogConfig = field(default_factory=AlertSyslogConfig)


@dataclass(slots=True)
class RulesConfig:
    suppression_seconds: int = 120
    portscan_window_seconds: int = 60
    portscan_distinct_ports: int = 6
    burst_window_seconds: int = 30
    burst_events: int = 20
    http_path_substrings: list[str] = field(
        default_factory=lambda: ["/admin", "/login", "phpmyadmin", "wp-"]
    )
    payload_keywords: list[str] = field(
        default_factory=lambda: ["select ", "union ", "../", "cmd="]
    )


@dataclass(slots=True)
class TcpListenerConfig:
    name: str
    host: str
    port: int
    mode: str = "generic"
    banner: str = ""
    max_bytes: int = 2048


@dataclass(slots=True)
class HttpListenerConfig:
    host: str = "0.0.0.0"
    port: int = 18080
    max_headers: int = 64
    max_body_bytes: int = 4096


@dataclass(slots=True)
class AppConfig:
    db_path: str = "./data/honeysentinel.db"
    security: SecurityConfig = field(default_factory=SecurityConfig)
    privacy: PrivacyConfig = field(default_factory=PrivacyConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
    tcp_listeners: list[TcpListenerConfig] = field(default_factory=list)
    http_listener: HttpListenerConfig = field(default_factory=HttpListenerConfig)


def _require_unprivileged(port: int) -> int:
    if port < 1024:
        raise ValueError(f"Port {port} is privileged; use >=1024")
    return port


def load_config(path: str | Path) -> AppConfig:
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return parse_config(raw)


def parse_config(raw: dict[str, Any]) -> AppConfig:
    security = SecurityConfig(api_key=str(raw.get("security", {}).get("api_key", "")))
    privacy_raw = raw.get("privacy", {})
    privacy = PrivacyConfig(
        store_tcp_payload_preview=bool(
            privacy_raw.get("store_tcp_payload_preview", False)
        ),
        tcp_payload_preview_bytes=int(privacy_raw.get("tcp_payload_preview_bytes", 256)),
    )

    alerts_raw = raw.get("alerts", {})
    alerts = AlertsConfig(
        slack=AlertSlackConfig(**alerts_raw.get("slack", {})),
        webhook=AlertWebhookConfig(**alerts_raw.get("webhook", {})),
        syslog=AlertSyslogConfig(**alerts_raw.get("syslog", {})),
    )

    rules = RulesConfig(**raw.get("rules", {}))

    listeners: list[TcpListenerConfig] = []
    for entry in raw.get("listeners", {}).get("tcp", []):
        cfg = TcpListenerConfig(**entry)
        cfg.port = _require_unprivileged(int(cfg.port))
        listeners.append(cfg)

    http_listener = HttpListenerConfig(**raw.get("listeners", {}).get("http", {}))
    http_listener.port = _require_unprivileged(int(http_listener.port))

    return AppConfig(
        db_path=str(raw.get("db_path", "./data/honeysentinel.db")),
        security=security,
        privacy=privacy,
        alerts=alerts,
        rules=rules,
        tcp_listeners=listeners,
        http_listener=http_listener,
    )
