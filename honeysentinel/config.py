from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_ENV_VAR_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


@dataclass(slots=True)
class PrivacyConfig:
    store_tcp_payload_preview: bool = False
    tcp_payload_preview_bytes: int = 256


@dataclass(slots=True)
class SecurityConfig:
    api_key: str = ""


@dataclass(slots=True)
class AlertEmailConfig:
    enabled: bool = False
    smtp_host: str = "localhost"
    smtp_port: int = 25
    username: str = ""
    password: str = ""
    from_addr: str = "honeysentinel@example.local"
    to_addrs: list[str] = field(default_factory=list)
    use_starttls: bool = False


@dataclass(slots=True)
class AlertTwilioConfig:
    enabled: bool = False
    account_sid: str = ""
    auth_token: str = ""
    from_number: str = ""
    to_numbers: list[str] = field(default_factory=list)
    min_severity: str = "high"


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
    email: AlertEmailConfig = field(default_factory=AlertEmailConfig)
    twilio: AlertTwilioConfig = field(default_factory=AlertTwilioConfig)
    webhook: AlertWebhookConfig = field(default_factory=AlertWebhookConfig)
    syslog: AlertSyslogConfig = field(default_factory=AlertSyslogConfig)


@dataclass(slots=True)
class SuricataIngestConfig:
    enabled: bool = False
    eve_path: str = "/var/log/suricata/eve.json"
    max_line_bytes: int = 65536


@dataclass(slots=True)
class ZeekIngestConfig:
    enabled: bool = False
    log_dir: str = "/opt/zeek/logs/current"
    fallback_log_dir: str = "/var/log/zeek/current"
    max_line_bytes: int = 65536


@dataclass(slots=True)
class IngestConfig:
    suricata: SuricataIngestConfig = field(default_factory=SuricataIngestConfig)
    zeek: ZeekIngestConfig = field(default_factory=ZeekIngestConfig)


@dataclass(slots=True)
class RulesConfig:
    suppression_seconds: int = 120
    correlation_window_minutes: int = 10
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
    ingest: IngestConfig = field(default_factory=IngestConfig)
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
    return parse_config(_expand_env_vars(raw))


def _expand_env_vars(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_VAR_PATTERN.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, list):
        return [_expand_env_vars(item) for item in value]
    if isinstance(value, dict):
        return {k: _expand_env_vars(v) for k, v in value.items()}
    return value


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
        email=AlertEmailConfig(**alerts_raw.get("email", {})),
        twilio=AlertTwilioConfig(**alerts_raw.get("twilio", {})),
        webhook=AlertWebhookConfig(**alerts_raw.get("webhook", {})),
        syslog=AlertSyslogConfig(**alerts_raw.get("syslog", {})),
    )

    ingest_raw = raw.get("ingest", {})
    ingest = IngestConfig(
        suricata=SuricataIngestConfig(**ingest_raw.get("suricata", {})),
        zeek=ZeekIngestConfig(**ingest_raw.get("zeek", {})),
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
        ingest=ingest,
        rules=rules,
        tcp_listeners=listeners,
        http_listener=http_listener,
    )
