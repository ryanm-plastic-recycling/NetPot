from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "target"


def load_targets(targets_path: Path) -> list[dict[str, str]]:
    data = yaml.safe_load(targets_path.read_text(encoding="utf-8"))
    targets = data.get("targets", []) if isinstance(data, dict) else []
    if not isinstance(targets, list):
        raise ValueError("targets must be a list")
    return targets


def get_tls_expiry(url: str, timeout: float) -> tuple[dict[str, Any], str | None]:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return {}, "URL has no hostname"

    port = parsed.port or 443
    context = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
    except (TimeoutError, OSError, ssl.SSLError) as exc:
        return {}, str(exc)

    not_after = cert.get("notAfter")
    if not not_after:
        return {}, "Certificate missing notAfter"

    expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    now = datetime.now(tz=timezone.utc)
    days_remaining = (expiry_dt - now).days

    return {
        "host": host,
        "port": port,
        "expires_at_utc": expiry_dt.isoformat(),
        "days_remaining": days_remaining,
    }, None


def run(targets_path: Path, reports_dir: Path, timeout: float, delay: float) -> list[dict[str, Any]]:
    targets = load_targets(targets_path)
    results: list[dict[str, Any]] = []

    for index, target in enumerate(targets):
        name = str(target.get("name", "Unnamed Target"))
        url = str(target.get("url", "")).strip()
        details, error = get_tls_expiry(url, timeout)

        result: dict[str, Any] = {"name": name, "url": url}
        if error:
            result.update({"status": "error", "error": error})
        else:
            result.update({"status": "ok", **details})

        target_dir = reports_dir / _slugify(name)
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / "tls_expiry.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        results.append(result)

        if index < len(targets) - 1 and delay > 0:
            time.sleep(delay)

    lines = ["# TLS Expiry Summary", ""]
    for result in results:
        lines.append(f"## {result['name']}")
        lines.append(f"- URL: {result['url']}")
        if result["status"] == "error":
            lines.append(f"- Status: error ({result['error']})")
        else:
            lines.append(f"- Certificate expires at: {result['expires_at_utc']}")
            lines.append(f"- Days remaining: {result['days_remaining']}")
        lines.append("")
    (reports_dir / "tls_summary.md").write_text("\n".join(lines), encoding="utf-8")

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Passive TLS certificate expiry checks for dashboard targets")
    parser.add_argument("--targets", type=Path, required=True, help="Path to targets YAML")
    parser.add_argument("--reports-dir", type=Path, default=Path("prove-risk/reports"), help="Directory for reports")
    parser.add_argument("--timeout", type=float, default=8.0, help="Socket timeout in seconds")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between targets in seconds")
    args = parser.parse_args()

    args.reports_dir.mkdir(parents=True, exist_ok=True)
    run(args.targets, args.reports_dir, timeout=args.timeout, delay=args.delay)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
