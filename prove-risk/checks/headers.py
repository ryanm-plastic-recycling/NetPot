from __future__ import annotations

import argparse
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

import yaml

REQUIRED_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


@dataclass
class HeaderCheckResult:
    name: str
    url: str
    status: str
    findings: dict[str, Any]


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "target"


def load_targets(targets_path: Path) -> list[dict[str, str]]:
    data = yaml.safe_load(targets_path.read_text(encoding="utf-8"))
    targets = data.get("targets", []) if isinstance(data, dict) else []
    if not isinstance(targets, list):
        raise ValueError("targets must be a list")
    return targets


def check_headers(url: str, timeout: float) -> tuple[dict[str, bool], dict[str, str], str | None]:
    req = Request(url, headers={"User-Agent": "prove-risk/1.0"})
    try:
        with urlopen(req, timeout=timeout) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
    except (TimeoutError, URLError, OSError) as exc:
        return {}, {}, str(exc)

    values = {header: headers.get(header.lower(), "") for header in REQUIRED_HEADERS}

    csp_value = values["Content-Security-Policy"]
    xfo_present = bool(values["X-Frame-Options"])
    frame_ancestors_present = "frame-ancestors" in csp_value.lower()

    present = {
        "Strict-Transport-Security": bool(values["Strict-Transport-Security"]),
        "Content-Security-Policy": bool(csp_value),
        "Frame-Protection": xfo_present or frame_ancestors_present,
        "X-Content-Type-Options": bool(values["X-Content-Type-Options"]),
        "Referrer-Policy": bool(values["Referrer-Policy"]),
        "Permissions-Policy": bool(values["Permissions-Policy"]),
    }
    return present, values, None


def run(targets_path: Path, reports_dir: Path, timeout: float, delay: float) -> list[HeaderCheckResult]:
    targets = load_targets(targets_path)
    results: list[HeaderCheckResult] = []

    for index, target in enumerate(targets):
        name = str(target.get("name", "Unnamed Target"))
        url = str(target.get("url", "")).strip()
        present, values, error = check_headers(url, timeout=timeout)

        if error:
            status = "error"
            findings: dict[str, Any] = {"error": error, "present": {}, "values": {}}
        else:
            status = "ok"
            findings = {"present": present, "values": values}

        target_dir = reports_dir / _slugify(name)
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / "headers.json").write_text(
            json.dumps({"name": name, "url": url, "status": status, **findings}, indent=2), encoding="utf-8"
        )

        results.append(HeaderCheckResult(name=name, url=url, status=status, findings=findings))

        if index < len(targets) - 1 and delay > 0:
            time.sleep(delay)

    summary_path = reports_dir / "headers_summary.md"
    lines = ["# Header Check Summary", ""]
    for result in results:
        lines.append(f"## {result.name}")
        lines.append(f"- URL: {result.url}")
        if result.status == "error":
            lines.append(f"- Status: error ({result.findings['error']})")
        else:
            present = result.findings["present"]
            for key, is_present in present.items():
                lines.append(f"- {key}: {'present' if is_present else 'missing'}")
        lines.append("")
    summary_path.write_text("\n".join(lines), encoding="utf-8")

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Passive security header checks for dashboard targets")
    parser.add_argument("--targets", type=Path, required=True, help="Path to targets YAML")
    parser.add_argument("--reports-dir", type=Path, default=Path("prove-risk/reports"), help="Directory for reports")
    parser.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between targets in seconds")
    args = parser.parse_args()

    args.reports_dir.mkdir(parents=True, exist_ok=True)
    run(args.targets, args.reports_dir, timeout=args.timeout, delay=args.delay)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
