from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import yaml

from checks import headers, tls_expiry, zap_baseline


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "target"


def load_targets(targets_path: Path) -> list[dict[str, str]]:
    data = yaml.safe_load(targets_path.read_text(encoding="utf-8"))
    targets = data.get("targets", []) if isinstance(data, dict) else []
    if not isinstance(targets, list):
        raise ValueError("targets must be a list")
    return targets


def build_summary(
    targets: list[dict[str, str]],
    header_results: list[headers.HeaderCheckResult],
    tls_results: list[dict[str, Any]],
    zap_results: list[dict[str, str]],
) -> str:
    header_map = {r.name: r for r in header_results}
    tls_map = {r["name"]: r for r in tls_results}
    zap_map = {r["name"]: r for r in zap_results}

    lines = ["# Prove Risk Summary", "", "This toolkit is passive-only and non-destructive.", ""]
    lines.append("## High risk findings")
    lines.append("")

    findings = 0
    for target in targets:
        name = str(target.get("name", "Unnamed Target"))
        url = str(target.get("url", "")).strip()
        lines.append(f"### {name}")
        lines.append(f"- URL: {url}")

        header_result = header_map.get(name)
        if header_result and header_result.status == "ok":
            present = header_result.findings["present"]
            missing = [k for k, v in present.items() if not v]
            critical_missing = [
                key
                for key in missing
                if key in {"Strict-Transport-Security", "Content-Security-Policy", "Frame-Protection"}
            ]
            if critical_missing:
                findings += 1
                lines.append(f"- Header risk: Missing critical protections: {', '.join(critical_missing)}")
            elif missing:
                lines.append(f"- Header improvements: Missing {', '.join(missing)}")
            else:
                lines.append("- Header posture: No missing required headers from this checklist")
        elif header_result:
            findings += 1
            lines.append(f"- Header check error: {header_result.findings['error']}")

        tls_result = tls_map.get(name)
        if tls_result:
            if tls_result.get("status") == "ok":
                days_remaining = int(tls_result["days_remaining"])
                if days_remaining <= 30:
                    findings += 1
                    lines.append(f"- TLS risk: Certificate expires in {days_remaining} day(s)")
                else:
                    lines.append(f"- TLS posture: {days_remaining} day(s) to expiry")
            else:
                findings += 1
                lines.append(f"- TLS check error: {tls_result.get('error', 'unknown error')}")

        zap_result = zap_map.get(name)
        if zap_result:
            if zap_result["status"] == "ok":
                lines.append("- ZAP baseline: Completed (review HTML report for warnings)")
            else:
                findings += 1
                lines.append(f"- ZAP baseline error: {zap_result['stderr']}")

        lines.append("")

    if findings == 0:
        lines.append("No high risk findings were detected by this passive baseline run.")
    lines.append("")
    lines.append("## Next actions")
    lines.append("")
    lines.extend(
        [
            "1. Prioritize missing critical headers (HSTS, CSP, frame protections) in staging, then production.",
            "2. Rotate/renew TLS certificates expiring within 30 days and automate renewal checks.",
            "3. Review each target's `zap.html` for passive warnings and create remediation tickets.",
            "4. Re-run this toolkit after fixes and attach `summary.md` in management status updates.",
        ]
    )

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run passive prove-risk toolkit checks")
    parser.add_argument("--targets", type=Path, default=Path("prove-risk/targets.example.yaml"), help="Path to targets YAML")
    parser.add_argument("--reports-dir", type=Path, default=Path("prove-risk/reports"), help="Directory for reports")
    parser.add_argument("--timeout", type=float, default=8.0, help="Network timeout in seconds")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between targets in seconds")
    parser.add_argument("--zap-minutes", type=int, default=2, help="ZAP baseline max spider minutes")
    parser.add_argument("--zap-timeout", type=int, default=600, help="Docker timeout for each ZAP target")
    args = parser.parse_args()

    args.reports_dir.mkdir(parents=True, exist_ok=True)
    targets = load_targets(args.targets)

    header_results = headers.run(args.targets, args.reports_dir, timeout=args.timeout, delay=args.delay)
    tls_results = tls_expiry.run(args.targets, args.reports_dir, timeout=args.timeout, delay=args.delay)
    zap_results = zap_baseline.run(
        args.targets,
        args.reports_dir,
        minutes=args.zap_minutes,
        docker_timeout=args.zap_timeout,
        delay=args.delay,
    )

    summary = build_summary(targets, header_results, tls_results, zap_results)
    (args.reports_dir / "summary.md").write_text(summary, encoding="utf-8")

    manifest = {
        "targets": targets,
        "reports": {
            "summary": str(args.reports_dir / "summary.md"),
            "headers": str(args.reports_dir / "headers_summary.md"),
            "tls": str(args.reports_dir / "tls_summary.md"),
            "zap": str(args.reports_dir / "zap_summary.md"),
        },
    }
    (args.reports_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"Wrote consolidated summary: {args.reports_dir / 'summary.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
