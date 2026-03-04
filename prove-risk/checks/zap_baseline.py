from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import yaml

DOCKER_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "target"


def load_targets(targets_path: Path) -> list[dict[str, str]]:
    data = yaml.safe_load(targets_path.read_text(encoding="utf-8"))
    targets = data.get("targets", []) if isinstance(data, dict) else []
    if not isinstance(targets, list):
        raise ValueError("targets must be a list")
    return targets




def is_docker_available() -> bool:
    return shutil.which("docker") is not None


def summarize_findings(stdout: str) -> dict[str, int]:
    summary = {"high": 0, "medium": 0, "low": 0, "informational": 0}
    patterns = {
        "high": r"FAIL-NEW:\s*(\d+)",
        "medium": r"WARN-NEW:\s*(\d+)",
        "low": r"WARN-INPROG:\s*(\d+)",
        "informational": r"INFO:\s*(\d+)",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, stdout)
        if match:
            summary[key] = int(match.group(1))
    return summary


def run_single_target(url: str, reports_dir: Path, minutes: int, docker_timeout: int, name: str = "UI target") -> dict[str, Any]:
    target_slug = _slugify(name)
    target_dir = reports_dir / target_slug
    target_dir.mkdir(parents=True, exist_ok=True)
    local_report = target_dir / "zap.html"

    cmd = [
        "docker",
        "run",
        "--rm",
        "-t",
        "-v",
        f"{target_dir.resolve()}:/zap/wrk:rw",
        DOCKER_IMAGE,
        "zap-baseline.py",
        "-t",
        url,
        "-m",
        str(minutes),
        "-r",
        "zap.html",
    ]

    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=docker_timeout)
        status = "ok" if proc.returncode in (0, 1, 2) else "error"
        stderr = proc.stderr.strip()
        stdout = proc.stdout.strip()
    except FileNotFoundError:
        status = "error"
        stdout = ""
        stderr = "Docker is not installed or not available in PATH"
    except subprocess.TimeoutExpired:
        status = "error"
        stdout = ""
        stderr = f"ZAP baseline timed out after {docker_timeout}s"

    (target_dir / "zap.log").write_text(f"Passive-only baseline check.\n\nSTDOUT:\n{stdout}\n\nSTDERR:\n{stderr}\n")

    return {
        "name": name,
        "url": url,
        "status": status,
        "report": str(local_report),
        "stderr": stderr,
        "summary": summarize_findings(stdout),
    }

def run(
    targets_path: Path,
    reports_dir: Path,
    minutes: int,
    docker_timeout: int,
    delay: float,
) -> list[dict[str, str]]:
    targets = load_targets(targets_path)
    results: list[dict[str, str]] = []

    for index, target in enumerate(targets):
        name = str(target.get("name", "Unnamed Target"))
        url = str(target.get("url", "")).strip()
        result = run_single_target(url=url, reports_dir=reports_dir, minutes=minutes, docker_timeout=docker_timeout, name=name)
        results.append(result)

        if index < len(targets) - 1 and delay > 0:
            time.sleep(delay)

    lines = ["# ZAP Baseline Summary", "", "Passive-only scan using OWASP ZAP baseline.", ""]
    for result in results:
        lines.append(f"## {result['name']}")
        lines.append(f"- URL: {result['url']}")
        lines.append(f"- Status: {result['status']}")
        lines.append(f"- HTML report: {result['report']}")
        if result["stderr"]:
            lines.append(f"- Notes: {result['stderr']}")
        lines.append("")
    (reports_dir / "zap_summary.md").write_text("\n".join(lines), encoding="utf-8")

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Run passive-only ZAP baseline checks via Docker")
    parser.add_argument("--targets", type=Path, required=True, help="Path to targets YAML")
    parser.add_argument("--reports-dir", type=Path, default=Path("prove-risk/reports"), help="Directory for reports")
    parser.add_argument("--minutes", type=int, default=2, help="Maximum spider time in minutes")
    parser.add_argument("--docker-timeout", type=int, default=600, help="Per-target docker timeout in seconds")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between targets in seconds")
    args = parser.parse_args()

    args.reports_dir.mkdir(parents=True, exist_ok=True)
    run(args.targets, args.reports_dir, args.minutes, args.docker_timeout, args.delay)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
