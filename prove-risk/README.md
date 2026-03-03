# Prove-Risk Toolkit (Passive, Safe by Default)

> [!WARNING]
> **Authorized use only:** Run this toolkit only against dashboards and infrastructure you own or are explicitly authorized to assess.
> **Prefer staging first:** Validate in staging/non-production before production runs.
> This toolkit is intentionally **passive-only** and non-destructive. It does not include exploit payloads, brute force, or credential attacks.

This folder provides a management-friendly “risk proof” workflow for internal dashboards:
- Per-target **HTML report** from OWASP ZAP baseline (passive scan)
- Per-target JSON artifacts for headers and TLS checks
- Markdown summaries and one consolidated `summary.md` for decision makers

## Layout

```text
prove-risk/
  README.md
  targets.example.yaml
  run_all.py
  checks/
    zap_baseline.py
    headers.py
    tls_expiry.py
  reports/
```

## Targets format

Use a YAML file like:

```yaml
targets:
  - name: "Finance Dashboard"
    url: "https://finance-dashboard.example.com"
  - name: "Ops Dashboard"
    url: "https://ops-dashboard.example.com"
```

## What each check does

### 1) ZAP baseline (`checks/zap_baseline.py`)
- Uses official Docker image: `ghcr.io/zaproxy/zaproxy:stable`
- Runs `zap-baseline.py` per target
- Writes HTML report to `prove-risk/reports/<target>/zap.html`
- Time-bounded with configurable `--minutes` and docker timeout
- Explicitly passive-only baseline behavior

### 2) Headers check (`checks/headers.py`)
Checks presence/absence of:
- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options` **or** CSP `frame-ancestors`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

Outputs:
- `prove-risk/reports/<target>/headers.json`
- `prove-risk/reports/headers_summary.md`

### 3) TLS expiry (`checks/tls_expiry.py`)
- Uses Python `ssl` + socket connection
- Reads certificate expiry and computes days remaining

Outputs:
- `prove-risk/reports/<target>/tls_expiry.json`
- `prove-risk/reports/tls_summary.md`

## Run everything

From repository root:

```bash
python prove-risk/run_all.py \
  --targets prove-risk/targets.example.yaml \
  --reports-dir prove-risk/reports \
  --timeout 8 \
  --delay 0.5 \
  --zap-minutes 2 \
  --zap-timeout 600
```

## Aggregated output

`run_all.py` writes:
- `prove-risk/reports/summary.md` with
  - High risk findings (critical header gaps, cert expiring soon, ZAP baseline issues)
  - Next actions section
- `prove-risk/reports/manifest.json`

## Safety controls included
- Rate limiting between targets (`--delay`)
- Timeouts on HTTP/socket operations (`--timeout`)
- Timeout guard around each Docker ZAP run (`--zap-timeout`)
