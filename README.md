# HoneySentinel

HoneySentinel is a **defensive**, low-interaction honeypot + alerting service. It exposes decoy TCP and HTTP listeners, records structured events to SQLite, runs local detection rules, and forwards alerts to email/Twilio/webhooks/syslog.

Built-in TCP decoys include SSH, Telnet, SMTP, Redis, generic binary, and an optional low-interaction RDP listener (default RDP port is 3389; use 33890 in unprivileged local setups).

## Safety warnings

- Use only on systems and networks you are authorized to monitor.
- Isolate deployment (VLAN/DMZ/container host), and deny outbound traffic by default except alert sinks.
- Do **not** place this on internal admin networks.
- This is not an IDS replacement; it is a lightweight signal generator.

## What is stored

- Event metadata (timestamps, source/destination ports, listener, messages)
- JSON event data per event
- By default, TCP stores hash + byte length only; no raw payload preview unless explicitly enabled.
- RDP decoy mode does **not** implement RDP authentication or a full handshake; it only accepts a connection, reads a bounded first chunk, stores summary metadata, and closes.
- HTTP request headers and body previews are redacted for credentials/secrets.

## Passive network visibility inputs

- **Suricata** is an IDS/IPS/NSM engine. HoneySentinel can ingest Suricata EVE JSON lines and normalize fields such as `src_ip`, `dest_ip`, ports, protocol, and `alert.signature`.
- **Zeek** is a passive NSM platform producing rich connection/protocol logs. HoneySentinel can ingest Zeek JSON `conn.log` style lines.
- Passive visibility requires mirrored traffic (SPAN/TAP) or flow export. Without those feeds, a sensor mostly sees its own host traffic.
- Ingestion is defensive-only: it tails existing logs, checkpoints `(inode, offset)`, handles rotation, and skips malformed lines.

## Quickstart (Python)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config.example.yaml config.yaml
python -m honeysentinel config.yaml
```

API/dashboard run on `http://127.0.0.1:8000`.


## **DO NOT PUT SECRETS IN config.yaml**

Use environment variable interpolation in YAML (supported by the config loader) and keep secrets in `.env` or your secret manager.

Example snippet:

```yaml
security:
  api_key: "${HONEYSENTINEL_API_KEY}"
alerts:
  email:
    username: "${SMTP_USERNAME}"
    password: "${SMTP_PASSWORD}"
  twilio:
    account_sid: "${TWILIO_ACCOUNT_SID}"
    auth_token: "${TWILIO_AUTH_TOKEN}"
```

Use `python scripts/generate_api_key.py` to create a strong API key.

## Alerts

- `alerts.email`: SMTP alerting with optional STARTTLS and optional auth (`username/password` can be empty for relay).
- `alerts.twilio`: SMS alerting via Twilio REST API. By default only severities `>= high` send (`min_severity` configurable).
- `rules.suppression_seconds`: deduplicates repeat alerts for the same rule + source IP.

## Environment variables / .env

HoneySentinel supports `${ENV_VAR}` expansion in `config.yaml`. Values come from process environment, and at startup HoneySentinel now loads a local `.env` file automatically (or `DOTENV_PATH` if set).

`.env` formatting tips:

- Avoid quotes unless the value truly needs them.
- Use `KEY=value` with no spaces around `=`.
- Keep `.env` out of Git (`.env.example` is provided as a safe template).

Variables used by default config patterns:

- `HONEYSENTINEL_API_KEY`
- `SMTP_USERNAME`
- `SMTP_PASSWORD`
- `TWILIO_ACCOUNT_SID`
- `TWILIO_AUTH_TOKEN`

If an alert channel is enabled but required credentials are still empty after expansion, HoneySentinel logs a warning so you can quickly verify env loading.

### Startup `.env` behavior

- `.env` loading can be inconsistent on Windows shells/services, so NetPot explicitly loads env files at startup before parsing `config.yaml`.
- Optional `DOTENV_PATH` can point to a specific env file for service managers or scheduled tasks.
- If `DOTENV_PATH` is unset (or points to a missing file), NetPot loads `.env` from the current working directory.


## Alert env vars (recommended)

Keep secrets out of `config.yaml` by exporting env vars referenced as `${VAR}` in YAML:

```bash
export SMTP_USERNAME=smtp-user
export SMTP_PASSWORD=smtp-password
export TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
export TWILIO_AUTH_TOKEN=your-twilio-auth-token
```

`alerts.twilio.min_severity` is a threshold (`low < medium < high < critical`).
Defaults stay quiet/safe: Twilio disabled and threshold set to `high`, plus rule suppression reduces duplicate notifications.

- Correlation rule raises severity one level and emits `correlated_alert` when honeypot activity and Suricata alerts share `src_ip` inside `rules.correlation_window_minutes`.
- RDP attempt rule: any RDP connection attempt triggers `medium` severity (`rdp_attempt`), and repeated attempts in the burst window escalate to `high` (`rdp_repeated`).

## Zeek JSON note

If your Zeek deployment outputs JSON logs, point `ingest.zeek.log_dir` to its active log directory (commonly `/opt/zeek/logs/current` or `/var/log/zeek/current`) and enable `ingest.zeek.enabled`.

## Test alert quickly

```bash
curl -i http://127.0.0.1:18080/admin
```

Then query events (defaults to OPEN disposition only):

```bash
curl -H "X-API-Key: changeme" http://127.0.0.1:8000/api/events
```

Filter by disposition(s):

```bash
curl -H "X-API-Key: changeme" "http://127.0.0.1:8000/api/events?disposition=OPEN,MALICIOUS"
```

Include all dispositions:

```bash
curl -H "X-API-Key: changeme" "http://127.0.0.1:8000/api/events?include_all=true"
```


## Tests tab (defensive prove-risk integration)

HoneySentinel includes a **Tests** tab in the web UI for defensive checks against a target URL.

Target URL rules:
- If no scheme is supplied, the backend/UI normalize to `http://`.
- Headers test supports both `http://` and `https://`.
- TLS Expiry test requires `https://`; `http://` returns a structured 400 error.


- **Run Headers**: passive HTTP security header presence checks.
- **Run TLS Expiry**: certificate expiry and days-remaining view with warning thresholds.
- **Run ZAP Baseline**: passive-only OWASP ZAP baseline scan (no active attacks).

ZAP baseline is explicitly opt-in and requires Docker:

```yaml
tests:
  enable_zap: false
  reports_dir: "./prove-risk/reports"
  request_timeout_seconds: 15
  zap_timeout_seconds: 300
```

When enabled (`tests.enable_zap: true`), the backend runs `zap-baseline.py` in Docker with timeouts/caps and stores reports under `tests.reports_dir`.
Generated HTML reports are served at `/reports/<path>` with path traversal protections.

All `/api/*` routes, including `/api/tests/*` and `/reports/*`, require `X-API-Key` when `security.api_key` is configured.

`/api/tests/capabilities` reports feature flags used by the UI (for example `enable_zap`).

## Development

```bash
make install
make lint
make test
make run
```


## Docker notes

- Compose reads optional secrets from `.env` (`.env.example` provided).
- By default, compose mounts `./config.example.yaml` into the container.
- To use a real local config file, run with `HONEYSENTINEL_CONFIG=./config.yaml docker compose up --build`.
