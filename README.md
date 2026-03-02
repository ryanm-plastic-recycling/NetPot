# HoneySentinel

HoneySentinel is a **defensive**, low-interaction honeypot + alerting service. It exposes decoy TCP and HTTP listeners, records structured events to SQLite, runs local detection rules, and forwards alerts to Slack/webhooks/syslog.

## Safety warnings

- Use only on systems and networks you are authorized to monitor.
- Isolate deployment (VLAN/DMZ/container host), and deny outbound traffic by default except alert sinks.
- Do **not** place this on internal admin networks.
- This is not an IDS replacement; it is a lightweight signal generator.

## What is stored

- Event metadata (timestamps, source/destination ports, listener, messages)
- JSON event data per event
- By default, TCP stores hash + byte length only; no raw payload preview unless explicitly enabled.
- HTTP request headers and body previews are redacted for credentials/secrets.

## Quickstart (Python)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config.example.yaml config.yaml
python -m honeysentinel config.yaml
```

API/dashboard run on `http://127.0.0.1:8000`.

## Quickstart (Docker)

```bash
docker compose up --build
```

This uses `config.example.yaml` and mounts database storage under `./data`.

## Config overview

See `config.example.yaml` for all fields:

- `security.api_key`: protects `/api/*` using `X-API-Key`.
- `privacy.store_tcp_payload_preview`: defaults to `false`.
- `rules.*`: thresholds for portscan, burst, path, and payload keyword detections.
- `listeners.tcp`: low-interaction service emulations.
- `listeners.http`: raw HTTP listener with caps.

## Test alert quickly

```bash
curl -i http://127.0.0.1:18080/admin
```

Then query events:

```bash
curl -H "X-API-Key: changeme" http://127.0.0.1:8000/api/events
```

## Database location

SQLite database path is `db_path` in config (default: `./data/honeysentinel.db`).

## Development

```bash
make install
make lint
make test
make run
```
