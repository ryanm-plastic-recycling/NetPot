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

## Alerts

- `alerts.email`: SMTP alerting with optional STARTTLS and optional auth (`username/password` can be empty for relay).
- `alerts.twilio`: SMS alerting via Twilio REST API. By default only severities `>= high` send (`min_severity` configurable).
- `rules.suppression_seconds`: deduplicates repeat alerts for the same rule + source IP.
- Correlation rule raises severity one level and emits `correlated_alert` when honeypot activity and Suricata alerts share `src_ip` inside `rules.correlation_window_minutes`.
- RDP attempt rule: any RDP connection attempt triggers `medium` severity (`rdp_attempt`), and repeated attempts in the burst window escalate to `high` (`rdp_repeated`).

## Zeek JSON note

If your Zeek deployment outputs JSON logs, point `ingest.zeek.log_dir` to its active log directory (commonly `/opt/zeek/logs/current` or `/var/log/zeek/current`) and enable `ingest.zeek.enabled`.

## Test alert quickly

```bash
curl -i http://127.0.0.1:18080/admin
```

Then query events:

```bash
curl -H "X-API-Key: changeme" http://127.0.0.1:8000/api/events
```

## Development

```bash
make install
make lint
make test
make run
```
