# Security guidance

HoneySentinel is a defensive honeypot. Deploy safely:

- Only monitor networks/systems where you have explicit authorization.
- Isolate in dedicated VLAN/DMZ; never directly expose sensitive internal systems.
- Restrict outbound egress to alert destinations only.
- Do not run with privileged ports unless intentionally configured and reviewed.
- Protect API endpoints with a strong `security.api_key`.
- Avoid collecting sensitive data; keep privacy defaults enabled.

## Passive NSM visibility boundaries

- Zeek provides passive NSM logs (connection/protocol telemetry).
- Suricata provides IDS/IPS/NSM detection and EVE JSON alerts/events.
- To see meaningful network activity, deploy with SPAN/TAP/flow export or equivalent mirroring.
- Without mirrored traffic, telemetry is limited and mostly local to the sensor host.

## Alerting and suppression

- Email and Twilio integrations are notification-only and intended for defensive operations.
- Twilio sends only high/critical by default via `alerts.twilio.min_severity`.
- SMS alerts can incur carrier/Twilio costs; keep severity thresholds conservative and recipient lists minimal.
- Keep suppression enabled and tune thresholds/rate limits to avoid notification floods.
- Suppression (`rules.suppression_seconds`) reduces duplicate notifications for repetitive sources.
