# Security guidance

HoneySentinel is a defensive honeypot. Deploy safely:

- Only monitor networks/systems where you have explicit authorization.
- Isolate in dedicated VLAN/DMZ; never directly expose sensitive internal systems.
- Restrict outbound egress to alert destinations only.
- Do not run with privileged ports unless intentionally configured and reviewed.
- Protect API endpoints with a strong `security.api_key`.
- Avoid collecting sensitive data; keep privacy defaults enabled.
