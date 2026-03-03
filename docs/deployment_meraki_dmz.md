# HoneySentinel deployment: Meraki MX85 + DMZ

This guide is for **defensive monitoring only** and focuses on decoy exposure + safe isolation.

## Recommended inbound NAT mappings

Publish decoy services from WAN to the HoneySentinel host/container in DMZ:

- WAN `tcp/22` -> `honeysentinel:12222`
- WAN `tcp/80` -> `honeysentinel:18080`
- WAN `tcp/3389` -> `honeysentinel:33890`

> In this environment, WAN `tcp/443` is reserved for AnyConnect. Do **not** map HoneySentinel to 443.

## DMZ placement guidance

- Place HoneySentinel in a dedicated DMZ VLAN/subnet.
- Enforce **default deny** from DMZ -> internal networks.
- Permit only explicitly required flows.
  - Typically: no DMZ -> internal access needed.
  - Allow only outbound traffic required for alert sinks (SMTP relay and Twilio API endpoints).

## Egress allowlist concept (high level)

Use an explicit outbound allowlist from the honeypot host/container to:

- SMTP relay hostname/IP + port(s) used by your alert transport.
- Twilio API endpoints over HTTPS (port 443).

Keep all other outbound flows denied by default.

## Future dashboard exposure planning

If you later expose dashboards or APIs publicly, prefer a **second public IP** to avoid collisions with AnyConnect service ports and reduce operational risk.
