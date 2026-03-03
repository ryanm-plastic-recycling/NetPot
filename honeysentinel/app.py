from __future__ import annotations

import asyncio
import ipaddress
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

from honeysentinel.alerting import Alerter
from honeysentinel.config import AppConfig, load_config
from honeysentinel.db import Database
from honeysentinel.events import Event
from honeysentinel.ingest import JsonLineTailer, parse_suricata_eve_line, parse_zeek_conn_line
from honeysentinel.listeners.http import RawHttpListener
from honeysentinel.listeners.tcp import TcpListener
from honeysentinel.rules import RuleEngine


logger = logging.getLogger(__name__)


class AppState:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.db = Database(config.db_path)
        self.rules = RuleEngine(config.rules)
        self.alerter = Alerter(config.alerts)
        self.listeners: list[TcpListener | RawHttpListener] = []
        self.ingest_tasks: list[asyncio.Task[None]] = []
        self.ingestors: list[JsonLineTailer] = []
        self.allowlist = self._build_allowlist(config.noise.allowlist)

    def _build_allowlist(self, entries: list[str]) -> list[Any]:
        parsed: list[Any] = []
        for entry in entries:
            candidate = str(entry).strip()
            if not candidate:
                continue
            try:
                if "/" in candidate:
                    parsed.append(ipaddress.ip_network(candidate, strict=False))
                else:
                    parsed.append(ipaddress.ip_address(candidate))
            except ValueError:
                logger.warning("Invalid allowlist entry ignored: %s", candidate)
        return parsed

    def _is_allowlisted(self, src_ip: str) -> bool:
        if not self.allowlist:
            return False
        try:
            addr = ipaddress.ip_address(src_ip)
        except ValueError:
            return False
        for allowed in self.allowlist:
            if isinstance(allowed, (ipaddress.IPv4Address, ipaddress.IPv6Address)) and addr == allowed:
                return True
            if isinstance(allowed, (ipaddress.IPv4Network, ipaddress.IPv6Network)) and addr in allowed:
                return True
        return False

    async def handle_event(self, event: Event) -> None:
        event_id = await self.db.insert_event(event)
        if self._is_allowlisted(event.src_ip):
            return
        for alert in self.rules.evaluate(event):
            alert.context.setdefault("listener", event.listener)
            alert.context.setdefault("event_id", event_id)
            alert.context.setdefault("dst_port", event.dst_port)
            alert.context.setdefault("src_port", event.src_port)
            await self.alerter.send(alert)


def _render_base_html(active: str) -> str:
    # active: "events" | "system" | "alerts"
    # Single-file UI, served by FastAPI. No build tooling.
    return rf"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>HoneySentinel</title>
  <style>
    :root {{
      --bg: #0b1020;
      --panel: #121a33;
      --panel2: #0f1630;
      --text: #e8ecff;
      --muted: #a8b0d6;
      --line: rgba(255,255,255,.10);
      --accent: #5aa7ff;
      --good: #35d07f;
      --warn: #ffcc66;
      --bad: #ff6b6b;
      --chip: rgba(90,167,255,.16);
      --shadow: 0 12px 30px rgba(0,0,0,.35);
      --radius: 14px;
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      --sans: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, "Apple Color Emoji", "Segoe UI Emoji";
    }}
    @media (prefers-color-scheme: light){{
      :root{{
        --bg:#f6f7fb; --panel:#ffffff; --panel2:#fbfbff; --text:#0f1530; --muted:#4d587a; --line: rgba(15,21,48,.12);
        --shadow: 0 12px 30px rgba(0,0,0,.10);
      }}
    }}
    html,body{{height:100%;}}
    body{{
      margin:0;
      font-family:var(--sans);
      background: radial-gradient(1200px 700px at 30% -10%, rgba(90,167,255,.25), transparent 60%),
                  radial-gradient(900px 600px at 90% 10%, rgba(53,208,127,.18), transparent 55%),
                  var(--bg);
      color:var(--text);
    }}
    .wrap{{max-width:1240px;margin:0 auto;padding:18px 16px 40px;}}
    .topbar{{
      display:flex;gap:12px;align-items:center;justify-content:space-between;
      padding:14px 14px;border:1px solid var(--line);border-radius:var(--radius);
      background: linear-gradient(180deg, rgba(255,255,255,.06), transparent);
      box-shadow: var(--shadow);
      position: sticky; top: 10px; z-index: 10;
      backdrop-filter: blur(10px);
    }}
    .brand{{display:flex;gap:12px;align-items:center;}}
    .logo{{
      width:40px;height:40px;border-radius:12px;
      background: radial-gradient(circle at 30% 30%, rgba(90,167,255,.9), rgba(90,167,255,.35) 55%, rgba(53,208,127,.25));
      box-shadow: inset 0 0 0 1px rgba(255,255,255,.14);
    }}
    h1{{font-size:18px;margin:0;letter-spacing:.3px;}}
    .sub{{font-size:12px;color:var(--muted);margin-top:2px;}}
    .right{{display:flex;gap:10px;align-items:center;flex-wrap:wrap;justify-content:flex-end;}}
    .status{{
      display:flex;gap:8px;align-items:center;padding:8px 10px;border:1px solid var(--line);border-radius:999px;background:rgba(255,255,255,.04);
      font-size:12px;color:var(--muted);
    }}
    .dot{{width:8px;height:8px;border-radius:50%;}}
    .dot.ok{{background:var(--good);}}
    .dot.bad{{background:var(--bad);}}
    .btn{{
      cursor:pointer; border:1px solid var(--line); background: rgba(255,255,255,.06);
      color: var(--text); padding:9px 12px; border-radius:12px; font-size:13px;
    }}
    .btn:hover{{border-color: rgba(90,167,255,.45);}}
    .btn.primary{{background: rgba(90,167,255,.18); border-color: rgba(90,167,255,.45);}}
    .tabs{{display:flex;gap:8px;align-items:center;}}
    .tab{{
      text-decoration:none;
      display:inline-flex;align-items:center;gap:8px;
      padding:9px 12px;border-radius:999px;border:1px solid var(--line);
      background: rgba(255,255,255,.04);
      color: var(--muted);
      font-size:13px;
    }}
    .tab.active{{
      color: var(--text);
      border-color: rgba(90,167,255,.55);
      background: rgba(90,167,255,.16);
    }}

    .grid{{display:grid;grid-template-columns: 1.25fr .75fr; gap:14px; margin-top:14px;}}
    @media (max-width: 980px){{ .grid{{grid-template-columns:1fr;}} .topbar{{position:static;}} }}

    .card{{
      border:1px solid var(--line); border-radius:var(--radius); background: rgba(255,255,255,.05);
      box-shadow: var(--shadow);
      overflow:hidden;
    }}
    .card .hd{{
      padding:12px 14px; border-bottom:1px solid var(--line);
      display:flex; align-items:center; justify-content:space-between; gap:10px;
      background: linear-gradient(180deg, rgba(255,255,255,.06), transparent);
    }}
    .card .hd .title{{font-size:13px;color:var(--muted);}}
    .card .bd{{padding:12px 14px;}}
    .row{{display:flex;gap:10px;flex-wrap:wrap;align-items:end;}}
    label{{font-size:12px;color:var(--muted);display:block;margin-bottom:6px;}}
    input, select, textarea{{
      width: 100%; box-sizing:border-box;
      padding:10px 10px; border-radius:12px; border:1px solid var(--line);
      background: rgba(0,0,0,.14); color: var(--text);
      outline: none;
    }}
    @media (prefers-color-scheme: light){{
      input, select, textarea{{background: rgba(255,255,255,.85);}}
    }}

    /* IMPORTANT: fix dropdown readability */
    select{{
      appearance: none;
      background-image:
        linear-gradient(45deg, transparent 50%, var(--muted) 50%),
        linear-gradient(135deg, var(--muted) 50%, transparent 50%);
      background-position:
        calc(100% - 18px) calc(1em + 2px),
        calc(100% - 13px) calc(1em + 2px);
      background-size: 5px 5px, 5px 5px;
      background-repeat: no-repeat;
      padding-right: 32px;
    }}
    option {{
      background: var(--panel);
      color: var(--text);
    }}

    .field{{min-width:160px; flex:1;}}
    .field.small{{min-width:120px; flex:0.7;}}
    .field.tiny{{min-width:90px; flex:0.4;}}
    .hint{{font-size:12px;color:var(--muted);margin-top:8px;line-height:1.35;}}
    .chips{{display:flex;gap:8px;flex-wrap:wrap;}}
    .chip{{
      font-size:12px; color: var(--text);
      padding:6px 10px; border-radius:999px;
      background: var(--chip); border:1px solid rgba(90,167,255,.25);
      cursor:pointer; user-select:none;
    }}
    .chip:hover{{border-color: rgba(90,167,255,.55);}}
    table{{width:100%; border-collapse: collapse; font-size:13px;}}
    th,td{{padding:10px 10px; border-bottom:1px solid var(--line); vertical-align:top;}}
    th{{color:var(--muted); font-weight:600; text-align:left; font-size:12px;}}
    tr:hover td{{background: rgba(90,167,255,.08);}}
    .mono{{font-family: var(--mono); font-size:12px;}}
    .pill{{
      display:inline-flex;align-items:center;gap:6px;
      padding:4px 8px;border-radius:999px;border:1px solid var(--line); background: rgba(255,255,255,.05);
      color:var(--muted); font-size:12px;
    }}
    .msg{{max-width:520px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;}}
    .drawer{{
      position: fixed; inset: 0 0 0 auto;
      width: min(560px, 92vw);
      background: var(--panel);
      border-left: 1px solid var(--line);
      transform: translateX(102%);
      transition: transform .18s ease;
      box-shadow: -20px 0 40px rgba(0,0,0,.35);
      z-index: 30;
      display:flex; flex-direction:column;
    }}
    .drawer.open{{transform: translateX(0);}}
    .drawer .dh{{padding:14px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:10px;}}
    .drawer .db{{padding:14px;overflow:auto;}}
    pre{{
      margin:0; padding:12px; border-radius:12px; border:1px solid var(--line);
      background: rgba(0,0,0,.14); color: var(--text); overflow:auto;
      font-family: var(--mono); font-size:12px; line-height:1.35;
    }}
    .kpi{{display:flex;gap:10px;flex-wrap:wrap;}}
    .kpi .box{{
      flex:1; min-width:160px;
      border:1px solid var(--line); border-radius:12px; padding:10px 12px; background: rgba(255,255,255,.05);
    }}
    .kpi .box .v{{font-size:18px;font-weight:700;}}
    .kpi .box .l{{font-size:12px;color:var(--muted);margin-top:2px;}}
    .err{{color: var(--bad); font-size:12px; white-space: pre-wrap;}}
    .ok{{color: var(--good); font-size:12px; white-space: pre-wrap;}}
    .two{{display:grid;grid-template-columns:1fr 1fr;gap:10px;}}
    @media (max-width: 980px){{ .two{{grid-template-columns:1fr;}} }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">
        <div class="logo" aria-hidden></div>
        <div>
          <h1>HoneySentinel</h1>
          <div class="sub">Live decoy + event ingestion dashboard</div>
        </div>
      </div>

      <div class="tabs">
        <a class="tab {'active' if active=='events' else ''}" href="/">Events</a>
        <a class="tab {'active' if active=='system' else ''}" href="/system">System</a>
        <a class="tab {'active' if active=='alerts' else ''}" href="/alerts">Alerts</a>
      </div>

      <div class="right">
        <div class="status" title="API health">
          <div id="dot" class="dot bad"></div>
          <div id="statusText">Disconnected</div>
        </div>
        <button class="btn" id="btnDocs">Docs</button>
        <button class="btn primary" id="btnRefresh">Refresh</button>
      </div>
    </div>

    <div id="page"></div>
  </div>

  <div id="drawer" class="drawer" aria-hidden="true">
    <div class="dh">
      <div>
        <div style="font-weight:700;">Event details</div>
        <div class="sub" id="drawerSub">—</div>
      </div>
      <button class="btn" id="btnClose">Close</button>
    </div>
    <div class="db">
      <div id="drawerSummary" style="margin-bottom:12px;border:1px solid var(--line);border-radius:12px;padding:10px;background:rgba(255,255,255,.04);"></div>
      <pre id="eventJson" class="mono">{{}}</pre>
    </div>
  </div>

<script>
(() => {{
  const ACTIVE = "{active}";
  const el = (id) => document.getElementById(id);

  const dot = el("dot");
  const statusText = el("statusText");
  const btnRefresh = el("btnRefresh");
  const btnDocs = el("btnDocs");
  const page = el("page");

  const drawer = el("drawer");
  const eventJson = el("eventJson");
  const drawerSub = el("drawerSub");
  const drawerSummary = el("drawerSummary");
  const btnClose = el("btnClose");

  const LS_KEY = "honeysentinel.apiKey";

  function setStatus(ok, text){{
    dot.className = "dot " + (ok ? "ok" : "bad");
    statusText.textContent = text;
  }}

  function getApiKey(){{
    const v = (document.getElementById("apiKey")?.value || "").trim();
    return v;
  }}

  async function apiFetch(path, opts={{}}){{
    const key = getApiKey();
    const headers = Object.assign({{}}, opts.headers || {{}});
    if (key) headers["X-API-Key"] = key;
    const r = await fetch(path, Object.assign({{}}, opts, {{ headers }}));
    let data = null;
    const ct = r.headers.get("content-type") || "";
    if (ct.includes("application/json")) {{
      try {{ data = await r.json(); }} catch {{ data = null; }}
    }} else {{
      try {{ data = await r.text(); }} catch {{ data = null; }}
    }}
    if (!r.ok) {{
      const detail = data && data.detail ? data.detail : (typeof data === "string" ? data : "");
      throw new Error(`${{r.status}} ${{r.statusText}}${{detail ? " — " + detail : ""}}`);
    }}
    return data;
  }}

  function openDrawer(eventObj){{
    drawer.classList.add("open");
    drawer.setAttribute("aria-hidden","false");
    drawerSub.textContent = `#${{eventObj.id}} • ${{eventObj.listener}} • ${{eventObj.event_type}}`;
    renderDrawerSummary(eventObj);
    eventJson.textContent = JSON.stringify(eventObj, null, 2);
  }}

  function closeDrawer(){{
    drawer.classList.remove("open");
    drawer.setAttribute("aria-hidden","true");
  }}

  btnClose?.addEventListener("click", closeDrawer);
  drawer?.addEventListener("click", (e) => {{ if (e.target === drawer) closeDrawer(); }});
  document.addEventListener("keydown", (e) => {{ if (e.key === "Escape") closeDrawer(); }});

  function escapeHtml(s) {{
    return String(s).replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
  }}


  function pickValue(obj, keys){{
    for (const key of keys) {{
      const val = obj && obj[key];
      if (val !== undefined && val !== null && String(val).trim() !== "") return val;
    }}
    return "—";
  }}

  function eventSummaryText(ev){{
    const rawSeverity = pickValue(ev.data || {{}}, ["severity", "alert_severity", "level"]);
    const severity = rawSeverity === "—" ? "INFO" : String(rawSeverity).toUpperCase();
    const pathOrPort = String(pickValue(ev.data || {{}}, ["path", "http_path", "url", "uri", "dst_port", "port", "service", "target_port"]));
    const src = `${{ev.src_ip || "—"}}:${{ev.src_port ?? "—"}}`;
    return `${{severity}} • ${{ev.event_type || "event"}} • ${{pathOrPort}} • ${{src}}`;
  }}

  function renderDrawerSummary(ev){{
    if (!drawerSummary) return;
    const data = ev.data || {{}};
    const src = `${{ev.src_ip || "—"}}:${{ev.src_port ?? "—"}}`;
    const pathPort = pickValue(data, ["path", "http_path", "url", "uri", "dst_port", "port", "service", "target_port"]);
    const ruleHit = pickValue(data, ["rule", "rule_name", "signature", "matched_rule"]);
    const msg = ev.message || pickValue(data, ["message", "summary", "note"]);
    drawerSummary.innerHTML = `
      <div style="font-weight:700;margin-bottom:8px;">Summary</div>
      <div class="hint" style="margin:0;">
        <div><b>Time:</b> ${{escapeHtml(ev.ts || "—")}}</div>
        <div><b>Listener:</b> ${{escapeHtml(ev.listener || "—")}}</div>
        <div><b>Type:</b> ${{escapeHtml(ev.event_type || "—")}}</div>
        <div><b>Source:</b> ${{escapeHtml(src)}}</div>
        <div><b>Path/Port:</b> ${{escapeHtml(pathPort)}}</div>
        <div><b>Rule hit:</b> ${{escapeHtml(ruleHit)}}</div>
        <div><b>Message:</b> ${{escapeHtml(String(msg || "—"))}}</div>
      </div>
    `;
  }}

  function toLocalMidnight(d) {{
    return new Date(d.getFullYear(), d.getMonth(), d.getDate(), 0, 0, 0, 0);
  }}

  function startOfThisWeekLocal() {{
    // Monday 00:00 local
    const now = new Date();
    const day = now.getDay(); // 0=Sun ... 6=Sat
    const delta = (day === 0 ? 6 : day - 1); // days since Monday
    const monday = new Date(now.getFullYear(), now.getMonth(), now.getDate() - delta);
    return toLocalMidnight(monday);
  }}

  function startOfThisMonthLocal() {{
    const now = new Date();
    return new Date(now.getFullYear(), now.getMonth(), 1, 0,0,0,0);
  }}

  function startOfLastMonthLocal() {{
    const now = new Date();
    return new Date(now.getFullYear(), now.getMonth() - 1, 1, 0,0,0,0);
  }}

  function startOfYesterdayLocal() {{
    const now = new Date();
    const y = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1);
    return toLocalMidnight(y);
  }}

  function iso(d) {{
    return d.toISOString();
  }}

  function renderEventsPage() {{
    page.innerHTML = `
      <div class="grid">
        <div class="card">
          <div class="hd">
            <div class="title">Events</div>
            <div class="pill"><span id="count">0</span> shown</div>
          </div>
          <div class="bd">
            <div class="row" style="margin-bottom:10px;">
              <div class="field">
                <label>API Key (stored in browser)</label>
                <input id="apiKey" type="password" placeholder="Paste your X-API-Key value…" />
              </div>
              <div class="field small">
                <label>Auto refresh</label>
                <select id="auto">
                  <option value="off">Off</option>
                  <option value="3">Every 3s</option>
                  <option value="5" selected>Every 5s</option>
                  <option value="10">Every 10s</option>
                  <option value="30">Every 30s</option>
                </select>
              </div>
              <div class="field tiny">
                <label>Limit</label>
                <input id="limit" type="number" min="1" max="500" value="100" />
              </div>
            </div>

            <div class="row" style="margin-bottom:10px;">
              <div class="field">
                <label>Listener</label>
                <select id="listener"><option value="">(any)</option></select>
              </div>
              <div class="field">
                <label>Event Type</label>
                <select id="eventType"><option value="">(any)</option></select>
              </div>
              <div class="field">
                <label>Source IP</label>
                <input id="srcIp" placeholder="e.g. 10.0.0.25" />
              </div>
              <div class="field small">
                <label>Timeframe</label>
                <select id="timeframe">
                  <option value="sinceMinutes">Rolling (minutes)</option>
                  <option value="yesterday">Yesterday</option>
                  <option value="thisWeek">This Week</option>
                  <option value="thisMonth">This Month</option>
                  <option value="lastMonth">Last Month</option>
                </select>
              </div>
              <div class="field tiny" id="sinceWrap">
                <label>Since (min)</label>
                <input id="sinceMin" type="number" min="0" value="1440" />
              </div>
            </div>

            <div class="chips" style="margin: 8px 0 12px;">
              <div class="chip" data-since="5">Last 5m</div>
              <div class="chip" data-since="15">Last 15m</div>
              <div class="chip" data-since="60">Last 60m</div>
              <div class="chip" data-since="240">Last 4h</div>
              <div class="chip" data-since="1440">Last 24h</div>
              <div class="chip" data-range="yesterday">Yesterday</div>
              <div class="chip" data-range="thisWeek">This Week</div>
              <div class="chip" data-range="thisMonth">This Month</div>
              <div class="chip" data-range="lastMonth">Last Month</div>
            </div>

            <div id="err" class="err"></div>

            <div style="overflow:auto;border:1px solid var(--line);border-radius:12px;">
              <table>
                <thead>
                  <tr>
                    <th style="width:70px;">ID</th>
                    <th style="width:190px;">Time</th>
                    <th style="width:160px;">Listener</th>
                    <th style="width:160px;">Type</th>
                    <th style="width:190px;">Source</th>
                    <th>Message</th>
                  </tr>
                </thead>
                <tbody id="tbody">
                  <tr><td colspan="6" style="color:var(--muted);">No events loaded yet.</td></tr>
                </tbody>
              </table>
            </div>

            <div class="hint">
              Tip: generate events by hitting the HTTP decoy (<span class="mono">http://localhost:18080/admin</span>)
              or probing a TCP decoy port. Click any row for full JSON.
            </div>
          </div>
        </div>

        <div class="card">
          <div class="hd">
            <div class="title">System snapshot</div>
            <div class="pill">/api/info</div>
          </div>
          <div class="bd">
            <div class="kpi">
              <div class="box">
                <div class="v" id="kpiDb">—</div>
                <div class="l">DB Path</div>
              </div>
              <div class="box">
                <div class="v" id="kpiTcp">—</div>
                <div class="l">TCP listeners</div>
              </div>
              <div class="box">
                <div class="v" id="kpiHttp">—</div>
                <div class="l">HTTP decoy</div>
              </div>
            </div>

            <div style="margin-top:12px;">
              <label>Raw info (read-only)</label>
              <pre id="info" class="mono">{{}}</pre>
            </div>
          </div>
        </div>
      </div>
    `;
  }}

  function renderSystemPage() {{
    page.innerHTML = `
      <div class="card" style="margin-top:14px;">
        <div class="hd">
          <div class="title">System</div>
          <div class="pill">/api/info</div>
        </div>
        <div class="bd">
          <div class="row" style="margin-bottom:10px;">
            <div class="field">
              <label>API Key (stored in browser)</label>
              <input id="apiKey" type="password" placeholder="Paste your X-API-Key value…" />
            </div>
          </div>
          <div id="err" class="err"></div>
          <div class="kpi" style="margin-bottom:12px;">
            <div class="box">
              <div class="v" id="kpiDb">—</div>
              <div class="l">DB Path</div>
            </div>
            <div class="box">
              <div class="v" id="kpiTcp">—</div>
              <div class="l">TCP listeners</div>
            </div>
            <div class="box">
              <div class="v" id="kpiHttp">—</div>
              <div class="l">HTTP decoy</div>
            </div>
          </div>
          <label>Raw info (read-only)</label>
          <pre id="info" class="mono">{{}}</pre>
        </div>
      </div>
    `;
  }}

  function renderAlertsPage() {{
    page.innerHTML = `
      <div class="grid">
        <div class="card">
          <div class="hd">
            <div class="title">Alert testing</div>
            <div class="pill">/api/alerts/test/*</div>
          </div>
          <div class="bd">
            <div class="row" style="margin-bottom:10px;">
              <div class="field">
                <label>API Key (stored in browser)</label>
                <input id="apiKey" type="password" placeholder="Paste your X-API-Key value…" />
              </div>
            </div>

            <div class="two">
              <div>
                <label>Test Email</label>
                <textarea id="emailMsg" rows="4" placeholder="Message (optional)"></textarea>
                <div style="height:10px;"></div>
                <button class="btn primary" id="btnTestEmail">Send Test Email</button>
                <div style="height:10px;"></div>
                <div id="emailRes" class="ok"></div>
              </div>

              <div>
                <label>Test SMS (Twilio)</label>
                <textarea id="smsMsg" rows="4" placeholder="Message (optional)"></textarea>
                <div style="height:10px;"></div>
                <button class="btn primary" id="btnTestSms">Send Test SMS</button>
                <div style="height:10px;"></div>
                <div id="smsRes" class="ok"></div>
              </div>
            </div>

            <div style="height:12px;"></div>
            <div id="err" class="err"></div>

            <div class="hint">
              These tests use whatever is configured in <span class="mono">config.yaml</span>.
              If Email/Twilio are disabled (or creds are wrong), you’ll get a clear error back.
            </div>
          </div>
        </div>

        <div class="card">
          <div class="hd">
            <div class="title">Alert configuration snapshot</div>
            <div class="pill">/api/info</div>
          </div>
          <div class="bd">
            <div id="alertsSummary" class="hint">Loading…</div>
            <div style="margin-top:10px;">
              <label>Raw info (read-only)</label>
              <pre id="info" class="mono">{{}}</pre>
            </div>
          </div>
        </div>
      </div>
    `;
  }}

  function mountPage() {{
    if (ACTIVE === "events") renderEventsPage();
    else if (ACTIVE === "system") renderSystemPage();
    else renderAlertsPage();
  }}

  function setSelectOptions(select, values){{
    const current = select.value;
    const base = select.querySelector('option[value=""]') || new Option("(any)", "");
    select.innerHTML = "";
    select.appendChild(base);
    const uniq = Array.from(new Set(values.filter(Boolean))).sort();
    for (const v of uniq) select.appendChild(new Option(v, v));
    if (uniq.includes(current)) select.value = current;
  }}

  async function loadInfo(){{
    const info = await apiFetch("/api/info");
    const infoPre = document.getElementById("info");
    if (infoPre) infoPre.textContent = JSON.stringify(info, null, 2);

    const db = document.getElementById("kpiDb");
    const tcp = document.getElementById("kpiTcp");
    const http = document.getElementById("kpiHttp");
    if (db) db.textContent = (info.db_path || "—").split(/[\\/]/).slice(-2).join("\\");
    if (tcp) tcp.textContent = String((info.tcp_listeners || []).length);
    if (http) http.textContent = info.http_listener ? `${{info.http_listener.host}}:${{info.http_listener.port}}` : "—";

    // For events page, populate listener dropdown from /api/info
    const listenerEl = document.getElementById("listener");
    if (listenerEl) {{
      const listeners = (info.tcp_listeners || []).map(x => x.name).concat(["http_raw"]);
      setSelectOptions(listenerEl, listeners);
    }}

    // Alerts page summary
    const sum = document.getElementById("alertsSummary");
    if (sum) {{
      const a = info.ingest ? "" : "";
      const emailEnabled = (info.ingest && false) ? "" : "";
      const alerts = info.privacy ? "" : "";
      const alertsCfg = info; // just use info blob
      const emailOn = (alertsCfg.ingest && false);
      // read enabled flags from alerts via info (we return full ingest/privacy; alerts config isn't included by default here)
      // We'll rely on test endpoints to confirm behavior.
      sum.innerHTML = `
        <div><span class="pill">Email test</span> and <span class="pill">SMS test</span> use your config + server-side alerting implementation.</div>
        <div style="margin-top:6px;color:var(--muted);">If a test fails, the response will tell you whether it’s disabled, misconfigured, or blocked by SMTP/Twilio.</div>
      `;
    }}

    return info;
  }}

  function buildSinceTs(){{
    const tf = document.getElementById("timeframe");
    const sinceMin = document.getElementById("sinceMin");

    if (!tf) {{
      // system/alerts pages don't filter
      return "";
    }}

    const v = tf.value;
    if (v === "yesterday") return iso(startOfYesterdayLocal());
    if (v === "thisWeek") return iso(startOfThisWeekLocal());
    if (v === "thisMonth") return iso(startOfThisMonthLocal());
    if (v === "lastMonth") return iso(startOfLastMonthLocal());

    // rolling minutes
    const m = Number(sinceMin?.value || 0);
    if (!m || m <= 0) return "";
    const d = new Date(Date.now() - m * 60 * 1000);
    return d.toISOString();
  }}

  async function loadEvents(){{
    const errEl = document.getElementById("err");
    const tbody = document.getElementById("tbody");
    const countEl = document.getElementById("count");
    if (!tbody) return;

    if (errEl) errEl.textContent = "";

    const params = new URLSearchParams();
    const limitEl = document.getElementById("limit");
    params.set("limit", String(Math.max(1, Math.min(500, Number(limitEl?.value || 100)))));
    params.set("offset", "0");

    const since = buildSinceTs();
    if (since) params.set("since_ts", since);

    const srcIpEl = document.getElementById("srcIp");
    const src = (srcIpEl?.value || "").trim();
    if (src) params.set("src_ip", src);

    const eventTypeEl = document.getElementById("eventType");
    const et = eventTypeEl?.value || "";
    if (et) params.set("event_type", et);

    const listenerEl = document.getElementById("listener");
    const li = listenerEl?.value || "";
    if (li) params.set("listener", li);

    const data = await apiFetch("/api/events?" + params.toString());
    const items = data.items || [];
    if (countEl) countEl.textContent = String(items.length);

    // Learn event types from data
    if (eventTypeEl) {{
      const seenTypes = items.map(x => x.event_type);
      setSelectOptions(eventTypeEl, [eventTypeEl.value || "", ...seenTypes, "tcp_connect","tcp_payload","http_request","suricata_eve","zeek_conn"]);
    }}

    if (!items.length){{
      tbody.innerHTML = `<tr><td colspan="6" style="color:var(--muted);">No events match current filters.</td></tr>`;
      return;
    }}

    tbody.innerHTML = items.map(ev => {{
      const src = `${{ev.src_ip}}:${{ev.src_port}}`;
      const msg = eventSummaryText(ev);
      const ts = ev.ts || "";
      return `
        <tr data-id="${{ev.id}}">
          <td class="mono">${{ev.id}}</td>
          <td class="mono">${{escapeHtml(ts)}}</td>
          <td><span class="pill">${{escapeHtml(ev.listener)}}</span></td>
          <td><span class="pill">${{escapeHtml(ev.event_type)}}</span></td>
          <td class="mono">${{escapeHtml(src)}}</td>
          <td class="msg" title="${{escapeHtml(msg)}}">${{escapeHtml(msg)}}</td>
        </tr>
      `;
    }}).join("");

    for (const tr of tbody.querySelectorAll("tr[data-id]")){{
      tr.addEventListener("click", () => {{
        const id = Number(tr.getAttribute("data-id"));
        const ev = items.find(x => x.id === id);
        if (ev) openDrawer(ev);
      }});
    }}
  }}

  async function testEmail(){{
    const errEl = document.getElementById("err");
    const out = document.getElementById("emailRes");
    if (out) out.textContent = "";
    if (errEl) errEl.textContent = "";
    const msg = (document.getElementById("emailMsg")?.value || "").trim();
    const payload = {{ message: msg }};
    const res = await apiFetch("/api/alerts/test/email", {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify(payload)
    }});
    if (out) out.textContent = "Email test queued/sent: " + JSON.stringify(res);
  }}

  async function testSms(){{
    const errEl = document.getElementById("err");
    const out = document.getElementById("smsRes");
    if (out) out.textContent = "";
    if (errEl) errEl.textContent = "";
    const msg = (document.getElementById("smsMsg")?.value || "").trim();
    const payload = {{ message: msg }};
    const res = await apiFetch("/api/alerts/test/twilio", {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify(payload)
    }});
    if (out) out.textContent = "SMS test queued/sent: " + JSON.stringify(res);
  }}

  async function refreshAll(){{
    try {{
      setStatus(false, "Connecting…");
      await loadInfo();
      if (ACTIVE === "events") await loadEvents();
      setStatus(true, "Connected");
    }} catch (e) {{
      setStatus(false, "Disconnected");
      const errEl = document.getElementById("err");
      if (errEl) errEl.textContent = String(e && e.message ? e.message : e);
    }}
  }}

  // Mount page skeleton
  mountPage();

  // Restore API key
  const apiKeyEl = document.getElementById("apiKey");
  const saved = localStorage.getItem(LS_KEY) || "";
  if (apiKeyEl && saved) apiKeyEl.value = saved;
  apiKeyEl?.addEventListener("change", () => {{
    localStorage.setItem(LS_KEY, getApiKey());
    refreshAll();
  }});

  // Wire core buttons
  btnRefresh.addEventListener("click", refreshAll);
  btnDocs.addEventListener("click", () => window.open("/docs", "_blank"));

  // Events page controls
  if (ACTIVE === "events") {{
    const listenerEl = document.getElementById("listener");
    const eventTypeEl = document.getElementById("eventType");
    const srcIpEl = document.getElementById("srcIp");
    const timeframeEl = document.getElementById("timeframe");
    const sinceMinEl = document.getElementById("sinceMin");
    const sinceWrap = document.getElementById("sinceWrap");
    const limitEl = document.getElementById("limit");
    const autoEl = document.getElementById("auto");

    function applyTimeframeUi(){{
      const v = timeframeEl.value;
      if (v === "sinceMinutes") {{
        sinceWrap.style.display = "";
      }} else {{
        sinceWrap.style.display = "none";
      }}
    }}

    timeframeEl.addEventListener("change", () => {{
      applyTimeframeUi();
      loadEvents();
    }});
    applyTimeframeUi();

    for (const x of [listenerEl, eventTypeEl, sinceMinEl, limitEl]) {{
      x.addEventListener("change", loadEvents);
    }}
    srcIpEl.addEventListener("keyup", (e) => {{ if (e.key === "Enter") loadEvents(); }});

    for (const c of document.querySelectorAll(".chip")){{
      c.addEventListener("click", () => {{
        const since = c.getAttribute("data-since");
        const range = c.getAttribute("data-range");
        if (since) {{
          timeframeEl.value = "sinceMinutes";
          applyTimeframeUi();
          sinceMinEl.value = since;
        }} else if (range) {{
          timeframeEl.value = range;
          applyTimeframeUi();
        }}
        loadEvents();
      }});
    }}

    let timer = null;
    function setAuto(){{
      if (timer) {{ clearInterval(timer); timer = null; }}
      const v = autoEl.value;
      if (v !== "off") {{
        const sec = Number(v);
        timer = setInterval(loadEvents, Math.max(1000, sec * 1000));
      }}
    }}
    autoEl.addEventListener("change", setAuto);
    setAuto();
  }}

  // Alerts page controls
  if (ACTIVE === "alerts") {{
    document.getElementById("btnTestEmail")?.addEventListener("click", () => testEmail().catch(e => {{
      const errEl = document.getElementById("err"); if (errEl) errEl.textContent = String(e.message || e);
    }}));
    document.getElementById("btnTestSms")?.addEventListener("click", () => testSms().catch(e => {{
      const errEl = document.getElementById("err"); if (errEl) errEl.textContent = String(e.message || e);
    }}));
  }}

  // Initial load
  refreshAll();
}})();
</script>
</body>
</html>
"""


def create_app(config_path: str = "config.yaml") -> FastAPI:
    cfg = load_config(config_path)
    state = AppState(cfg)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await state.db.connect()

        # TCP listeners
        for tcp_cfg in cfg.tcp_listeners:
            listener = TcpListener(tcp_cfg, cfg.privacy, state.handle_event)
            await listener.start()
            state.listeners.append(listener)

        # HTTP listener
        raw_http = RawHttpListener(cfg.http_listener, state.handle_event)
        await raw_http.start()
        state.listeners.append(raw_http)

        # Optional ingest tasks
        if cfg.ingest.suricata.enabled:
            suricata_tailer = JsonLineTailer(
                source_key="suricata",
                path_getter=lambda: Path(cfg.ingest.suricata.eve_path),
                parser=parse_suricata_eve_line,
                get_state=state.db.get_ingest_state,
                set_state=state.db.set_ingest_state,
                handle_event=state.handle_event,
                max_line_bytes=cfg.ingest.suricata.max_line_bytes,
            )
            state.ingestors.append(suricata_tailer)
            state.ingest_tasks.append(asyncio.create_task(suricata_tailer.run()))

        if cfg.ingest.zeek.enabled:

            def _zeek_path() -> Path | None:
                primary = Path(cfg.ingest.zeek.log_dir) / "conn.log"
                fallback = Path(cfg.ingest.zeek.fallback_log_dir) / "conn.log"
                if primary.exists():
                    return primary
                if fallback.exists():
                    return fallback
                return None

            zeek_tailer = JsonLineTailer(
                source_key="zeek_conn",
                path_getter=_zeek_path,
                parser=parse_zeek_conn_line,
                get_state=state.db.get_ingest_state,
                set_state=state.db.set_ingest_state,
                handle_event=state.handle_event,
                max_line_bytes=cfg.ingest.zeek.max_line_bytes,
            )
            state.ingestors.append(zeek_tailer)
            state.ingest_tasks.append(asyncio.create_task(zeek_tailer.run()))

        try:
            yield
        finally:
            for ingestor in state.ingestors:
                await ingestor.stop()
            await asyncio.gather(*state.ingest_tasks, return_exceptions=True)
            await asyncio.gather(*(listener.stop() for listener in state.listeners), return_exceptions=True)
            await state.db.close()

    app = FastAPI(title="HoneySentinel", lifespan=lifespan)
    app.state.hs = state

    async def require_api_key(request: Request, x_api_key: str = Header(default="")) -> None:
        key = request.app.state.hs.config.security.api_key
        if key and key != x_api_key:
            raise HTTPException(status_code=401, detail="Unauthorized")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    # Pages
    @app.get("/", response_class=HTMLResponse)
    async def events_page() -> str:
        return _render_base_html("events")

    @app.get("/system", response_class=HTMLResponse)
    async def system_page() -> str:
        return _render_base_html("system")

    @app.get("/alerts", response_class=HTMLResponse)
    async def alerts_page() -> str:
        return _render_base_html("alerts")

    # APIs
    @app.get("/api/info", dependencies=[Depends(require_api_key)])
    async def info() -> dict[str, Any]:
        return {
            "db_path": str(Path(cfg.db_path).resolve()),
            "tcp_listeners": [asdict(listener) for listener in cfg.tcp_listeners],
            "http_listener": asdict(cfg.http_listener),
            "privacy": asdict(cfg.privacy),
            "ingest": asdict(cfg.ingest),
        }

    @app.get("/api/events", dependencies=[Depends(require_api_key)])
    async def events(
        limit: int = Query(100, ge=1, le=500),
        offset: int = Query(0, ge=0),
        since_ts: str | None = None,
        src_ip: str | None = None,
        event_type: str | None = None,
        listener: str | None = None,
        event_id: int | None = Query(default=None, ge=1),
    ) -> dict[str, Any]:
        rows = await state.db.query_events(
            {
                "limit": limit,
                "offset": offset,
                "since_ts": since_ts,
                "src_ip": src_ip,
                "event_type": event_type,
                "listener": listener,
                "event_id": event_id,
            }
        )
        return {"items": rows, "count": len(rows)}

    # Alert test endpoints (real sends)
    @app.post("/api/alerts/test/email", dependencies=[Depends(require_api_key)])
    async def test_email(payload: dict[str, Any]) -> JSONResponse:
        """
        payload:
          - message: optional string
        """
        cfg_alerts = state.config.alerts
        if not getattr(cfg_alerts.email, "enabled", False):
            raise HTTPException(status_code=400, detail="Email alerts are disabled in config.yaml (alerts.email.enabled=false).")

        msg = (payload.get("message") or "").strip() or "HoneySentinel test email."

        # Build a minimal "alert-like" object that Alerter can send.
        # Alerter implementation typically accepts a dataclass; if yours differs,
        # this will throw a clear error and we’ll adapt.
        try:
            from honeysentinel.alerting import Alert  # type: ignore

            alert = Alert(
                rule="ui_test_email",
                severity="high",
                src_ip="ui",
                message=msg,
                context={"test": True, "channel": "email"},
            )
            await state.alerter.send(alert)
            return JSONResponse({"ok": True, "sent": True})
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Email test failed: {e!s}")

    @app.post("/api/alerts/test/twilio", dependencies=[Depends(require_api_key)])
    async def test_twilio(payload: dict[str, Any]) -> JSONResponse:
        """
        payload:
          - message: optional string
        """
        cfg_alerts = state.config.alerts
        if not getattr(cfg_alerts.twilio, "enabled", False):
            raise HTTPException(status_code=400, detail="Twilio alerts are disabled in config.yaml (alerts.twilio.enabled=false).")

        msg = (payload.get("message") or "").strip() or "HoneySentinel test SMS."

        try:
            from honeysentinel.alerting import Alert  # type: ignore

            alert = Alert(
                rule="ui_test_sms",
                severity="high",
                src_ip="ui",
                message=msg,
                context={"test": True, "channel": "sms"},
            )
            await state.alerter.send(alert)
            return JSONResponse({"ok": True, "sent": True})
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Twilio test failed: {e!s}")

    return app
