from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from honeysentinel.alerting import Alerter
from honeysentinel.config import AppConfig, load_config
from honeysentinel.db import Database
from honeysentinel.events import Event
from honeysentinel.ingest import JsonLineTailer, parse_suricata_eve_line, parse_zeek_conn_line
from honeysentinel.listeners.http import RawHttpListener
from honeysentinel.listeners.tcp import TcpListener
from honeysentinel.rules import RuleEngine


class AppState:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.db = Database(config.db_path)
        self.rules = RuleEngine(config.rules)
        self.alerter = Alerter(config.alerts)
        self.listeners: list[TcpListener | RawHttpListener] = []
        self.ingest_tasks: list[asyncio.Task[None]] = []
        self.ingestors: list[JsonLineTailer] = []

    async def handle_event(self, event: Event) -> None:
        event_id = await self.db.insert_event(event)
        for alert in self.rules.evaluate(event):
            alert.context.setdefault("listener", event.listener)
            alert.context.setdefault("event_id", event_id)
            await self.alerter.send(alert)


def _render_dashboard_html() -> str:
    # Single-file dashboard (no build tooling). Uses /api/info and /api/events.
    return r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>HoneySentinel Dashboard</title>
  <style>
    :root{
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
    }
    @media (prefers-color-scheme: light){
      :root{
        --bg:#f6f7fb; --panel:#ffffff; --panel2:#fbfbff; --text:#0f1530; --muted:#4d587a; --line: rgba(15,21,48,.12);
        --shadow: 0 12px 30px rgba(0,0,0,.10);
      }
    }
    html,body{height:100%;}
    body{
      margin:0;
      font-family:var(--sans);
      background: radial-gradient(1200px 700px at 30% -10%, rgba(90,167,255,.25), transparent 60%),
                  radial-gradient(900px 600px at 90% 10%, rgba(53,208,127,.18), transparent 55%),
                  var(--bg);
      color:var(--text);
    }
    .wrap{max-width:1240px;margin:0 auto;padding:18px 16px 40px;}
    .topbar{
      display:flex;gap:12px;align-items:center;justify-content:space-between;
      padding:14px 14px;border:1px solid var(--line);border-radius:var(--radius);
      background: linear-gradient(180deg, rgba(255,255,255,.06), transparent);
      box-shadow: var(--shadow);
      position: sticky; top: 10px; z-index: 10;
      backdrop-filter: blur(10px);
    }
    .brand{display:flex;gap:12px;align-items:center;}
    .logo{
      width:40px;height:40px;border-radius:12px;
      background: radial-gradient(circle at 30% 30%, rgba(90,167,255,.9), rgba(90,167,255,.35) 55%, rgba(53,208,127,.25));
      box-shadow: inset 0 0 0 1px rgba(255,255,255,.14);
    }
    h1{font-size:18px;margin:0;letter-spacing:.3px;}
    .sub{font-size:12px;color:var(--muted);margin-top:2px;}
    .right{display:flex;gap:10px;align-items:center;flex-wrap:wrap;justify-content:flex-end;}
    .status{
      display:flex;gap:8px;align-items:center;padding:8px 10px;border:1px solid var(--line);border-radius:999px;background:rgba(255,255,255,.04);
      font-size:12px;color:var(--muted);
    }
    .dot{width:8px;height:8px;border-radius:50%;}
    .dot.ok{background:var(--good);}
    .dot.bad{background:var(--bad);}
    .btn{
      cursor:pointer; border:1px solid var(--line); background: rgba(255,255,255,.06);
      color: var(--text); padding:9px 12px; border-radius:12px; font-size:13px;
    }
    .btn:hover{border-color: rgba(90,167,255,.45);}
    .btn.primary{background: rgba(90,167,255,.18); border-color: rgba(90,167,255,.45);}
    .grid{display:grid;grid-template-columns: 1.2fr .8fr; gap:14px; margin-top:14px;}
    @media (max-width: 980px){ .grid{grid-template-columns:1fr;} .topbar{position:static;} }

    .card{
      border:1px solid var(--line); border-radius:var(--radius); background: rgba(255,255,255,.05);
      box-shadow: var(--shadow);
      overflow:hidden;
    }
    .card .hd{
      padding:12px 14px; border-bottom:1px solid var(--line);
      display:flex; align-items:center; justify-content:space-between; gap:10px;
      background: linear-gradient(180deg, rgba(255,255,255,.06), transparent);
    }
    .card .hd .title{font-size:13px;color:var(--muted);}
    .card .bd{padding:12px 14px;}
    .row{display:flex;gap:10px;flex-wrap:wrap;align-items:end;}
    label{font-size:12px;color:var(--muted);display:block;margin-bottom:6px;}
    input, select{
      width: 100%; box-sizing:border-box;
      padding:10px 10px; border-radius:12px; border:1px solid var(--line);
      background: rgba(0,0,0,.10); color: var(--text);
      outline: none;
    }
    @media (prefers-color-scheme: light){
      input,select{background: rgba(255,255,255,.65);}
    }
    .field{min-width:160px; flex:1;}
    .field.small{min-width:120px; flex:0.6;}
    .field.tiny{min-width:90px; flex:0.4;}
    .hint{font-size:12px;color:var(--muted);margin-top:8px;line-height:1.35;}
    .chips{display:flex;gap:8px;flex-wrap:wrap;}
    .chip{
      font-size:12px; color: var(--text);
      padding:6px 10px; border-radius:999px;
      background: var(--chip); border:1px solid rgba(90,167,255,.25);
      cursor:pointer;
    }
    .chip:hover{border-color: rgba(90,167,255,.55);}
    table{width:100%; border-collapse: collapse; font-size:13px;}
    th,td{padding:10px 10px; border-bottom:1px solid var(--line); vertical-align:top;}
    th{color:var(--muted); font-weight:600; text-align:left; font-size:12px;}
    tr:hover td{background: rgba(90,167,255,.08);}
    .mono{font-family: var(--mono); font-size:12px;}
    .pill{
      display:inline-flex;align-items:center;gap:6px;
      padding:4px 8px;border-radius:999px;border:1px solid var(--line); background: rgba(255,255,255,.05);
      color:var(--muted); font-size:12px;
    }
    .msg{max-width:520px;}
    .drawer{
      position: fixed; inset: 0 0 0 auto;
      width: min(560px, 92vw);
      background: var(--panel);
      border-left: 1px solid var(--line);
      transform: translateX(102%);
      transition: transform .18s ease;
      box-shadow: -20px 0 40px rgba(0,0,0,.35);
      z-index: 30;
      display:flex; flex-direction:column;
    }
    .drawer.open{transform: translateX(0);}
    .drawer .dh{padding:14px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:10px;}
    .drawer .db{padding:14px;overflow:auto;}
    pre{
      margin:0; padding:12px; border-radius:12px; border:1px solid var(--line);
      background: rgba(0,0,0,.14); color: var(--text); overflow:auto;
      font-family: var(--mono); font-size:12px; line-height:1.35;
    }
    .kpi{display:flex;gap:10px;flex-wrap:wrap;}
    .kpi .box{
      flex:1; min-width:160px;
      border:1px solid var(--line); border-radius:12px; padding:10px 12px; background: rgba(255,255,255,.05);
    }
    .kpi .box .v{font-size:18px;font-weight:700;}
    .kpi .box .l{font-size:12px;color:var(--muted);margin-top:2px;}
    .err{color: var(--bad); font-size:12px;}
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
      <div class="right">
        <div class="status" title="API health">
          <div id="dot" class="dot bad"></div>
          <div id="statusText">Disconnected</div>
        </div>
        <button class="btn" id="btnDocs">Docs</button>
        <button class="btn primary" id="btnRefresh">Refresh</button>
      </div>
    </div>

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
              <select id="listener">
                <option value="">(any)</option>
              </select>
            </div>
            <div class="field">
              <label>Event Type</label>
              <select id="eventType">
                <option value="">(any)</option>
              </select>
            </div>
            <div class="field">
              <label>Source IP</label>
              <input id="srcIp" placeholder="e.g. 10.0.0.25" />
            </div>
            <div class="field tiny">
              <label>Since (min)</label>
              <input id="sinceMin" type="number" min="0" value="60" />
            </div>
          </div>

          <div class="chips" style="margin: 8px 0 14px;">
            <div class="chip" data-since="5">Last 5m</div>
            <div class="chip" data-since="15">Last 15m</div>
            <div class="chip" data-since="60">Last 60m</div>
            <div class="chip" data-since="240">Last 4h</div>
            <div class="chip" data-since="1440">Last 24h</div>
          </div>

          <div id="err" class="err"></div>

          <div style="overflow:auto;border:1px solid var(--line);border-radius:12px;">
            <table>
              <thead>
                <tr>
                  <th style="width:70px;">ID</th>
                  <th style="width:180px;">Time</th>
                  <th style="width:150px;">Listener</th>
                  <th style="width:150px;">Type</th>
                  <th style="width:170px;">Source</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody id="tbody">
                <tr><td colspan="6" style="color:var(--muted);">No events loaded yet.</td></tr>
              </tbody>
            </table>
          </div>

          <div class="hint">
            Tip: generate events by hitting the HTTP decoy (default <span class="mono">http://localhost:18080/admin</span>)
            or probing a TCP decoy port. Click any row to see full details.
          </div>
        </div>
      </div>

      <div class="card">
        <div class="hd">
          <div class="title">System</div>
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
            <pre id="info" class="mono">{}</pre>
          </div>
        </div>
      </div>
    </div>
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
      <pre id="eventJson" class="mono">{}</pre>
    </div>
  </div>

<script>
(() => {
  const el = (id) => document.getElementById(id);
  const apiKeyEl = el("apiKey");
  const dot = el("dot");
  const statusText = el("statusText");
  const errEl = el("err");
  const tbody = el("tbody");
  const countEl = el("count");

  const listenerEl = el("listener");
  const eventTypeEl = el("eventType");
  const srcIpEl = el("srcIp");
  const sinceMinEl = el("sinceMin");
  const limitEl = el("limit");
  const autoEl = el("auto");

  const infoPre = el("info");
  const kpiDb = el("kpiDb");
  const kpiTcp = el("kpiTcp");
  const kpiHttp = el("kpiHttp");

  const drawer = el("drawer");
  const eventJson = el("eventJson");
  const drawerSub = el("drawerSub");

  const btnRefresh = el("btnRefresh");
  const btnDocs = el("btnDocs");
  const btnClose = el("btnClose");

  const LS_KEY = "honeysentinel.apiKey";

  function setStatus(ok, text){
    dot.className = "dot " + (ok ? "ok" : "bad");
    statusText.textContent = text;
  }

  function getApiKey(){
    return (apiKeyEl.value || "").trim();
  }

  async function apiFetch(path){
    const key = getApiKey();
    const headers = key ? { "X-API-Key": key } : {};
    const r = await fetch(path, { headers });
    if (!r.ok){
      let detail = "";
      try { detail = (await r.json()).detail || ""; } catch {}
      throw new Error(`${r.status} ${r.statusText}${detail ? " — " + detail : ""}`);
    }
    return r.json();
  }

  function isoSince(minutes){
    const m = Number(minutes || 0);
    if (!m || m <= 0) return "";
    const d = new Date(Date.now() - m * 60 * 1000);
    return d.toISOString();
  }

  function escapeHtml(s){
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function openDrawer(eventObj){
    drawer.classList.add("open");
    drawer.setAttribute("aria-hidden","false");
    drawerSub.textContent = `#${eventObj.id} • ${eventObj.listener} • ${eventObj.event_type}`;
    eventJson.textContent = JSON.stringify(eventObj, null, 2);
  }

  function closeDrawer(){
    drawer.classList.remove("open");
    drawer.setAttribute("aria-hidden","true");
  }

  function setSelectOptions(select, values){
    const current = select.value;
    const base = select.querySelector('option[value=""]');
    select.innerHTML = "";
    select.appendChild(base || new Option("(any)", ""));
    const uniq = Array.from(new Set(values.filter(Boolean))).sort();
    for (const v of uniq){
      const opt = new Option(v, v);
      select.appendChild(opt);
    }
    if (uniq.includes(current)) select.value = current;
  }

  async function loadInfo(){
    const info = await apiFetch("/api/info");
    infoPre.textContent = JSON.stringify(info, null, 2);

    kpiDb.textContent = (info.db_path || "—").split(/[\\/]/).slice(-2).join("\\");
    kpiTcp.textContent = String((info.tcp_listeners || []).length);
    kpiHttp.textContent = info.http_listener ? `${info.http_listener.host}:${info.http_listener.port}` : "—";

    const listeners = (info.tcp_listeners || []).map(x => x.name).concat(["http-decoy"]);
    setSelectOptions(listenerEl, listeners);

    // Derive event types from rules + known types (best-effort).
    // Real types vary based on listener mode; we’ll learn from live data too.
    setSelectOptions(eventTypeEl, ["tcp_connect","tcp_payload","http_request","suricata_eve","zeek_conn"]);
    return info;
  }

  async function loadEvents(){
    errEl.textContent = "";
    const params = new URLSearchParams();
    params.set("limit", String(Math.max(1, Math.min(500, Number(limitEl.value || 100)))));
    params.set("offset", "0");

    const since = isoSince(Number(sinceMinEl.value || 0));
    if (since) params.set("since_ts", since);

    const src = (srcIpEl.value || "").trim();
    if (src) params.set("src_ip", src);

    const et = eventTypeEl.value;
    if (et) params.set("event_type", et);

    const li = listenerEl.value;
    if (li){
      // backend stores http listener name as whatever it sets in Event.listener;
      // in this project, it’s "http-decoy"
      params.set("listener", li);
    }

    const data = await apiFetch("/api/events?" + params.toString());
    const items = data.items || [];
    countEl.textContent = String(items.length);

    // Learn event types from data
    const seenTypes = items.map(x => x.event_type);
    setSelectOptions(eventTypeEl, [eventTypeEl.value || "", ...seenTypes]);

    if (!items.length){
      tbody.innerHTML = `<tr><td colspan="6" style="color:var(--muted);">No events match current filters.</td></tr>`;
      return;
    }

    tbody.innerHTML = items.map(ev => {
      const src = `${ev.src_ip}:${ev.src_port}`;
      const msg = ev.message || "";
      const ts = ev.ts || "";
      return `
        <tr data-id="${ev.id}">
          <td class="mono">${ev.id}</td>
          <td class="mono">${escapeHtml(ts)}</td>
          <td><span class="pill">${escapeHtml(ev.listener)}</span></td>
          <td><span class="pill">${escapeHtml(ev.event_type)}</span></td>
          <td class="mono">${escapeHtml(src)}</td>
          <td class="msg">${escapeHtml(msg)}</td>
        </tr>
      `;
    }).join("");

    // Row click -> drawer
    for (const tr of tbody.querySelectorAll("tr[data-id]")){
      tr.addEventListener("click", () => {
        const id = Number(tr.getAttribute("data-id"));
        const ev = items.find(x => x.id === id);
        if (ev) openDrawer(ev);
      });
    }
  }

  async function refreshAll(){
    try{
      setStatus(false, "Connecting…");
      await loadInfo();
      await loadEvents();
      setStatus(true, "Connected");
    } catch (e){
      setStatus(false, "Disconnected");
      errEl.textContent = String(e && e.message ? e.message : e);
    }
  }

  // Wiring
  btnRefresh.addEventListener("click", refreshAll);
  btnDocs.addEventListener("click", () => window.open("/docs", "_blank"));
  btnClose.addEventListener("click", closeDrawer);
  drawer.addEventListener("click", (e) => { if (e.target === drawer) closeDrawer(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

  // Save/restore API key
  const saved = localStorage.getItem(LS_KEY) || "";
  if (saved) apiKeyEl.value = saved;
  apiKeyEl.addEventListener("change", () => {
    localStorage.setItem(LS_KEY, getApiKey());
    refreshAll();
  });

  // Auto refresh
  let timer = null;
  function setAuto(){
    if (timer) { clearInterval(timer); timer = null; }
    const v = autoEl.value;
    if (v !== "off"){
      const sec = Number(v);
      timer = setInterval(loadEvents, Math.max(1000, sec * 1000));
    }
  }
  autoEl.addEventListener("change", setAuto);

  // Filters trigger
  for (const x of [listenerEl, eventTypeEl, srcIpEl, sinceMinEl, limitEl]){
    x.addEventListener("change", loadEvents);
  }
  srcIpEl.addEventListener("keyup", (e) => { if (e.key === "Enter") loadEvents(); });

  for (const c of document.querySelectorAll(".chip")){
    c.addEventListener("click", () => {
      sinceMinEl.value = c.getAttribute("data-since");
      loadEvents();
    });
  }

  // Initial
  setAuto();
  refreshAll();
})();
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
        for tcp_cfg in cfg.tcp_listeners:
            listener = TcpListener(tcp_cfg, cfg.privacy, state.handle_event)
            await listener.start()
            state.listeners.append(listener)

        raw_http = RawHttpListener(cfg.http_listener, state.handle_event)
        await raw_http.start()
        state.listeners.append(raw_http)

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
            await asyncio.gather(
                *(listener.stop() for listener in state.listeners),
                return_exceptions=True,
            )
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

    # Real dashboard
    @app.get("/", response_class=HTMLResponse)
    async def dashboard() -> str:
        return _render_dashboard_html()

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

    return app
