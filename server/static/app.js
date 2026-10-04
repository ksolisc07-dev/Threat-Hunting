/* Threat Hunting Console — SPA sin dependencias */
(() => {
  "use strict";

  // ------------------------------------------------------------------ util
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const SEVS = ["critical", "high", "medium", "low", "info"];
  const SEV_ES = { critical: "Crítica", high: "Alta", medium: "Media", low: "Baja", info: "Info" };
  const STATUS_ES = { new: "Nuevo", investigating: "Investigando", resolved: "Resuelto", false_positive: "Falso positivo" };
  const TASK_ES = { pending: "pendiente", sent: "enviada", done: "completada", error: "error" };
  const cssVar = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

  const fmtTime = (ts) => ts ? new Date(ts * 1000).toLocaleString("es", { dateStyle: "short", timeStyle: "medium" }) : "—";
  function ago(ts) {
    if (!ts) return "nunca";
    const s = Math.max(0, Date.now() / 1000 - ts);
    if (s < 60) return `hace ${Math.round(s)}s`;
    if (s < 3600) return `hace ${Math.round(s / 60)} min`;
    if (s < 86400) return `hace ${Math.round(s / 3600)} h`;
    return `hace ${Math.round(s / 86400)} d`;
  }
  const sev = (s) => `<span class="sev ${esc(s)}">${esc(SEV_ES[s] || s)}</span>`;
  const status = (s) => `<span class="status ${esc(s)}">${esc(STATUS_ES[s] || s)}</span>`;
  const tech = (t) => t ? `<a class="tag tech" target="_blank" rel="noopener" href="https://attack.mitre.org/techniques/${esc(t.replace(".", "/"))}/">${esc(t)}</a>` : "";
  const riskColor = (r) => r >= 70 ? cssVar("--critical") : r >= 40 ? cssVar("--high") : r >= 15 ? cssVar("--medium") : cssVar("--ok");
  const risk = (r) => `<div class="risk"><div class="risk-bar"><i style="width:${Math.min(100, r)}%;background:${riskColor(r)}"></i></div><b>${Math.round(r)}</b></div>`;
  const osIcon = (os) => ({ Windows: "🪟", Linux: "🐧", Darwin: "🍎" }[os] || "💻");
  const json = (o) => `<pre class="json">${esc(JSON.stringify(o, null, 2))}</pre>`;
  const empty = (msg) => `<div class="empty">${esc(msg)}</div>`;

  function toast(msg, kind = "", onClick) {
    const t = document.createElement("div");
    t.className = `toast ${kind}`;
    t.innerHTML = msg;
    if (onClick) t.onclick = () => { onClick(); t.remove(); };
    $("#toasts").append(t);
    setTimeout(() => t.remove(), 7000);
  }

  // ------------------------------------------------------------------ api
  let TOKEN = "";
  try { TOKEN = sessionStorage.getItem("thl_token") || ""; } catch (_) { /* almacenamiento bloqueado */ }

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      ...opts,
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${TOKEN}`, ...(opts.headers || {}) },
      body: opts.body && typeof opts.body !== "string" ? JSON.stringify(opts.body) : opts.body,
    });
    if (res.status === 401) { showLogin(); throw new Error("No autorizado"); }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    return data;
  }

  function showLogin(msg = "") {
    $("#login").hidden = false;
    $("#loginError").textContent = msg;
    $("#token").focus();
  }
  $("#loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    TOKEN = $("#token").value.trim();
    try {
      await api("/api/overview");
      try { sessionStorage.setItem("thl_token", TOKEN); } catch (_) { /* ignore */ }
      $("#login").hidden = true;
      route();
    } catch (err) { showLogin("Token inválido"); }
  });
  $("#logout").onclick = () => { try { sessionStorage.removeItem("thl_token"); } catch (_) { /* ignore */ } TOKEN = ""; showLogin(); };
  $("#menuBtn").onclick = () => $("#nav").classList.toggle("open");

  // ------------------------------------------------------------------ drawer
  function openDrawer(title, html) {
    $("#drawerTitle").innerHTML = title;
    $("#drawerBody").innerHTML = html;
    $("#drawer").classList.add("open");
    $("#scrim").classList.add("open");
    $("#drawer").setAttribute("aria-hidden", "false");
  }
  function closeDrawer() {
    $("#drawer").classList.remove("open");
    $("#scrim").classList.remove("open");
    $("#drawer").setAttribute("aria-hidden", "true");
  }
  $("#drawerClose").onclick = closeDrawer;
  $("#scrim").onclick = closeDrawer;
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

  // ------------------------------------------------------------------ charts
  function timelineChart(points) {
    const W = 720, H = 200, P = { l: 30, r: 8, t: 10, b: 22 };
    const max = Math.max(1, ...points.map((p) => SEVS.reduce((a, s) => a + (p[s] || 0), 0)));
    const bw = (W - P.l - P.r) / points.length;
    let bars = "";
    points.forEach((p, i) => {
      let y = H - P.b;
      for (const s of [...SEVS].reverse()) {
        const v = p[s] || 0;
        if (!v) continue;
        const h = (v / max) * (H - P.t - P.b);
        y -= h;
        bars += `<rect x="${P.l + i * bw + 2}" y="${y}" width="${Math.max(1, bw - 4)}" height="${h}" rx="2" fill="${cssVar("--" + s)}"><title>${new Date(p.t * 1000).getHours()}:00 · ${SEV_ES[s]}: ${v}</title></rect>`;
      }
    });
    let grid = "";
    for (let k = 0; k <= 4; k++) {
      const y = P.t + ((H - P.t - P.b) * k) / 4;
      grid += `<line class="grid-line" x1="${P.l}" x2="${W - P.r}" y1="${y}" y2="${y}"/><text class="axis" x="${P.l - 6}" y="${y + 3}" text-anchor="end">${Math.round(max * (1 - k / 4))}</text>`;
    }
    const labels = points.map((p, i) => i % 3 === 0 ? `<text class="axis" x="${P.l + i * bw + bw / 2}" y="${H - 6}" text-anchor="middle">${new Date(p.t * 1000).getHours()}h</text>` : "").join("");
    return `<div class="chart"><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Hallazgos por hora">${grid}${bars}${labels}</svg>
      <div class="legend">${SEVS.slice(0, 4).map((s) => `<span><i style="background:${cssVar("--" + s)}"></i>${SEV_ES[s]}</span>`).join("")}</div></div>`;
  }

  function donut(counts) {
    const total = SEVS.reduce((a, s) => a + (counts[s] || 0), 0);
    const R = 52, C = 2 * Math.PI * R;
    let off = 0, arcs = "";
    for (const s of SEVS) {
      const v = counts[s] || 0;
      if (!v) continue;
      const len = (v / total) * C;
      arcs += `<circle r="${R}" cx="70" cy="70" fill="none" stroke="${cssVar("--" + s)}" stroke-width="18" stroke-dasharray="${len} ${C - len}" stroke-dashoffset="${-off}" transform="rotate(-90 70 70)"><title>${SEV_ES[s]}: ${v}</title></circle>`;
      off += len;
    }
    if (!total) arcs = `<circle r="${R}" cx="70" cy="70" fill="none" stroke="${cssVar("--border")}" stroke-width="18"/>`;
    return `<div class="donut-wrap"><svg viewBox="0 0 140 140" width="140" height="140">${arcs}
      <text x="70" y="68" text-anchor="middle" font-size="26" font-weight="700" fill="${cssVar("--text")}">${total}</text>
      <text x="70" y="88" text-anchor="middle" font-size="11" fill="${cssVar("--muted")}">abiertos</text></svg>
      <div class="legend" style="flex-direction:column;gap:6px">${SEVS.slice(0, 4).map((s) => `<span><i style="background:${cssVar("--" + s)}"></i>${SEV_ES[s]}: <b>${counts[s] || 0}</b></span>`).join("")}</div></div>`;
  }

  function heat(n, max) {
    if (!n) return "transparent";
    const a = 0.15 + 0.75 * Math.min(1, n / Math.max(1, max));
    return `color-mix(in srgb, ${cssVar("--critical")} ${Math.round(a * 100)}%, transparent)`;
  }

  // ------------------------------------------------------------------ views
  const views = {};
  let current = null;
  let lastMaxFinding = null;

  function findingRow(f, withHost = true) {
    return `<tr class="click" data-finding="${f.id}">
      <td>${sev(f.severity)}</td>
      <td><div>${esc(f.title)}</div><div class="feed-meta">${esc(f.rule_id)} · ${esc(f.source)}${f.hits > 1 ? ` · ×${f.hits}` : ""}</div></td>
      ${withHost ? `<td>${f.hostname ? `<a href="#/agents/${esc(f.agent_id)}">${esc(f.hostname)}</a>` : "—"}</td>` : ""}
      <td>${esc(f.tactic || "")}<div>${tech(f.technique)}</div></td>
      <td>${status(f.status)}</td>
      <td class="time" title="${fmtTime(f.updated_at)}">${ago(f.updated_at)}</td></tr>`;
  }
  const findingTable = (rows, withHost = true) => rows.length ? `<div class="table-wrap"><table>
    <thead><tr><th>Sev.</th><th>Hallazgo</th>${withHost ? "<th>Host</th>" : ""}<th>ATT&amp;CK</th><th>Estado</th><th>Actualizado</th></tr></thead>
    <tbody>${rows.map((f) => findingRow(f, withHost)).join("")}</tbody></table></div>` : empty("Sin hallazgos");

  // ---- Panorama
  views.overview = {
    async render(el) {
      const d = await api("/api/overview");
      const maxT = Math.max(1, ...d.tactics.map((t) => t.count));
      const lh = d.last_hunt;
      el.innerHTML = `
        <div class="page-head"><div><h1>Panorama</h1><p>Caza autónoma cada ${d.hunt_interval}s · ${lh ? `última caza ${ago(lh.finished_at)} (${lh.findings} nuevos, ${lh.tasks} tareas)` : "sin cazas todavía"}</p></div></div>
        <div class="grid kpis">
          <div class="card kpi"><div class="label">Agentes en línea</div><div class="value">${d.agents_online}<span class="muted" style="font-size:16px"> / ${d.agents_total}</span></div><div class="sub">endpoints monitorizados</div></div>
          <div class="card kpi ${d.by_severity.critical ? "alert" : ""}"><div class="label">Críticos abiertos</div><div class="value">${d.by_severity.critical || 0}</div><div class="sub">${d.by_severity.high || 0} altos</div></div>
          <div class="card kpi"><div class="label">Hallazgos abiertos</div><div class="value">${d.open_findings}</div><div class="sub">nuevos + en investigación</div></div>
          <div class="card kpi"><div class="label">Respuestas autónomas</div><div class="value">${d.auto_tasks_24h}</div><div class="sub">tareas forenses 24h</div></div>
          <div class="card kpi"><div class="label">Eventos 24h</div><div class="value">${d.events_24h.toLocaleString("es")}</div><div class="sub">procesos + conexiones</div></div>
        </div>
        <div class="grid cols-2">
          <div class="card"><div class="card-head"><h3>Hallazgos · últimas 24h</h3></div>${timelineChart(d.timeline)}</div>
          <div class="card"><div class="card-head"><h3>Por severidad</h3></div>${donut(d.by_severity)}</div>
        </div>
        <div class="card" style="margin-top:16px"><div class="card-head"><h3>Cobertura ATT&amp;CK (hallazgos abiertos)</h3><a href="#/mitre">Matriz →</a></div>
          <div class="tactics-strip">${d.tactics.map((t) => `<div class="tactic-cell" style="background:${heat(t.count, maxT)}"><span>${esc(t.tactic)}</span><b>${t.count || ""}</b></div>`).join("")}</div></div>
        <div class="grid cols-2e" style="margin-top:16px">
          <div class="card"><div class="card-head"><h3>Hosts con mayor riesgo</h3><a href="#/agents">Todos →</a></div>
            <div class="risk-list">${d.top_hosts.length ? d.top_hosts.map((a) => `<a href="#/agents/${esc(a.id)}"><span><span class="dot ${a.online ? "on" : "off"}"></span>${osIcon(a.os)} ${esc(a.hostname)}</span>${risk(a.risk_score)}</a>`).join("") : empty("Aún no hay agentes. Despliega el agente en un endpoint.")}</div></div>
          <div class="card"><div class="card-head"><h3>Hallazgos recientes</h3><a href="#/findings">Todos →</a></div>
            <div class="feed">${d.recent_findings.length ? d.recent_findings.map((f) => `<div class="feed-item" data-finding="${f.id}">${sev(f.severity)}<div><div class="feed-title">${esc(f.title)}</div><div class="feed-meta">${esc(f.hostname || "")} · ${esc(f.technique || "")}</div></div><span class="time">${ago(f.updated_at)}</span></div>`).join("") : empty("Sin hallazgos")}</div></div>
        </div>
        <div class="card" style="margin-top:16px"><div class="card-head"><h3>Actividad autónoma del cazador</h3><a href="#/tasks">Tareas →</a></div>
          <div class="feed">${d.activity.length ? d.activity.map((t) => `<div class="feed-item" data-task="${t.id}"><span class="tag">${esc(t.module)}</span><div><div class="feed-title">${esc(t.hostname)} · ${esc(TASK_ES[t.status] || t.status)}</div><div class="feed-meta">${esc(t.created_by === "hunter" ? "🤖 " : "👤 ")}${esc(t.reason || "")}</div></div><span class="time">${ago(t.created_at)}</span></div>`).join("") : empty("Sin actividad todavía")}</div></div>`;
    },
    refresh: true,
  };

  // ---- Agentes
  views.agents = {
    async render(el, params) {
      if (params[0]) return views.agent.render(el, params);
      const rows = await api("/api/agents");
      el.innerHTML = `<div class="page-head"><div><h1>Agentes</h1><p>${rows.length} endpoints enrolados</p></div></div>
        <div class="card">${rows.length ? `<div class="table-wrap"><table><thead><tr><th>Host</th><th>SO</th><th>IP</th><th>Estado</th><th>Último contacto</th><th>Hallazgos</th><th>Riesgo</th></tr></thead><tbody>
        ${rows.map((a) => `<tr class="click" data-href="#/agents/${esc(a.id)}"><td><b>${esc(a.hostname)}</b><div class="feed-meta mono">${esc(a.id.slice(0, 8))} · v${esc(a.agent_version || "?")}</div></td>
          <td>${osIcon(a.os)} ${esc(a.os)} ${esc(a.os_version || "")}</td><td class="mono">${esc(a.ip || "")}</td>
          <td><span class="dot ${a.online ? "on" : "off"}"></span>${a.online ? "En línea" : "Desconectado"}</td>
          <td class="time">${ago(a.last_seen)}</td>
          <td>${a.open_findings}${a.critical_findings ? ` <span class="sev critical">${a.critical_findings} crít.</span>` : ""}</td>
          <td>${risk(a.risk_score)}</td></tr>`).join("")}</tbody></table></div>` : `<div class="empty">No hay agentes enrolados.<br><br>Ejecuta en cada endpoint:<br><code>python agent/th_agent.py --server ${esc(location.origin)} --enroll-key &lt;CLAVE&gt;</code></div>`}</div>`;
    },
    refresh: true,
  };

  // ---- Detalle de agente
  const agentState = { tab: "processes", filter: "" };
  views.agent = {
    async render(el, params) {
      const id = params[0];
      const [a, findings] = await Promise.all([api(`/api/agents/${id}`), api(`/api/findings?agent_id=${encodeURIComponent(id)}`)]);
      if (agentState.id !== id) Object.assign(agentState, { id, tab: "processes", filter: "" });
      const flagged = new Set(findings.filter((f) => f.status !== "false_positive").map((f) => f.evidence && f.evidence.pid).filter(Boolean));
      const h = a.host || {};
      el.innerHTML = `
        <div class="page-head"><div><a href="#/agents">← Agentes</a><h1>${osIcon(a.os)} ${esc(a.hostname)}</h1>
          <p><span class="dot ${a.online ? "on" : "off"}"></span>${a.online ? "En línea" : "Desconectado"} · último contacto ${ago(a.last_seen)} · intervalo ${a.interval}s</p></div>
          <div class="actions"><button class="btn" data-quick="snapshot">Recolección completa</button><button class="btn" data-quick="hunt_mode">Modo caza 10 min</button><button class="btn" data-quick="connections">Conexiones</button></div></div>
        <div class="card" style="margin-bottom:16px"><div class="host-head">
          <div><span>Riesgo</span>${risk(a.risk_score)}</div>
          <div><span>Sistema</span>${esc(h.platform || `${a.os} ${a.os_version || ""}`)}</div>
          <div><span>IP</span><span class="mono" style="display:inline;color:inherit">${esc(a.ip || "")}</span></div>
          <div><span>CPU / RAM</span>${h.cpu_percent ?? "—"}% / ${h.mem_percent ?? "—"}%</div>
          <div><span>Arranque</span>${fmtTime(h.boot_time)}</div>
          <div><span>Usuarios</span>${esc((a.users || []).map((u) => u.name).filter((v, i, s) => s.indexOf(v) === i).join(", ") || "—")}</div>
        </div></div>
        <div class="card">
          <div class="tabs" role="tablist">${[["processes", `Procesos (${a.processes.length})`], ["findings", `Hallazgos (${findings.length})`], ["network", "Red"], ["listeners", `Escucha (${a.listeners.length})`], ["persistence", "Persistencia"], ["tasks", "Tareas"]]
            .map(([k, l]) => `<button role="tab" data-tab="${k}" class="${agentState.tab === k ? "active" : ""}">${esc(l)}</button>`).join("")}</div>
          <div id="tabBody"></div></div>`;
      $$(".tabs button", el).forEach((b) => b.onclick = () => { agentState.tab = b.dataset.tab; agentState.filter = ""; views.agent.render(el, params); });
      $$("[data-quick]", el).forEach((b) => b.onclick = async () => {
        const m = b.dataset.quick;
        try {
          await api("/api/tasks", { method: "POST", body: { agent_id: id, module: m, params: m === "hunt_mode" ? { interval: 15, duration: 600 } : {} } });
          toast(`Tarea <b>${esc(m)}</b> encolada para ${esc(a.hostname)}`);
        } catch (err) { toast(esc(err.message), "high"); }
      });
      const body = $("#tabBody", el);
      const tab = agentState.tab;
      if (tab === "processes") renderProcessTree(body, a.processes, flagged, id);
      else if (tab === "findings") body.innerHTML = findingTable(findings, false);
      else if (tab === "listeners") body.innerHTML = a.listeners.length ? `<div class="table-wrap"><table><thead><tr><th>Proto</th><th>Dirección</th><th>Puerto</th><th>Proceso</th><th>PID</th></tr></thead><tbody>${a.listeners.map((l) => `<tr><td>${esc(l.proto)}</td><td class="mono">${esc(l.addr)}</td><td class="mono">${esc(l.port)}</td><td>${esc(l.process_name || "")}</td><td class="mono">${esc(l.pid ?? "")}</td></tr>`).join("")}</tbody></table></div>` : empty("Sin puertos en escucha");
      else if (tab === "network") {
        const dests = await api(`/api/agents/${id}/destinations`);
        body.innerHTML = dests.length ? `<p class="muted">Destinos agregados (conexiones nuevas observadas por el muestreador del agente).</p><div class="table-wrap"><table><thead><tr><th>Destino</th><th>Conexiones</th><th>Procesos</th><th>Primera</th><th>Última</th><th></th></tr></thead><tbody>${dests.map((d) => `<tr><td class="mono">${esc(d.raddr)}:${esc(d.rport)}</td><td>${d.n}</td><td>${esc(d.procs || "")}</td><td class="time">${fmtTime(d.first)}</td><td class="time">${ago(d.last)}</td><td><button class="btn sm" data-pivot="raddr:${esc(d.raddr)}">Pivotar</button></td></tr>`).join("")}</tbody></table></div>` : empty("Sin conexiones registradas");
        $$("[data-pivot]", body).forEach((b) => b.onclick = () => { huntState.scope = "network"; huntState.q = b.dataset.pivot; location.hash = "#/hunt"; });
      } else if (tab === "persistence") {
        const rows = await api(`/api/agents/${id}/persistence`);
        body.innerHTML = rows.length ? `<div class="table-wrap"><table><thead><tr><th>Tipo</th><th>Ubicación</th><th>Valor</th><th>Visto</th><th></th></tr></thead><tbody>${rows.map((r) => `<tr><td><span class="tag">${esc(r.kind)}</span></td><td class="mono trunc" title="${esc(r.location)}">${esc(r.location)}</td><td class="mono trunc" title="${esc(r.value)}">${esc(r.value)}</td><td class="time">${fmtTime(r.first_seen)}</td><td>${r.baseline ? '<span class="tag">línea base</span>' : '<span class="sev medium">nueva</span>'}</td></tr>`).join("")}</tbody></table></div>` : empty("Aún no se ha recolectado persistencia");
      } else if (tab === "tasks") {
        const [tasks, modules] = await Promise.all([api(`/api/tasks?agent_id=${encodeURIComponent(id)}`), api("/api/modules")]);
        body.innerHTML = `<form class="toolbar" id="taskForm"><select name="module">${Object.entries(modules).map(([k, v]) => `<option value="${esc(k)}" title="${esc(v)}">${esc(k)}</option>`).join("")}</select>
          <input name="params" placeholder='parámetros JSON, p. ej. {"path": "/tmp/x"} o {"pid": 1234}' style="flex:1;font-family:var(--mono)"><button class="btn primary">Encolar tarea</button></form>
          ${taskTable(tasks, false)}`;
        $("#taskForm", body).onsubmit = async (e) => {
          e.preventDefault();
          const f = e.target;
          let p = {};
          try { p = f.params.value.trim() ? JSON.parse(f.params.value) : {}; } catch (_) { return toast("Parámetros JSON inválidos", "high"); }
          try { await api("/api/tasks", { method: "POST", body: { agent_id: id, module: f.module.value, params: p } }); toast("Tarea encolada"); views.agent.render(el, params); } catch (err) { toast(esc(err.message), "high"); }
        };
      }
    },
    refresh: true,
  };

  function renderProcessTree(body, procs, flagged, agentId) {
    body.innerHTML = `<div class="toolbar"><input type="search" id="procFilter" placeholder="Filtrar por nombre, PID, usuario o línea de comandos" value="${esc(agentState.filter)}"></div><div class="tree" id="tree"></div>`;
    const draw = () => {
      const q = agentState.filter.toLowerCase();
      const byPid = new Map(procs.map((p) => [p.pid, p]));
      const kids = new Map();
      for (const p of procs) {
        const parent = byPid.has(p.ppid) && p.ppid !== p.pid ? p.ppid : 0;
        if (!kids.has(parent)) kids.set(parent, []);
        kids.get(parent).push(p);
      }
      const match = (p) => !q || `${p.name} ${p.pid} ${p.username} ${p.cmdline}`.toLowerCase().includes(q);
      const rows = [];
      if (q) {
        procs.filter(match).forEach((p) => rows.push({ p, depth: 0 }));
      } else {
        const walk = (pid, depth) => (kids.get(pid) || []).sort((a, b) => a.pid - b.pid).forEach((p) => { rows.push({ p, depth }); if (depth < 40) walk(p.pid, depth + 1); });
        walk(0, 0);
      }
      $("#tree", body).innerHTML = rows.slice(0, 1500).map(({ p, depth }) => `<div class="tree-row ${flagged.has(p.pid) ? "flag" : ""}" data-pid="${p.pid}" title="${esc(p.exe || "")}">
        <span class="twig">${"  ".repeat(depth)}${depth ? "└ " : ""}</span><span class="pname">${flagged.has(p.pid) ? "⚠ " : ""}${esc(p.name)}</span>
        <span class="muted">${p.pid}</span><span class="muted">${esc(p.username || "")}</span><span class="pcmd">${esc(p.cmdline || "")}</span></div>`).join("") || empty("Sin procesos");
      $$(".tree-row", body).forEach((r) => r.onclick = () => {
        const p = byPid.get(+r.dataset.pid);
        openDrawer(`${esc(p.name)} <span class="muted">PID ${p.pid}</span>`, `<dl class="kv">
          <dt>Ejecutable</dt><dd class="mono">${esc(p.exe || "—")}</dd><dt>Línea de comandos</dt><dd class="mono">${esc(p.cmdline || "—")}</dd>
          <dt>Usuario</dt><dd>${esc(p.username || "—")}</dd><dt>Padre</dt><dd>${esc(p.parent_name || "—")} (${p.ppid})</dd>
          <dt>Inicio</dt><dd>${fmtTime(p.create_time)}</dd><dt>SHA256</dt><dd class="mono">${esc(p.sha256 || "—")}</dd></dl>
          <div class="actions"><button class="btn" data-t="process_tree">Árbol forense</button>${p.exe ? '<button class="btn" data-t="scan_file">Escanear binario</button>' : ""}${p.sha256 ? `<a class="btn" target="_blank" rel="noopener" href="https://www.virustotal.com/gui/file/${esc(p.sha256)}">VirusTotal ↗</a>` : ""}<button class="btn" data-hunt="1">Cazar en la flota</button></div>`);
        $$("[data-t]", $("#drawerBody")).forEach((b) => b.onclick = async () => {
          const m = b.dataset.t;
          try { await api("/api/tasks", { method: "POST", body: { agent_id: agentId, module: m, params: m === "process_tree" ? { pid: p.pid } : { path: p.exe } } }); toast(`Tarea ${esc(m)} encolada`); } catch (err) { toast(esc(err.message), "high"); }
        });
        $("[data-hunt]", $("#drawerBody")).onclick = () => { huntState.scope = "processes"; huntState.q = p.sha256 ? `sha256:${p.sha256}` : `name:${p.name}`; closeDrawer(); location.hash = "#/hunt"; };
      });
    };
    $("#procFilter", body).oninput = (e) => { agentState.filter = e.target.value; draw(); };
    draw();
  }

  // ---- Hallazgos
  const fState = { status: "open", severity: "", q: "" };
  views.findings = {
    async render(el) {
      const qs = new URLSearchParams(fState).toString();
      const rows = await api(`/api/findings?${qs}`);
      const keep = document.activeElement && document.activeElement.id === "fq";
      el.innerHTML = `<div class="page-head"><div><h1>Hallazgos</h1><p>${rows.length} resultados · detección en tiempo real + caza autónoma</p></div></div>
        <div class="card"><div class="toolbar">
          <input type="search" id="fq" placeholder="Buscar título, regla, técnica, host o evidencia" value="${esc(fState.q)}">
          <select id="fstatus">${[["open", "Abiertos"], ["", "Todos"], ["new", "Nuevos"], ["investigating", "Investigando"], ["resolved", "Resueltos"], ["false_positive", "Falsos positivos"]].map(([v, l]) => `<option value="${v}" ${fState.status === v ? "selected" : ""}>${l}</option>`).join("")}</select>
          <select id="fsev"><option value="">Toda severidad</option>${SEVS.map((s) => `<option value="${s}" ${fState.severity === s ? "selected" : ""}>${SEV_ES[s]}</option>`).join("")}</select>
        </div>${findingTable(rows)}</div>`;
      let timer;
      $("#fq", el).oninput = (e) => { clearTimeout(timer); timer = setTimeout(() => { fState.q = e.target.value; views.findings.render(el); }, 300); };
      if (keep) { const i = $("#fq", el); i.focus(); i.setSelectionRange(i.value.length, i.value.length); }
      $("#fstatus", el).onchange = (e) => { fState.status = e.target.value; views.findings.render(el); };
      $("#fsev", el).onchange = (e) => { fState.severity = e.target.value; views.findings.render(el); };
    },
    refresh: true,
  };

  async function showFinding(id) {
    const f = await api(`/api/findings/${id}`);
    const ev = f.evidence || {};
    openDrawer(`${sev(f.severity)} ${esc(f.title)}`, `
      <p class="muted">${esc(f.description || "")}</p>
      <dl class="kv">
        <dt>Host</dt><dd>${f.hostname ? `<a href="#/agents/${esc(f.agent_id)}">${esc(f.hostname)}</a>` : "—"}</dd>
        <dt>Regla</dt><dd><span class="tag">${esc(f.rule_id)}</span> · origen <b>${esc(f.source)}</b></dd>
        <dt>ATT&amp;CK</dt><dd>${esc(f.tactic || "")} ${tech(f.technique)}</dd>
        <dt>Puntuación</dt><dd>${f.score} · visto ${f.hits} ${f.hits === 1 ? "vez" : "veces"}</dd>
        <dt>Primera / última</dt><dd>${fmtTime(f.created_at)} · ${fmtTime(f.updated_at)}</dd>
        <dt>Estado</dt><dd>${status(f.status)}</dd>
      </dl>
      <div class="actions">
        <button class="btn" data-st="investigating">Investigar</button>
        <button class="btn" data-st="resolved">Resolver</button>
        <button class="btn" data-st="false_positive">Falso positivo</button>
        <button class="btn" id="respond">🤖 Enriquecer (respuesta autónoma)</button>
        ${ev.sha256 ? `<a class="btn" target="_blank" rel="noopener" href="https://www.virustotal.com/gui/file/${esc(ev.sha256)}">VirusTotal ↗</a>` : ""}
        ${ev.raddr ? `<button class="btn" id="pivotIp">Pivotar IP</button><button class="btn" id="iocIp">Marcar IP como IOC</button>` : ""}
      </div>
      <h3 class="section">Evidencia</h3>${json(ev)}
      <h3 class="section">Notas del analista</h3>
      <textarea id="notes" rows="3" placeholder="Hipótesis, contexto, siguientes pasos…">${esc(f.notes || "")}</textarea>
      <div class="actions"><button class="btn" id="saveNotes">Guardar notas</button></div>
      <h3 class="section">Recolección autónoma (${f.tasks.length})</h3>
      ${f.tasks.length ? f.tasks.map((t) => `<details><summary><span class="tag">${esc(t.module)}</span> ${esc(TASK_ES[t.status] || t.status)} · <span class="mono">${esc(JSON.stringify(t.params))}</span></summary>${t.result ? json(t.result) : '<p class="muted">Esperando al agente…</p>'}</details>`).join("") : '<p class="muted">Sin tareas asociadas (solo se lanzan automáticamente para severidad alta o crítica).</p>'}`);
    const body = $("#drawerBody");
    $$("[data-st]", body).forEach((b) => b.onclick = async () => { await api(`/api/findings/${id}`, { method: "PATCH", body: { status: b.dataset.st } }); toast(`Estado: ${STATUS_ES[b.dataset.st]}`); showFinding(id); refreshView(); });
    $("#saveNotes", body).onclick = async () => { await api(`/api/findings/${id}`, { method: "PATCH", body: { notes: $("#notes", body).value } }); toast("Notas guardadas"); };
    $("#respond", body).onclick = async () => { const r = await api(`/api/findings/${id}/respond`, { method: "POST" }); toast(`${r.tasks} tareas forenses encoladas`); showFinding(id); };
    if (ev.raddr) {
      $("#pivotIp", body).onclick = () => { huntState.scope = "network"; huntState.q = `raddr:${ev.raddr}`; closeDrawer(); location.hash = "#/hunt"; };
      $("#iocIp", body).onclick = async () => { const r = await api("/api/iocs", { method: "POST", body: [{ type: "ip", value: ev.raddr, description: `Desde hallazgo #${id}`, severity: "high" }] }); toast(r.added ? "IOC añadido: se re-cazará en toda la flota" : "El IOC ya existía"); };
    }
  }

  async function showTask(id) {
    const t = await api(`/api/tasks/${id}`);
    openDrawer(`<span class="tag">${esc(t.module)}</span> ${esc(t.hostname)}`, `<dl class="kv">
      <dt>Estado</dt><dd>${esc(TASK_ES[t.status] || t.status)}</dd><dt>Origen</dt><dd>${t.created_by === "hunter" ? "🤖 Cazador autónomo" : "👤 Analista"}</dd>
      <dt>Motivo</dt><dd>${esc(t.reason || "")}${t.finding_id ? ` · <a href="#" data-finding="${t.finding_id}">hallazgo #${t.finding_id}</a>` : ""}</dd>
      <dt>Parámetros</dt><dd class="mono">${esc(JSON.stringify(t.params))}</dd>
      <dt>Creada</dt><dd>${fmtTime(t.created_at)}</dd><dt>Completada</dt><dd>${fmtTime(t.completed_at)}</dd></dl>
      <h3 class="section">Resultado</h3>${t.result ? json(t.result) : '<p class="muted">Pendiente: el agente la recogerá en su próximo check-in.</p>'}`);
  }

  // ---- Tareas
  function taskTable(rows, withHost = true) {
    return rows.length ? `<div class="table-wrap"><table><thead><tr><th>#</th>${withHost ? "<th>Host</th>" : ""}<th>Módulo</th><th>Parámetros</th><th>Origen / motivo</th><th>Estado</th><th>Creada</th></tr></thead><tbody>
      ${rows.map((t) => `<tr class="click" data-task="${t.id}"><td class="mono">${t.id}</td>${withHost ? `<td>${esc(t.hostname)}</td>` : ""}<td><span class="tag">${esc(t.module)}</span></td>
        <td class="mono trunc">${esc(JSON.stringify(t.params))}</td><td class="trunc">${t.created_by === "hunter" ? "🤖" : "👤"} ${esc(t.reason || "")}</td>
        <td><span class="status ${t.status === "error" ? "new" : t.status === "done" ? "resolved" : "investigating"}">${esc(TASK_ES[t.status] || t.status)}</span></td><td class="time">${ago(t.created_at)}</td></tr>`).join("")}</tbody></table></div>` : empty("Sin tareas");
  }
  views.tasks = {
    async render(el) {
      const rows = await api("/api/tasks");
      el.innerHTML = `<div class="page-head"><div><h1>Tareas</h1><p>Recolección forense en los agentes: 🤖 lanzada por el cazador autónomo · 👤 por un analista. Solo módulos de solo lectura en lista blanca.</p></div></div><div class="card">${taskTable(rows)}</div>`;
    },
    refresh: true,
  };

  // ---- Caza
  const huntState = { scope: "processes", q: "", rows: null, ms: 0, error: "" };
  const EXAMPLES = {
    processes: ["cmdline:*-enc*", "parent:winword.exe|excel.exe", "exe:/tmp/*|/dev/shm/*", "name:powershell.exe -user:*SYSTEM* since:24h", "cmdline:*/dev/tcp/*", "mimikatz"],
    network: ["rport:4444|1337|31337", "process:powershell.exe|rundll32.exe", "raddr:185.* since:6h", "rport:>1024 -raddr:10.* -raddr:192.168.*"],
    persistence: ["kind:cron value:*curl*", "kind:run_key", "value:*\\Temp\\*", "kind:authorized_keys"],
  };
  views.hunt = {
    async render(el) {
      const [rules, hunts] = await Promise.all([api("/api/rules"), api("/api/hunts?limit=15")]);
      const lastById = {};
      if (hunts[0]) hunts[0].summary.forEach((s) => lastById[s.id] = s);
      el.innerHTML = `<div class="page-head"><div><h1>Caza</h1><p>Consulta toda la telemetría de la flota y revisa las hipótesis que el motor autónomo prueba en cada ciclo.</p></div></div>
        <div class="card"><div class="card-head"><h3>Consola de caza</h3></div>
          <form class="query-bar" id="qform"><select id="qscope">${[["processes", "Procesos"], ["network", "Red"], ["persistence", "Persistencia"]].map(([v, l]) => `<option value="${v}" ${huntState.scope === v ? "selected" : ""}>${l}</option>`).join("")}</select>
            <input id="q" value="${esc(huntState.q)}" placeholder="campo:valor  -campo:valor  a|b  comodín*  since:2h" autocomplete="off"><button class="btn primary">Buscar</button></form>
          <div class="examples">${EXAMPLES[huntState.scope].map((x) => `<button type="button" data-ex="${esc(x)}">${esc(x)}</button>`).join("")}</div>
          <div id="qres" style="margin-top:14px"></div></div>
        <div class="grid cols-2e" style="margin-top:16px">
          <div class="card"><div class="card-head"><h3>Hipótesis de caza autónoma</h3><span class="muted">${hunts[0] ? `ciclo #${hunts[0].id} ${ago(hunts[0].finished_at)}` : ""}</span></div>
            ${rules.hypotheses.map((h) => { const s = lastById[h.id]; return `<div class="hyp"><div><b>${esc(h.title)}</b> ${sev(h.severity)} ${tech(h.technique)}</div><div class="muted" style="text-align:right">${h.hits} hallazgos${s ? ` · ${s.ms} ms` : ""}${s && s.error ? ` · <span class="error">${esc(s.error)}</span>` : ""}</div><p>${esc(h.hypothesis)}</p></div>`; }).join("")}</div>
          <div class="card"><div class="card-head"><h3>Historial de cazas</h3></div>
            ${hunts.length ? `<div class="table-wrap"><table><thead><tr><th>#</th><th>Disparo</th><th>Inicio</th><th>Duración</th><th>Nuevos</th><th>Tareas</th></tr></thead><tbody>${hunts.map((h) => `<tr><td class="mono">${h.id}</td><td>${h.trigger === "auto" ? "🤖 auto" : "👤 manual"}</td><td class="time">${fmtTime(h.started_at)}</td><td>${h.finished_at ? `${Math.round((h.finished_at - h.started_at) * 1000)} ms` : "…"}</td><td>${h.findings}</td><td>${h.tasks}</td></tr>`).join("")}</tbody></table></div>` : empty("Sin cazas todavía")}
            <h3 class="section">Reglas en tiempo real (${rules.realtime.length})</h3>
            <div class="table-wrap"><table><tbody>${rules.realtime.map((r) => `<tr><td><span class="tag">${esc(r.id)}</span></td><td>${esc(r.title)}</td><td>${sev(r.severity)}</td><td>${tech(r.technique)}</td><td class="muted">${r.hits}</td></tr>`).join("")}</tbody></table></div></div>
        </div>`;
      $("#qscope", el).onchange = (e) => { huntState.scope = e.target.value; huntState.rows = null; views.hunt.render(el); };
      $$("[data-ex]", el).forEach((b) => b.onclick = () => { $("#q", el).value = b.dataset.ex; runQuery(el); });
      $("#qform", el).onsubmit = (e) => { e.preventDefault(); runQuery(el); };
      if (huntState.q && huntState.rows === null) runQuery(el); else drawResults(el);
    },
  };
  async function runQuery(el) {
    huntState.q = $("#q", el).value;
    huntState.error = "";
    try {
      const r = await api("/api/query", { method: "POST", body: { q: huntState.q, scope: huntState.scope, limit: 500 } });
      huntState.rows = r.rows; huntState.ms = r.ms;
    } catch (err) { huntState.rows = []; huntState.error = err.message; }
    drawResults(el);
  }
  function drawResults(el) {
    const box = $("#qres", el);
    if (!box) return;
    if (huntState.error) { box.innerHTML = `<p class="error">${esc(huntState.error)}</p>`; return; }
    const rows = huntState.rows;
    if (!rows) { box.innerHTML = '<p class="muted">Escribe una consulta o elige un ejemplo.</p>'; return; }
    if (!rows.length) { box.innerHTML = empty("Sin coincidencias"); return; }
    const cols = { processes: ["host", "name", "pid", "username", "parent_name", "cmdline", "first_seen"], network: ["host", "ts", "process_name", "pid", "raddr", "rport", "laddr", "lport"], persistence: ["host", "kind", "location", "value", "first_seen"] }[huntState.scope];
    const hosts = new Set(rows.map((r) => r.host));
    box.innerHTML = `<p class="muted">${rows.length} filas en ${huntState.ms} ms · ${hosts.size} hosts · <a href="#" id="csv">Exportar CSV</a></p><div class="table-wrap"><table><thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>
      ${rows.map((r) => `<tr>${cols.map((c) => { const v = r[c]; if (c === "host") return `<td><a href="#/agents/${esc(r.agent_id)}">${esc(v)}</a></td>`; if (c === "ts" || c === "first_seen") return `<td class="time">${fmtTime(v)}</td>`; return `<td class="${["cmdline", "value", "location"].includes(c) ? "mono trunc" : "mono"}" title="${esc(v ?? "")}">${esc(v ?? "")}</td>`; }).join("")}</tr>`).join("")}</tbody></table></div>`;
    $("#csv", box).onclick = (e) => {
      e.preventDefault();
      const all = Object.keys(rows[0]);
      const csv = [all.join(","), ...rows.map((r) => all.map((k) => `"${String(r[k] ?? "").replace(/"/g, '""')}"`).join(","))].join("\n");
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
      a.download = `hunt-${huntState.scope}-${Date.now()}.csv`;
      a.click();
    };
  }

  // ---- MITRE
  views.mitre = {
    async render(el) {
      const data = await api("/api/mitre");
      const max = Math.max(1, ...data.flatMap((t) => t.techniques.map((x) => x.n)));
      el.innerHTML = `<div class="page-head"><div><h1>MITRE ATT&amp;CK</h1><p>Técnicas observadas en la flota (excluye falsos positivos). La intensidad indica volumen de hallazgos.</p></div></div>
        <div class="mitre">${data.map((t) => `<div class="mitre-col"><h4>${esc(t.tactic)}<small>${t.techniques.reduce((a, x) => a + x.n, 0)} hallazgos</small></h4>
          ${t.techniques.map((x) => `<div class="tech" data-q="${esc(x.technique || "")}" style="background:${heat(x.n, max)}"><b>${esc(x.technique || "?")}</b> · ${x.n}<div class="feed-meta">${x.hosts} host(s) · ${esc((x.rules || "").split(",").join(", "))}</div></div>`).join("")}</div>`).join("")}</div>`;
      $$(".tech", el).forEach((t) => t.onclick = () => { fState.q = t.dataset.q; fState.status = ""; location.hash = "#/findings"; });
    },
    refresh: true,
  };

  // ---- IOCs
  views.iocs = {
    async render(el) {
      const rows = await api("/api/iocs");
      el.innerHTML = `<div class="page-head"><div><h1>Indicadores de compromiso</h1><p>Se aplican en tiempo real a la telemetría nueva y retrospectivamente a todo el histórico en cada ciclo de caza.</p></div></div>
        <div class="grid cols-2e">
          <div class="card"><div class="card-head"><h3>Añadir indicador</h3></div>
            <form id="iocForm" class="toolbar"><select name="type"><option value="ip">IP</option><option value="sha256">SHA256</option><option value="domain">Dominio</option><option value="process">Nombre de proceso</option><option value="cmdline">Fragmento de cmdline</option></select>
              <input name="value" placeholder="Valor" required style="flex:1"><select name="severity">${SEVS.map((s) => `<option value="${s}" ${s === "high" ? "selected" : ""}>${SEV_ES[s]}</option>`).join("")}</select>
              <input name="description" placeholder="Descripción / fuente" style="flex-basis:100%"><button class="btn primary">Añadir</button></form></div>
          <div class="card"><div class="card-head"><h3>Importación masiva</h3></div>
            <textarea id="bulk" rows="4" placeholder="tipo,valor,descripción  (una por línea)&#10;ip,203.0.113.66,C2 de campaña X&#10;sha256,e3b0c442...,dropper"></textarea>
            <div class="actions"><button class="btn" id="bulkBtn">Importar</button></div></div>
        </div>
        <div class="card" style="margin-top:16px">${rows.length ? `<div class="table-wrap"><table><thead><tr><th>Tipo</th><th>Valor</th><th>Severidad</th><th>Descripción</th><th>Alta</th><th></th></tr></thead><tbody>${rows.map((i) => `<tr><td><span class="tag">${esc(i.type)}</span></td><td class="mono">${esc(i.value)}</td><td>${sev(i.severity)}</td><td>${esc(i.description || "")}</td><td class="time">${ago(i.created_at)}</td><td><button class="btn sm danger" data-del="${i.id}">Eliminar</button></td></tr>`).join("")}</tbody></table></div>` : empty("Sin indicadores")}</div>`;
      $("#iocForm", el).onsubmit = async (e) => {
        e.preventDefault();
        const f = e.target;
        try { const r = await api("/api/iocs", { method: "POST", body: [{ type: f.type.value, value: f.value.value, severity: f.severity.value, description: f.description.value }] }); toast(r.added ? "IOC añadido" : "Ya existía"); views.iocs.render(el); } catch (err) { toast(esc(err.message), "high"); }
      };
      $("#bulkBtn", el).onclick = async () => {
        const items = $("#bulk", el).value.split("\n").map((l) => l.trim()).filter(Boolean).map((l) => { const [type, value, ...d] = l.split(","); return { type: (type || "").trim(), value: (value || "").trim(), description: d.join(",").trim(), severity: "high" }; });
        try { const r = await api("/api/iocs", { method: "POST", body: items }); toast(`${r.added} IOCs importados`); views.iocs.render(el); } catch (err) { toast(esc(err.message), "high"); }
      };
      $$("[data-del]", el).forEach((b) => b.onclick = async () => { await api(`/api/iocs/${b.dataset.del}`, { method: "DELETE" }); views.iocs.render(el); });
    },
  };

  // ------------------------------------------------------------------ router
  async function route() {
    if (!TOKEN) return showLogin();
    const [, name = "overview", ...params] = (location.hash || "#/overview").slice(1).split("/");
    const view = views[name] || views.overview;
    current = { name, params, view };
    $$("nav a").forEach((a) => a.classList.toggle("active", a.dataset.view === name));
    $("#nav").classList.remove("open");
    const el = $("#view");
    try {
      await view.render(el, params);
    } catch (err) {
      if (err.message !== "No autorizado") el.innerHTML = `<div class="card empty">Error: ${esc(err.message)}</div>`;
    }
  }

  async function refreshView() {
    if (!current || !current.view.refresh || $("#login").hidden === false) return;
    const a = document.activeElement;
    if (a && ["INPUT", "TEXTAREA", "SELECT"].includes(a.tagName) && a.id !== "fq") return; // no pisar lo que escribe el analista
    if (window.getSelection && String(window.getSelection())) return;
    const y = window.scrollY;
    try { await current.view.render($("#view"), current.params); window.scrollTo(0, y); } catch (_) { /* ignore */ }
  }

  async function poll() {
    if (!TOKEN || !$("#login").hidden) return;
    try {
      const d = await api("/api/overview");
      $("#live").classList.remove("off");
      $("#liveText").textContent = "en vivo";
      $("#navOpen").textContent = (d.by_severity.critical || 0) + (d.by_severity.high || 0) || "";
      if (lastMaxFinding !== null && d.max_finding_id > lastMaxFinding) {
        d.recent_findings.filter((f) => f.id > lastMaxFinding && ["critical", "high"].includes(f.severity)).slice(0, 3)
          .forEach((f) => toast(`${sev(f.severity)} <b>${esc(f.title)}</b><div class="feed-meta">${esc(f.hostname || "")}</div>`, f.severity, () => showFinding(f.id)));
      }
      lastMaxFinding = d.max_finding_id;
    } catch (_) {
      $("#live").classList.add("off");
      $("#liveText").textContent = "sin conexión";
    }
  }

  // Delegación de clics: filas y elementos con data-*
  document.addEventListener("click", (e) => {
    const f = e.target.closest("[data-finding]");
    if (f && !e.target.closest("a[href^='#/']")) { e.preventDefault(); showFinding(f.dataset.finding); return; }
    const t = e.target.closest("[data-task]");
    if (t) { showTask(t.dataset.task); return; }
    const r = e.target.closest("tr[data-href]");
    if (r && !e.target.closest("a")) location.hash = r.dataset.href;
  });

  $("#huntNow").onclick = async (e) => {
    const b = e.currentTarget;
    b.disabled = true;
    b.textContent = "Cazando…";
    try {
      const r = await api("/api/hunts/run", { method: "POST" });
      toast(`Caza #${r.hunt_id} completada: <b>${r.new_findings}</b> hallazgos nuevos, ${r.tasks} tareas autónomas`);
      refreshView();
    } catch (err) { toast(esc(err.message), "high"); }
    b.disabled = false;
    b.textContent = "Cazar ahora";
  };

  window.addEventListener("hashchange", () => { closeDrawer(); route(); });
  route().then(poll);
  setInterval(poll, 5000);
  setInterval(refreshView, 10000);
})();
