"use strict";

// --- utilidades ---

const $ = (sel) => document.querySelector(sel);
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/i;

// escapar todo lo que viene de DNS o del usuario antes de meterlo en el HTML
function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
}

// token de la API (solo hace falta si el servidor tiene DNSINSPECTOR_TOKEN)
async function authFetch(path, options = {}) {
  const send = () => fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", ...authHeader() },
  });
  let response = await send();
  if (response.status === 401) {
    const token = await askToken();
    if (token) {
      sessionStorage.setItem("apiToken", token.trim());
      response = await send();
    }
  }
  return response;
}

// dialogo propio: window.prompt no funciona en todos los navegadores
function askToken() {
  const dialog = $("#token-dialog");
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => resolve(dialog.returnValue === "ok" ? $("#token-input").value : ""), { once: true });
    $("#token-cancel").onclick = () => dialog.close("cancel");
    $("#token-form").onsubmit = () => { dialog.returnValue = "ok"; };
    dialog.showModal();
  });
}

function authHeader() {
  const token = sessionStorage.getItem("apiToken");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

// los enlaces de descarga no pueden llevar cabecera, asi que bajamos el fichero con fetch
async function downloadReport(link) {
  const response = await authFetch(link.dataset.download);
  if (!response.ok) return;
  const url = URL.createObjectURL(await response.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = link.dataset.filename;
  a.click();
  URL.revokeObjectURL(url);
}

async function api(path, options = {}) {
  const response = await authFetch(path, options);
  if (response.status === 204) return null;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(errorMessage(response.status, data));
  return data;
}

function errorMessage(status, data) {
  if (status === 429) return "Rate limit reached. Wait a minute and try again.";
  if (Array.isArray(data.detail)) {
    // errores de pydantic: nos quedamos con el texto
    return data.detail.map((d) => String(d.msg).replace(/^Value error, /, "")).join(". ");
  }
  return data.detail || `Request failed (HTTP ${status})`;
}

document.addEventListener("click", (e) => {
  const link = e.target.closest("a[data-download]");
  if (link) {
    e.preventDefault();
    downloadReport(link);
  }
});

function showError(id, message) {
  const el = $(id);
  el.textContent = message || "";
  el.hidden = !message;
}

function loading(text) {
  return `<div class="state"><div class="spinner"></div>${esc(text)}</div>`;
}

function formatDate(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
}

// --- router con hash ---

const routes = {
  analyze: () => {},
  lookup: () => {},
  history: () => loadHistory(),
  analysis: (id) => showAnalysis(id),
  compare: (a, b) => showCompare(a, b),
};

function router() {
  const [name = "analyze", ...args] = location.hash.replace(/^#\/?/, "").split("/");
  const route = routes[name] ? name : "analyze";
  const viewId = ["analysis", "compare"].includes(route) ? "detail" : route;
  document.querySelectorAll(".view").forEach((v) => { v.hidden = v.id !== `view-${viewId}`; });
  const activeTab = viewId === "detail" ? "history" : viewId;
  document.querySelectorAll("[data-tab]").forEach((a) => {
    a.classList.toggle("active", a.dataset.tab === activeTab);
  });
  routes[route](...args);
}

window.addEventListener("hashchange", router);

// --- analisis ---

$("#analyze-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = $("#analyze-domain");
  const domain = input.value.trim().replace(/\.$/, "");
  const selectors = $("#analyze-selectors").value.split(",").map((s) => s.trim()).filter(Boolean);
  // validacion rapida en el navegador, el servidor vuelve a validar
  const validAscii = DOMAIN_RE.test(domain) || /[^\x00-\x7f]/.test(domain);
  input.setAttribute("aria-invalid", String(!validAscii));
  if (!validAscii) return showError("#analyze-error", "Enter a valid domain name, e.g. example.com");
  if (selectors.length > 5) return showError("#analyze-error", "Use at most 5 DKIM selectors");
  showError("#analyze-error", "");

  const button = event.target.querySelector("button[type=submit]");
  button.disabled = true;
  $("#analysis-result").innerHTML = loading(`Analyzing ${domain}… this usually takes a few seconds`);
  try {
    const report = await api("/api/analyses", {
      method: "POST",
      body: JSON.stringify({ domain, dkim_selectors: selectors, probe_dkim: $("#analyze-probe").checked }),
    });
    $("#analysis-result").innerHTML = renderReport(report);
    bindReportActions($("#analysis-result"));
  } catch (err) {
    $("#analysis-result").innerHTML = "";
    showError("#analyze-error", err.message);
  } finally {
    button.disabled = false;
  }
});

async function showAnalysis(id) {
  const view = $("#view-detail");
  view.innerHTML = loading("Loading analysis…");
  try {
    const report = await api(`/api/analyses/${encodeURIComponent(id)}`);
    view.innerHTML = `<a href="#/history" class="btn small">← History</a>${renderReport(report)}`;
    bindReportActions(view);
  } catch (err) {
    view.innerHTML = `<div class="state">${esc(err.message)}</div>`;
  }
}

function bindReportActions(root) {
  root.querySelector("[data-delete]")?.addEventListener("click", async (e) => {
    if (!confirm("Delete this analysis from the history?")) return;
    try {
      await api(`/api/analyses/${e.currentTarget.dataset.delete}`, { method: "DELETE" });
      location.hash = "#/history";
      root.innerHTML = "";
    } catch (err) {
      alert(err.message);
    }
  });
}

// estado de cada auditoria -> color de la pastilla
const STATUS_CLASS = {
  ok: "good", signed: "good",
  weak: "warn", no_chain: "warn", revoked: "warn", unsigned: "warn",
  invalid: "bad", missing: "bad", broken: "bad",
};

function auditCard(title, audit, detail) {
  const status = audit?.status ?? "-";
  const cls = STATUS_CLASS[status] || "neutral";
  return `<div class="card">
    <div class="card-title">${esc(title)}<span class="pill ${cls}">${esc(status.replace("_", " "))}</span></div>
    <div class="card-detail">${detail}</div>
  </div>`;
}

function spfDetail(spf) {
  if (!spf?.record) return "No SPF record evaluated";
  const lookups = spf.lookup_count == null ? "" : ` · ${spf.lookup_count}/10 DNS lookups`;
  return `<code>${esc(spf.all ?? "no all")}</code>${esc(lookups)}`;
}

function dkimDetail(dkim) {
  if (dkim?.status === "not_found") return "No key found among common selectors";
  if (!dkim?.selectors?.length) return "No selector given. DKIM keys cannot be discovered via DNS.";
  return dkim.selectors.map((s) => {
    const key = s.key_bits ? `${s.key_type?.toUpperCase()} ${s.key_bits}-bit` : s.status;
    const tag = s.probed ? " (found by probing)" : "";
    return `<code>${esc(s.selector)}</code>: ${esc(key)}${esc(tag)}`;
  }).join("<br>");
}

function dmarcDetail(dmarc) {
  if (!dmarc?.record) return "No DMARC record";
  const t = dmarc.tags || {};
  const parts = [`p=${t.p}`, t.sp && `sp=${t.sp}`, t.pct && `pct=${t.pct}`];
  const inherited = dmarc.inherited ? ` · inherited from ${dmarc.source}` : "";
  return `<code>${esc(parts.filter(Boolean).join("; "))}</code>${esc(inherited)}`;
}

function dnssecDetail(dnssec) {
  if (!dnssec || dnssec.status === "skipped") return "-";
  const v = dnssec.validation;
  const parts = [`DS: ${dnssec.ds?.length ?? 0}`, `DNSKEY: ${dnssec.dnskey?.length ?? 0}`];
  if (v) parts.push(v.ds_matches_dnskey && v.dnskey_signature_valid ? "DS↔DNSKEY verified" : "verification failed");
  parts.push(`AD=${dnssec.ad_flag ? 1 : 0}`);
  const d = dnssec.denial;
  if (d?.type === "NSEC3") parts.push(`NSEC3 it=${d.iterations}${d.salt ? " salted" : ""}`);
  else if (d?.type) parts.push(d.type);
  return esc(parts.join(" · "));
}

function mtaStsDetail(m) {
  if (m.status === "not_applicable") return "Domain has no MX records";
  if (m.status === "skipped") return "-";
  const id = m.mta_sts?.tags?.id ? `id=${m.mta_sts.tags.id}` : "no policy record";
  const pol = m.policy ? ` · policy: ${esc(m.policy.policy?.mode || m.policy.status)}` : "";
  return `<code>${esc(id)}</code>${pol} · TLS-RPT: ${esc(m.tls_rpt?.status || "-")}`;
}

function bimiDetail(b) {
  if (b.status === "not_applicable") return "Domain has no MX records";
  if (b.status === "skipped" || b.status === "error") return "-";
  const dmarc = b.dmarc_ready ? "DMARC ready" : "DMARC not enforced";
  if (!b.record) return esc(`No record · ${dmarc}`);
  return `${b.tags?.a ? "with certificate" : "no certificate"} · ${esc(dmarc)}`;
}

function renderReport(r) {
  const counts = r.summary.counts;
  const sevBar = SEVERITIES.map((s) => `<div class="sev-count sev-${s} ${counts[s] ? "" : "zero"}">
      <strong>${counts[s]}</strong><span>${s}</span></div>`).join("");

  // recomendaciones prioritarias: critical/high/medium primero, maximo 5
  const priorities = r.findings.filter((f) => ["critical", "high", "medium"].includes(f.severity)).slice(0, 5);
  const prioritiesHtml = priorities.length
    ? `<ol class="priorities">${priorities.map((f) => `<li class="sev-${f.severity}">
        <span class="sev-tag">${esc(f.severity)}</span><span>${esc(f.recommendation)} <small>(${esc(f.id)})</small></span></li>`).join("")}</ol>`
    : `<p class="note">No critical, high or medium findings.</p>`;

  const findings = SEVERITIES.map((sev) => {
    const items = r.findings.filter((f) => f.severity === sev);
    if (!items.length) return "";
    return items.map((f) => `<details class="finding sev-${sev}">
      <summary><span class="sev-tag">${esc(sev)}</span><span class="fid">${esc(f.id)}</span>
        <span>${esc(f.title)}</span><span class="cat">${esc(f.category)}</span></summary>
      <dl class="finding-body">
        <dt>Description</dt><dd>${esc(f.description)}</dd>
        <dt>Evidence</dt><dd><pre>${esc(f.evidence)}</pre></dd>
        <dt>Recommendation</dt><dd>${esc(f.recommendation)}</dd>
        ${f.reference ? `<dt>Reference</dt><dd>${esc(f.reference)}</dd>` : ""}
      </dl></details>`).join("");
  }).join("");

  const id = r.id;
  return `
  <div class="report-head">
    <div>
      <h1>${esc(r.domain)}</h1>
      <div class="meta">
        <span>${esc(formatDate(r.started_at))}</span>
        <span>Duration ${esc(r.duration_ms)} ms</span>
        <span>Resolver ${esc((r.resolver || []).join(", "))}</span>
      </div>
    </div>
    <div class="actions">
      <a class="btn small" href="#" data-download="/api/analyses/${id}/report.json" data-filename="dnsinspector-${id}.json">JSON</a>
      <a class="btn small" href="#" data-download="/api/analyses/${id}/report.pdf" data-filename="dnsinspector-${id}.pdf">PDF</a>
      <button class="btn small danger" data-delete="${id}">Delete</button>
    </div>
  </div>

  <div class="cards">
    ${auditCard("SPF", r.spf, spfDetail(r.spf))}
    ${auditCard("DKIM", r.dkim, dkimDetail(r.dkim))}
    ${auditCard("DMARC", r.dmarc, dmarcDetail(r.dmarc))}
    ${auditCard("DNSSEC", r.dnssec, dnssecDetail(r.dnssec))}
    ${r.mta_sts ? auditCard("MTA-STS", r.mta_sts, mtaStsDetail(r.mta_sts)) : ""}
    ${r.bimi ? auditCard("BIMI", r.bimi, bimiDetail(r.bimi)) : ""}
  </div>

  <h2>Findings by severity</h2>
  <div class="sev-bar">${sevBar}</div>

  <h2>Priority recommendations</h2>
  ${prioritiesHtml}

  <h2>Findings <small>(${r.summary.total})</small></h2>
  ${findings || `<p class="note">No findings.</p>`}

  <h2>DNS records</h2>
  ${recordsTable(Object.values(r.records))}

  <h2>Authoritative name servers <small>(${esc(r.nameservers?.status || "not checked")})</small></h2>
  ${nameserversTable(r.nameservers)}

  <p class="note">${esc(r.dkim?.note || "")} ${esc(r.dnssec?.note || "")}</p>`;
}

function recordsTable(results) {
  const rows = results.map((q) => `<tr>
    <td><strong>${esc(q.rtype)}</strong></td>
    <td class="status-${esc(q.status)}">${esc(q.status)}</td>
    <td class="values">${q.records.length ? q.records.map((v) => `<div>${esc(v)}</div>`).join("") : `<span class="status-nodata">${esc(q.error || "—")}</span>`}</td>
    <td class="num">${q.ttl ?? "—"}</td>
    <td class="num">${esc(q.nameserver || "—")}</td>
    <td class="num">${esc(q.elapsed_ms)} ms</td>
  </tr>`).join("");
  return `<div class="table-wrap"><table>
    <thead><tr><th>Type</th><th>Status</th><th>Values</th><th>TTL</th><th>Server</th><th>Time</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

// tabla con la respuesta de cada servidor autoritativo
function nameserversTable(ns) {
  if (!ns?.servers?.length) return `<p class="note">Name servers were not checked in this analysis.</p>`;
  const cls = (status) => (status === "ok" ? "status-ok" : status === "not_checked" ? "status-nodata" : "status-error");
  const rows = ns.servers.map((s) => `<tr>
    <td class="mono">${esc(s.ns)}</td>
    <td class="mono">${esc(s.ip || "—")}</td>
    <td class="${cls(s.status)}">${esc(s.status.replace("_", " "))}</td>
    <td class="values">${esc(s.serial ?? s.error ?? (s.rcode ? `${s.rcode}, AA=${s.aa ? 1 : 0}` : "—"))}</td>
    <td class="values">${esc(s.primary || "—")}</td>
    <td class="num">${s.elapsed_ms != null ? `${esc(s.elapsed_ms)} ms` : "—"}</td>
  </tr>`).join("");
  return `<div class="table-wrap"><table>
    <thead><tr><th>Name server</th><th>Address</th><th>Status</th><th>SOA serial</th><th>Primary</th><th>Time</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

// --- consulta DNS suelta ---

$("#lookup-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const name = $("#lookup-name").value.trim();
  if (!name) return showError("#lookup-error", "Enter a domain or an IP address");
  showError("#lookup-error", "");
  const button = event.target.querySelector("button[type=submit]");
  button.disabled = true;
  $("#lookup-result").innerHTML = loading("Querying…");
  try {
    const params = new URLSearchParams({ name, type: $("#lookup-type").value });
    const data = await api(`/api/lookup?${params}`);
    const title = data.kind === "ptr" ? `PTR for ${data.query}` : data.query;
    $("#lookup-result").innerHTML = `<h2>${esc(title)}</h2>${recordsTable(data.results)}`;
  } catch (err) {
    $("#lookup-result").innerHTML = "";
    showError("#lookup-error", err.message);
  } finally {
    button.disabled = false;
  }
});

// --- historial ---

const selected = new Set();

$("#history-form").addEventListener("submit", (event) => {
  event.preventDefault();
  loadHistory();
});

$("#compare-btn").addEventListener("click", () => {
  const [a, b] = [...selected];
  location.hash = `#/compare/${a}/${b}`;
});

async function loadHistory() {
  const box = $("#history-result");
  const domain = $("#history-domain").value.trim();
  selected.clear();
  updateCompareButton();
  showError("#history-error", "");
  box.innerHTML = loading("Loading history…");
  try {
    const items = await api(`/api/analyses?${new URLSearchParams(domain ? { domain } : {})}`);
    if (!items.length) {
      box.innerHTML = `<div class="state">No analyses yet. Run one from the Analyze tab.</div>`;
      return;
    }
    box.innerHTML = `<div class="table-wrap"><table>
      <thead><tr><th></th><th>Date</th><th>Domain</th><th>Highest</th>
      ${SEVERITIES.map((s) => `<th class="num">${s}</th>`).join("")}<th class="num">Duration</th><th></th></tr></thead>
      <tbody>${items.map(historyRow).join("")}</tbody></table></div>
      <p class="note">Select two analyses of the same domain to compare them.</p>`;
    bindHistory(box, items);
  } catch (err) {
    box.innerHTML = "";
    showError("#history-error", err.message);
  }
}

function historyRow(item) {
  const highest = item.highest_severity
    ? `<span class="sev-${item.highest_severity}"><span class="sev-tag">${esc(item.highest_severity)}</span></span>`
    : "—";
  return `<tr class="clickable" data-id="${item.id}">
    <td><input type="checkbox" aria-label="Select analysis ${item.id}" data-select="${item.id}"></td>
    <td>${esc(formatDate(item.created_at))}</td>
    <td class="mono">${esc(item.domain)}</td>
    <td>${highest}</td>
    ${SEVERITIES.map((s) => `<td class="num">${item.counts[s]}</td>`).join("")}
    <td class="num">${esc(item.duration_ms)} ms</td>
    <td><button class="btn small danger" data-delete-row="${item.id}">Delete</button></td>
  </tr>`;
}

function bindHistory(box, items) {
  const domains = Object.fromEntries(items.map((i) => [i.id, i.domain]));
  box.querySelectorAll("tr[data-id]").forEach((row) => {
    row.addEventListener("click", (e) => {
      if (e.target.closest("input, button")) return;
      location.hash = `#/analysis/${row.dataset.id}`;
    });
  });
  box.querySelectorAll("[data-select]").forEach((box2) => {
    box2.addEventListener("change", () => {
      const id = Number(box2.dataset.select);
      box2.checked ? selected.add(id) : selected.delete(id);
      const ids = [...selected];
      const sameDomain = ids.length === 2 && domains[ids[0]] === domains[ids[1]];
      updateCompareButton(sameDomain, ids.length === 2 && !sameDomain);
    });
  });
  box.querySelectorAll("[data-delete-row]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!confirm("Delete this analysis from the history?")) return;
      try {
        await api(`/api/analyses/${btn.dataset.deleteRow}`, { method: "DELETE" });
        loadHistory();
      } catch (err) {
        showError("#history-error", err.message);
      }
    });
  });
}

function updateCompareButton(enabled = false, differentDomains = false) {
  $("#compare-btn").disabled = !enabled;
  showError("#history-error", differentDomains ? "Only analyses of the same domain can be compared" : "");
}

// --- comparar dos analisis ---

async function showCompare(a, b) {
  const view = $("#view-detail");
  view.innerHTML = loading("Comparing…");
  try {
    const d = await api(`/api/compare?${new URLSearchParams({ a, b })}`);
    const statusRows = Object.entries(d.statuses).map(([key, s]) => `<tr>
      <td><strong>${esc(key.toUpperCase())}</strong></td><td>${esc(s.before)}</td><td>${esc(s.after)}</td>
      <td>${s.changed ? '<span class="pill warn">changed</span>' : '<span class="pill neutral">same</span>'}</td></tr>`).join("");
    const recordRows = Object.entries(d.records)
      .filter(([, r]) => r.added.length || r.removed.length)
      .map(([type, r]) => `<tr><td><strong>${esc(type)}</strong></td><td class="values">
        ${r.added.map((v) => `<div class="diff-add">+ ${esc(v)}</div>`).join("")}
        ${r.removed.map((v) => `<div class="diff-del">− ${esc(v)}</div>`).join("")}</td></tr>`).join("");
    const findingList = (list, empty) => list.length
      ? `<ol class="priorities">${list.map((f) => `<li class="sev-${f.severity}"><span class="sev-tag">${esc(f.severity)}</span>
          <span><small>${esc(f.id)}</small> ${esc(f.title)}</span></li>`).join("")}</ol>`
      : `<p class="note">${empty}</p>`;

    view.innerHTML = `<a href="#/history" class="btn small">← History</a>
      <div class="report-head"><div><h1>${esc(d.domain)}</h1>
        <div class="meta"><span>Before: <a href="#/analysis/${d.before.id}">#${d.before.id}</a> ${esc(formatDate(d.before.started_at))}</span>
        <span>After: <a href="#/analysis/${d.after.id}">#${d.after.id}</a> ${esc(formatDate(d.after.started_at))}</span></div></div></div>
      <h2>Check status</h2>
      <div class="table-wrap"><table><thead><tr><th>Check</th><th>Before</th><th>After</th><th></th></tr></thead>
        <tbody>${statusRows}</tbody></table></div>
      <div class="two-col">
        <div><h2>New findings</h2>${findingList(d.findings.new, "No new findings.")}</div>
        <div><h2>Resolved findings</h2>${findingList(d.findings.resolved, "No resolved findings.")}</div>
      </div>
      <h2>Record changes</h2>
      ${recordRows ? `<div class="table-wrap"><table><thead><tr><th>Type</th><th>Change</th></tr></thead><tbody>${recordRows}</tbody></table></div>`
        : `<p class="note">No DNS record changes.</p>`}`;
  } catch (err) {
    view.innerHTML = `<a href="#/history" class="btn small">← History</a><div class="state">${esc(err.message)}</div>`;
  }
}

router();
