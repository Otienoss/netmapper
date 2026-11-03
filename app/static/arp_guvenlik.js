"use strict";

const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? "").replace(/[&<>"']/g,
  (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({detail: `HTTP ${response.status}`}));
  if (!response.ok) {
    const detail = data.detail;
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return data;
}

function reportHtml(report) {
  const stats = report.stats || {};
  const alerts = report.alerts || [];
  let html = `<div class="summary"><span class="status ${esc(report.status)}">${esc(report.status)}</span>` +
    `<span>${esc(report.analyzed_packets ?? 0)} ARP olayı · ${alerts.length} uyarı</span></div>`;
  if (stats.requests !== undefined) {
    html += `<div class="evidence mono">request=${esc(stats.requests)} · reply=${esc(stats.replies)} · ` +
      `gratuitous=${esc(stats.gratuitous_replies)} · süre=${esc(stats.capture_duration_sec)}s</div>`;
  }
  if (!alerts.length && report.status === "inconclusive") {
    html += `<div class="note">${esc(stats.reason || "Yeterli kanıt yok; bu 'güvenli' demek değildir.")}</div>`;
  }
  for (const alert of alerts) {
    html += `<div class="alert"><div class="kind ${esc(alert.severity)}">${esc(alert.severity)} · ${esc(alert.kind)}</div>` +
      `<div>${esc(alert.message)}</div>` +
      `<div class="evidence mono">${esc(JSON.stringify(alert.evidence || {}))}</div>` +
      `<div class="fix">Öneri: ${esc(alert.recommendation)}</div></div>`;
  }
  return html;
}

function configHtml(report) {
  const summary = report.summary || {};
  let html = `<div class="summary"><span class="status ${esc(report.overall)}">${esc(report.overall)}</span>` +
    `<span>pass=${esc(summary.pass ?? 0)} · fail=${esc(summary.fail ?? 0)} · unknown=${esc(summary.unknown ?? 0)}</span></div>`;
  html += "<table><thead><tr><th>Kontrol</th><th>Durum</th><th>Kanıt</th><th>Öneri</th></tr></thead><tbody>";
  for (const finding of report.findings || []) {
    html += `<tr><td class="mono">${esc(finding.control)}</td>` +
      `<td class="${finding.status === "fail" ? "critical" : finding.status === "unknown" ? "medium" : "clean"}">${esc(finding.status)}</td>` +
      `<td>${esc(finding.evidence)}</td><td>${esc(finding.recommendation)}</td></tr>`;
  }
  return html + "</tbody></table>";
}

function errorHtml(target, error) {
  target.innerHTML = `<div class="err">${esc(error.message || error)}</div>`;
}

let currentJob = null;
let finished = false;
let pollTimer = null;
let activeSocket = null;

function renderState(state) {
  const logs = state.logs || [];
  $("logs").innerHTML = logs.length
    ? logs.map((line) => esc(line)).join("<br>") : "[—] Log bekleniyor…";
  $("logs").scrollTop = $("logs").scrollHeight;
  if (state.error) $("logs").innerHTML += `<br><span class="err">${esc(state.error)}</span>`;
  const results = state.results || [];
  if (results.length && results[0]) {
    $("monitor-result").innerHTML = reportHtml(results[0]);
  }
  if (["done", "error"].includes(state.status)) {
    finished = true;
    $("start-btn").disabled = false;
    $("stop-btn").disabled = true;
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }
}

function connectWS(wsUrl) {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  try {
    activeSocket = new WebSocket(`${proto}://${location.host}${wsUrl}`);
  } catch (error) {
    startPolling();
    return;
  }
  activeSocket.onmessage = (event) => {
    try { renderState(JSON.parse(event.data)); }
    catch (error) { console.error("WS payload", error); }
  };
  activeSocket.onclose = () => { if (!finished) startPolling(); };
}

function startPolling() {
  if (pollTimer || !currentJob || finished) return;
  pollTimer = setInterval(async () => {
    if (!currentJob || finished) { clearInterval(pollTimer); pollTimer = null; return; }
    try {
      const state = await api(`/api/v1/jobs/${currentJob}`);
      renderState(state);
    } catch (error) { /* geçici ağ hatası: sonraki tur */ }
  }, 2000);
}

$("start-btn").addEventListener("click", async () => {
  $("start-btn").disabled = true;
  $("stop-btn").disabled = true;
  $("monitor-result").innerHTML = "";
  $("logs").textContent = "Monitör başlatılıyor…";
  finished = false;
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  currentJob = null;
  if (activeSocket) activeSocket.close();
  try {
    const payload = {
      interface: $("interface").value.trim(),
      gateway_ip: $("gateway_ip").value.trim() || null,
      gateway_mac: $("gateway_mac").value.trim() || null,
      duration_sec: Number($("duration").value),
      max_packets: Number($("max_packets").value),
    };
    const data = await api("/api/v1/arp/monitor/start", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload),
    });
    currentJob = data.job_id;
    $("job-id").textContent = ` · job ${currentJob.slice(0, 12)}…`;
    $("stop-btn").disabled = false;
    connectWS(data.ws_url);
  } catch (error) {
    finished = true;
    $("start-btn").disabled = false;
    errorHtml($("monitor-result"), error);
  }
});

$("stop-btn").addEventListener("click", async () => {
  if (!currentJob) return;
  $("stop-btn").disabled = true;
  try {
    await api(`/api/v1/arp/monitor/stop/${currentJob}`, {method: "POST"});
    $("logs").innerHTML += "<br>Durdurma isteği gönderildi; analiz bekleniyor…";
  } catch (error) {
    $("stop-btn").disabled = false;
    errorHtml($("monitor-result"), error);
  }
});

$("pcap-btn").addEventListener("click", async () => {
  const file = $("pcap-file").files[0];
  if (!file) { errorHtml($("pcap-result"), new Error("Önce bir PCAP dosyası seçin")); return; }
  if (file.size > 25 * 1024 * 1024) {
    errorHtml($("pcap-result"), new Error("PCAP boyut sınırı 25 MiB")); return;
  }
  $("pcap-btn").disabled = true;
  $("pcap-result").innerHTML = "<div class='note'>PCAP analiz ediliyor…</div>";
  try {
    const query = new URLSearchParams();
    if ($("gateway_ip").value.trim()) query.set("gateway_ip", $("gateway_ip").value.trim());
    if ($("gateway_mac").value.trim()) query.set("gateway_mac", $("gateway_mac").value.trim());
    const suffix = query.toString() ? `?${query}` : "";
    const report = await api(`/api/v1/arp/pcap-audit${suffix}`, {
      method: "POST",
      headers: {"Content-Type": "application/octet-stream"},
      body: await file.arrayBuffer(),
    });
    $("pcap-result").innerHTML = reportHtml(report);
  } catch (error) {
    errorHtml($("pcap-result"), error);
  } finally {
    $("pcap-btn").disabled = false;
  }
});

$("config-btn").addEventListener("click", async () => {
  const configText = $("config-text").value.trim();
  if (!configText) { errorHtml($("config-result"), new Error("Konfigürasyon metni gerekli")); return; }
  $("config-btn").disabled = true;
  try {
    const report = await api("/api/v1/arp/config-audit", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        config_text: configText,
        config_complete: $("config-complete").checked,
      }),
    });
    $("config-result").innerHTML = configHtml(report);
  } catch (error) {
    errorHtml($("config-result"), error);
  } finally {
    $("config-btn").disabled = false;
  }
});
