"use strict";

const POLL_MS = 1000;
const HIST_BINS = 60;          // last 60 minutes
const HIST_BIN_MS = 60_000;    // 1-minute bins

// ───────── helpers ─────────
const el = (id) => document.getElementById(id);

function fmt(n, digits = 0) {
  if (n === null || n === undefined || Number.isNaN(n)) return "—";
  if (Math.abs(n) >= 1_000_000) return (n / 1_000_000).toFixed(2) + "M";
  if (Math.abs(n) >= 1_000)     return (n / 1_000).toFixed(2) + "k";
  return Number(n).toLocaleString(undefined, { maximumFractionDigits: digits });
}
function fmtUptime(s) {
  s = Math.floor(s || 0);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${sec}s`;
  return `${sec}s`;
}
function fmtTime(ns) {
  if (!ns) return "—";
  const d = new Date(ns / 1_000_000);
  const pad = (n) => String(n).padStart(2, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
function fmtClock(ts_ms) {
  const d = new Date(ts_ms);
  const pad = (n) => String(n).padStart(2, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
function severity(z) {
  const a = Math.abs(z);
  if (a >= 6.0) return "high";
  if (a >= 4.5) return "med";
  return "low";
}
// Prefer the classifier's Korean severity (present on all new alerts); fall back
// to the z-score band for older rows. Behavioural alerts have z=0 so this is the
// only way to colour them correctly.
function sevClass(a) {
  switch (a.severity) {
    case "심각": return "high";
    case "경고": return "med";
    case "주의": return "low";
    case "관심": return "low";
    default:     return severity(a.z_score);
  }
}
function isBehavioral(a) {
  return a.baseline_std === 0 && a.baseline_mean === 0;
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
async function jget(url) {
  const r = await fetch(url, { cache: "no-store" });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
}

// ───────── state ─────────
const STATE = {
  alerts: [],
  expanded: new Set(),
  filterSev: "all",
};

// ───────── filter chips ─────────
document.querySelectorAll(".chip").forEach((b) => {
  b.addEventListener("click", () => {
    document.querySelectorAll(".chip").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    STATE.filterSev = b.dataset.sev;
    renderAlerts(STATE.alerts);
  });
});

// ───────── renderers ─────────
function setPill(state, warmupRemaining) {
  const pill = el("pill-state");
  pill.classList.remove("ok", "warm", "error");
  if (state === "error")   { pill.classList.add("error"); pill.textContent = "오류"; return; }
  if (warmupRemaining > 0) { pill.classList.add("warm");  pill.textContent = `워밍업 ${warmupRemaining}`; return; }
  pill.classList.add("ok"); pill.textContent = "정상 감시중";
}

function renderStatus(s) {
  const stateLabel = s.last_error ? "error" : (s.running ? "ok" : "stopped");
  setPill(stateLabel, s.warmup_remaining);
  el("meta-iface").textContent = (s.interface || "—").replace(/\\Device\\NPF_/, "");
  el("meta-iface").title = s.interface || "";
  el("meta-filter").textContent = s.bpf_filter || "—";
  el("meta-uptime").textContent = `${fmtUptime(s.uptime_s)} · ${fmt(s.packets_seen)} pkts`;
  el("meta-window").textContent = `${(s.window_seconds || 1).toFixed(1)}s`;

  // KPI: live throughput
  const cw = s.current_window || {};
  const dur = cw.duration_s || s.window_seconds || 1;
  el("kpi-pps").textContent = fmt((cw.packet_count || 0) / dur);
  el("kpi-pps-sub").textContent =
    `${fmt((cw.bytes_total || 0) / dur)} B/s · ${fmt(cw.unique_dst_ips || 0)} dst`;

  // KPI: total
  const total = s.alert_total || 0;
  el("kpi-total").textContent = fmt(total);
  const totalKpi = el("kpi-total").closest(".kpi");
  totalKpi.dataset.tone = total > 0 ? "warn" : "neutral";
  el("kpi-total-sub").textContent = total > 0 ? "since service start" : "no anomalies yet";

  // warmup footer note
  const note = el("warmup-note");
  if (s.warmup_remaining > 0) {
    note.textContent = `기준선 학습 중 — ${s.warmup_remaining} window 남음`;
  } else if (s.last_error) {
    note.textContent = `오류: ${s.last_error}`;
  } else {
    note.textContent = `보호 중 · alert ${total}건`;
  }

  // live talkers
  renderBars("bars-src",  cw.top_src_ips || {},  (k) => k);
  renderBars("bars-dst",  cw.top_dst_ips || {},  (k) => k);
  renderBars("bars-port", cw.top_dst_ports || {}, (k) => `:${k}`);
  renderProtoMix(cw);
  el("live-sub").textContent = cw.window_start_ns
    ? `at ${fmtTime(cw.window_end_ns)} · ${fmt(cw.packet_count || 0)} pkts`
    : "current window";
}

function renderBars(elemId, dict, labelFn) {
  const wrap = el(elemId);
  const entries = Object.entries(dict);
  if (entries.length === 0) {
    wrap.innerHTML = `<div class="bar-empty">데이터 없음</div>`;
    return;
  }
  const max = Math.max(...entries.map(([, v]) => v), 1);
  wrap.innerHTML = "";
  for (const [k, v] of entries) {
    const pct = ((v / max) * 100).toFixed(1);
    const row = document.createElement("div");
    row.className = "bar-row";
    row.innerHTML = `
      <div class="label mono" style="--w:${pct}%" title="${escapeHtml(String(k))}">
        <span>${escapeHtml(labelFn(k))}</span>
      </div>
      <div class="count mono">${fmt(v)}</div>
    `;
    wrap.appendChild(row);
  }
}

function renderProtoMix(cw) {
  const wrap = el("protomix");
  const total = (cw.tcp_count || 0) + (cw.udp_count || 0) + (cw.icmp_count || 0) + (cw.other_count || 0);
  if (!total) {
    wrap.innerHTML = `<div class="bar-empty" style="padding:4px 8px">no traffic</div>`;
    return;
  }
  const pct = (n) => ((n / total) * 100).toFixed(2);
  wrap.innerHTML = `
    <div class="protomix-seg tcp"   style="width:${pct(cw.tcp_count)}%"></div>
    <div class="protomix-seg udp"   style="width:${pct(cw.udp_count)}%"></div>
    <div class="protomix-seg icmp"  style="width:${pct(cw.icmp_count)}%"></div>
    <div class="protomix-seg other" style="width:${pct(cw.other_count)}%"></div>
  `;
  // legend (re-render once)
  let legend = wrap.parentElement.querySelector(".protomix-legend");
  if (!legend) {
    legend = document.createElement("div");
    legend.className = "protomix-legend";
    legend.innerHTML = `
      <span><i class="swatch" style="background:#6ea8fe"></i>TCP</span>
      <span><i class="swatch" style="background:#34d399"></i>UDP</span>
      <span><i class="swatch" style="background:#fbbf24"></i>ICMP</span>
      <span><i class="swatch" style="background:#94a3b8"></i>OTHER</span>
    `;
    wrap.parentElement.appendChild(legend);
  }
  legend.querySelectorAll("span").forEach((span, i) => {
    const counts = [cw.tcp_count, cw.udp_count, cw.icmp_count, cw.other_count];
    const labels = ["TCP", "UDP", "ICMP", "OTHER"];
    span.lastChild.nodeValue = ` ${labels[i]} ${pct(counts[i])}%`;
  });
}

function renderHistogram(alerts) {
  const wrap = el("histogram");
  const axis = el("hist-axis");
  const now = Date.now();
  const bins = new Array(HIST_BINS).fill(0).map(() => ({ count: 0, maxSev: null }));
  const start = now - HIST_BINS * HIST_BIN_MS;

  let last1h = 0, last24h = 0;
  for (const a of alerts) {
    const t = a.timestamp_ns / 1_000_000;
    if (now - t <= 86_400_000) last24h += 1;
    if (now - t <= 3_600_000)  last1h  += 1;
    const idx = Math.floor((t - start) / HIST_BIN_MS);
    if (idx >= 0 && idx < HIST_BINS) {
      const sev = sevClass(a);
      bins[idx].count += 1;
      const order = { low: 0, med: 1, high: 2 };
      if (bins[idx].maxSev === null || order[sev] > order[bins[idx].maxSev]) {
        bins[idx].maxSev = sev;
      }
    }
  }

  const maxCount = Math.max(1, ...bins.map((b) => b.count));
  wrap.innerHTML = "";
  bins.forEach((b) => {
    const div = document.createElement("div");
    div.className = "hist-bar" + (b.maxSev ? ` sev-${b.maxSev}` : "");
    const h = b.count === 0 ? 2 : Math.max(2, (b.count / maxCount) * 100);
    div.style.height = `${h}%`;
    div.title = b.count > 0 ? `${b.count} alert${b.count > 1 ? "s" : ""}` : "";
    wrap.appendChild(div);
  });

  axis.innerHTML = "";
  for (let i = 0; i <= 6; i++) {
    const t = start + (HIST_BINS * HIST_BIN_MS * i / 6);
    const span = document.createElement("span");
    span.textContent = fmtClock(t);
    axis.appendChild(span);
  }

  // KPI updates from alerts
  el("kpi-1h").textContent = fmt(last1h);
  el("kpi-24h").textContent = fmt(last24h);
  const k1h = el("kpi-1h").closest(".kpi");
  k1h.dataset.tone = last1h > 5 ? "crit" : (last1h > 0 ? "warn" : "neutral");
  el("kpi-1h-sub").textContent = last1h === 0 ? "no anomalies" : "anomalies in last 60 min";

  const featCounts = {};
  for (const a of alerts) {
    if (now - a.timestamp_ns / 1_000_000 > 3_600_000) continue;
    featCounts[a.feature] = (featCounts[a.feature] || 0) + 1;
  }
  const sorted = Object.entries(featCounts).sort((a, b) => b[1] - a[1]);
  if (sorted.length > 0) {
    el("kpi-feature").textContent = sorted[0][0];
    el("kpi-feature-sub").textContent = `${sorted[0][1]}건 · 최근 1시간`;
  } else {
    el("kpi-feature").textContent = "—";
    el("kpi-feature-sub").textContent = "no recent alerts";
  }
}

function renderAlerts(alerts) {
  STATE.alerts = alerts;
  const tbody = el("alerts-tbody");
  const sub = el("alerts-sub");
  let shown = alerts;
  if (STATE.filterSev !== "all") {
    shown = alerts.filter((a) => sevClass(a) === STATE.filterSev);
  }
  if (shown.length === 0) {
    const empty = STATE.filterSev === "all"
      ? "아직 알림이 없습니다. 워밍업이 끝나면 이상치가 여기 표시됩니다."
      : `해당 심각도(${STATE.filterSev.toUpperCase()})의 알림이 없습니다.`;
    tbody.innerHTML = `<tr class="empty-row"><td colspan="6">${empty}</td></tr>`;
    sub.textContent = STATE.filterSev === "all" ? "정상 동작 중" : "필터 적용중";
    return;
  }

  sub.textContent = `${shown.length} / 전체 ${alerts.length}건`;
  tbody.innerHTML = "";
  for (const a of shown) {
    const sev = sevClass(a);
    const behav = isBehavioral(a);
    const expanded = STATE.expanded.has(a.id);
    const tr = document.createElement("tr");
    tr.dataset.alertId = a.id;
    const topSrc = behav
      ? (a.context?.new_destination || "—")
      : (Object.keys(a.context?.top_src_ips || {})[0] || "—");
    const zCell = behav
      ? "—"
      : `${a.z_score >= 0 ? "+" : ""}${a.z_score.toFixed(2)}σ`;
    const valCell = behav
      ? fmt(a.value, 0)
      : `${fmt(a.value, 1)} <span style="color:var(--text-faint)">/</span> ${fmt(a.baseline_mean, 1)} ±${fmt(a.baseline_std, 1)}`;
    tr.innerHTML = `
      <td class="col-time mono">${fmtTime(a.timestamp_ns)}</td>
      <td class="col-sev"><span class="sev-badge ${sev}">${escapeHtml(a.severity || sev.toUpperCase())}</span></td>
      <td class="col-feat">
        <div>${escapeHtml(a.category || a.feature)}</div>
        <div class="mono" style="font-size:11px;color:var(--text-faint)">${escapeHtml(a.feature)}</div>
      </td>
      <td class="col-z mono ${a.z_score >= 0 ? "z-pos" : "z-neg"}">${zCell}</td>
      <td class="col-val mono">${valCell}</td>
      <td class="col-src mono">${escapeHtml(topSrc)}</td>
    `;
    tr.addEventListener("click", () => toggleExpand(a.id));
    tbody.appendChild(tr);

    if (expanded) {
      tbody.appendChild(buildDetailRow(a, sev));
    }
  }
}

function toggleExpand(id) {
  if (STATE.expanded.has(id)) STATE.expanded.delete(id);
  else STATE.expanded.add(id);
  renderAlerts(STATE.alerts);
}

function buildDetailRow(a, sev) {
  const tr = document.createElement("tr");
  tr.className = "alert-detail-row";
  const ctx = a.context || {};

  const barList = (dict, fmtKey) => {
    const entries = Object.entries(dict || {});
    if (entries.length === 0) return `<div class="bar-empty">—</div>`;
    const max = Math.max(...entries.map(([, v]) => v), 1);
    return entries.slice(0, 5).map(([k, v]) => {
      const pct = ((v / max) * 100).toFixed(1);
      return `
        <div class="bar-row">
          <div class="label mono" style="--w:${pct}%" title="${escapeHtml(String(k))}">
            <span>${escapeHtml(fmtKey(k))}</span>
          </div>
          <div class="count mono">${fmt(v)}</div>
        </div>`;
    }).join("");
  };

  tr.innerHTML = `
    <td colspan="6">
      <div class="alert-detail sev-${sev}">
        <div class="detail-block full">
          <div class="detail-title">쉬운 설명</div>
          <div class="detail-text">${escapeHtml(a.summary || a.explanation)}</div>
          ${a.recommendation ? `<div class="detail-text" style="margin-top:6px;font-weight:600">→ 권장: ${escapeHtml(a.recommendation)}</div>` : ""}
        </div>
        <div class="detail-block full">
          <div class="detail-title">기술 상세 (전문가용)</div>
          <div class="detail-text" style="color:var(--text-dim)">${escapeHtml(a.explanation)}</div>
        </div>
        <div class="detail-block">
          <div class="detail-title">Top source IPs</div>
          <div class="bars">${barList(ctx.top_src_ips, (k) => k)}</div>
        </div>
        <div class="detail-block">
          <div class="detail-title">Top destination IPs</div>
          <div class="bars">${barList(ctx.top_dst_ips, (k) => k)}</div>
        </div>
        <div class="detail-block">
          <div class="detail-title">Top destination ports</div>
          <div class="bars">${barList(ctx.top_dst_ports, (k) => `:${k}`)}</div>
        </div>
        <div class="detail-block full">
          <div class="detail-title">Stats</div>
          <div class="detail-text mono" style="font-size:11px;color:var(--text-dim)">
            id #${a.id} · ${new Date(a.timestamp_ns / 1_000_000).toISOString().replace("T", " ").slice(0, 19)}
            · feature: <strong>${escapeHtml(a.feature)}</strong>
            · current: <strong>${fmt(a.value, 2)}</strong>
            · baseline: <strong>${fmt(a.baseline_mean, 2)}</strong> ±${fmt(a.baseline_std, 2)}
            · z-score: <strong>${a.z_score >= 0 ? "+" : ""}${a.z_score.toFixed(3)}</strong>
            · direction: <strong>${a.direction}</strong>
          </div>
        </div>
      </div>
    </td>
  `;
  return tr;
}

// ───────── tick ─────────
async function tick() {
  try {
    const [status, alerts] = await Promise.all([
      jget("/api/status"),
      jget("/api/alerts?limit=200"),
    ]);
    renderStatus(status);
    renderHistogram(alerts);
    renderAlerts(alerts);
  } catch (e) {
    console.error(e);
    const pill = el("pill-state");
    pill.classList.remove("ok", "warm");
    pill.classList.add("error");
    pill.textContent = "API 연결 실패";
  }
}

tick();
setInterval(tick, POLL_MS);
