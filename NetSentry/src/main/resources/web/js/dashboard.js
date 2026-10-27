(() => {
  const NS = window.NetSentry;
  NS.renderDashboard = function (result) {
    document.getElementById("metric-records").textContent = result
      ? NS.fmt(result.totalRecords)
      : "—";
    document.getElementById("metric-records-foot").textContent = result
      ? `${NS.fmt(result.acceptedRecords)} accepted · ${NS.fmt(result.rejectedRecords)} rejected`
      : "Awaiting first analysis";
    document.getElementById("metric-alerts").textContent = result
      ? NS.fmt(result.alertCount)
      : "—";
    document.getElementById("metric-alerts-foot").textContent = result
      ? `${NS.fmt(result.severityCounts?.HIGH)} high · ${NS.fmt(result.severityCounts?.MEDIUM)} medium · ${NS.fmt(result.severityCounts?.LOW)} low`
      : "Heuristic alerts generated";
    document.getElementById("metric-rejected").textContent = result
      ? NS.fmt(result.rejectedRecords)
      : "—";
    document.getElementById("metric-rejected-foot").textContent = result
      ? `${NS.fmt(result.acceptedRecords)} records passed validation`
      : "Input validation results";
    document.getElementById("metric-duration").textContent = result
      ? `${Number(result.durationMs || 0).toLocaleString()} ms`
      : "—";
    document.getElementById("metric-duration-foot").textContent = result
      ? `${Number(result.recordsPerSecond || 0).toLocaleString(undefined, { maximumFractionDigits: 0 })} records/sec`
      : "Processing time";
    document.getElementById("last-analysis").textContent = result
      ? `Last run: ${NS.fmtDate(result.analysisTimestamp)} · ${result.datasetName}`
      : "No analysis performed";
    document.getElementById("nav-alert-count").textContent = NS.fmt(
      result ? result.alertCount : 0,
    );
    const tbody = document.getElementById("recent-alerts");
    tbody.replaceChildren();
    const alerts = result?.alerts || [];
    if (!alerts.length) {
      tbody.innerHTML = `<tr><td colspan="6" class="empty-cell">${result ? "No alerts were generated for this dataset." : "No analysis data available yet."}</td></tr>`;
    } else
      alerts.slice(0, 6).forEach((a) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `<td><span class="severity-pill ${NS.esc(a.severity)}">${NS.esc(a.severity)}</span></td><td class="rule-name">${NS.esc(a.ruleName)}</td><td class="ip-cell">${NS.esc(a.srcIp)}</td><td class="ip-cell">${NS.esc(a.dstIp)}</td><td class="metric-cell">${NS.esc(a.observedMetric)} ${NS.esc(a.metricName)}</td><td>${NS.esc(NS.fmtDate(a.detectionTimestamp))}</td>`;
        tr.addEventListener("click", () => {
          NS.navigate("alerts");
          NS.selectAlert?.(a.id);
        });
        tbody.appendChild(tr);
      });
    this.drawTrend(result?.trafficTrend || []);
    this.drawSeverity(result?.severityCounts || { HIGH: 0, MEDIUM: 0, LOW: 0 });
  };
  NS.drawTrend = function (points) {
    const canvas = document.getElementById("traffic-chart"),
      empty = document.getElementById("traffic-chart-empty");
    const ctx = canvas.getContext("2d");
    const rect = canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.max(1, rect.width * dpr);
    canvas.height = Math.max(1, rect.height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const w = rect.width,
      h = rect.height;
    ctx.clearRect(0, 0, w, h);
    if (!points.length || !w || !h) {
      empty.classList.remove("hidden");
      return;
    }
    empty.classList.add("hidden");
    const pad = { l: 27, r: 10, t: 12, b: 25 },
      cw = w - pad.l - pad.r,
      ch = h - pad.t - pad.b;
    const max = Math.max(1, ...points.map((p) => p.connections));
    ctx.strokeStyle = "#263946";
    ctx.lineWidth = 1;
    ctx.fillStyle = "#8295a5";
    ctx.font = "9px DM Sans, sans-serif";
    for (let i = 0; i < 4; i++) {
      const y = pad.t + (ch * i) / 3;
      ctx.beginPath();
      ctx.moveTo(pad.l, y);
      ctx.lineTo(w - pad.r, y);
      ctx.stroke();
      ctx.fillText(Math.round(max * (1 - i / 3)), 1, y + 3);
    }
    const gap = cw / Math.max(1, points.length);
    const barW = Math.max(3, Math.min(28, gap * 0.52));
    points.forEach((p, i) => {
      const bh = Math.max(2, (ch * p.connections) / max),
        x = pad.l + i * gap + (gap - barW) / 2,
        y = pad.t + ch - bh;
      const grad = ctx.createLinearGradient(0, y, 0, pad.t + ch);
      grad.addColorStop(0, "#4cd7e9");
      grad.addColorStop(1, "#24667a");
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.roundRect(x, y, barW, bh, [3, 3, 0, 0]);
      ctx.fill();
    });
    const stride = Math.max(1, Math.ceil(points.length / 5));
    ctx.fillStyle = "#8195a4";
    points.forEach((p, i) => {
      if (i % stride === 0 || i === points.length - 1) {
        const label = new Date(p.bucket).toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          hour12: false,
        });
        ctx.fillText(label, Math.min(w - pad.r - 34, pad.l + i * gap), h - 6);
      }
    });
  };
  NS.drawSeverity = function (counts) {
    const host = document.getElementById("severity-chart");
    const high = Number(counts.HIGH || 0),
      med = Number(counts.MEDIUM || 0),
      low = Number(counts.LOW || 0),
      total = high + med + low;
    host.replaceChildren();
    if (!total) {
      const empty = document.createElement("div");
      empty.className = "chart-empty inline";
      empty.textContent = "No alerts to display.";
      host.appendChild(empty);
      return;
    }
    const ring = document.createElement("div");
    ring.className = "severity-ring";
    const highP = (high / total) * 100,
      medP = (med / total) * 100;
    ring.style.background = `conic-gradient(var(--red) 0 ${highP}%, var(--orange) ${highP}% ${highP + medP}%, var(--green) ${highP + medP}% 100%)`;
    ring.innerHTML = `<div class="severity-ring-label"><strong>${NS.fmt(total)}</strong><small>ALERTS</small></div>`;
    host.appendChild(ring);
  };
  NS.renderReports = function (result) {
    const host = document.getElementById("report-summary"),
      badge = document.getElementById("report-badge");
    badge.textContent = result ? "LATEST RUN" : "NO REPORT";
    document.getElementById("download-json").disabled = !result;
    document.getElementById("download-csv").disabled = !result;
    if (!result) {
      host.className = "report-placeholder";
      host.textContent =
        "No report is available yet. Run an analysis to generate one.";
      return;
    }
    host.className = "";
    host.innerHTML = `<div class="report-summary-grid"><div class="report-metric"><span>Total records</span><strong>${NS.fmt(result.totalRecords)}</strong></div><div class="report-metric"><span>Accepted</span><strong>${NS.fmt(result.acceptedRecords)}</strong></div><div class="report-metric"><span>Rejected</span><strong>${NS.fmt(result.rejectedRecords)}</strong></div><div class="report-metric"><span>Alerts</span><strong>${NS.fmt(result.alertCount)}</strong></div></div><div class="report-meta"><span><strong>Dataset:</strong> ${NS.esc(result.datasetName)}</span><span><strong>Analyzed:</strong> ${NS.esc(NS.fmtDate(result.analysisTimestamp))}</span><span><strong>Duration:</strong> ${NS.esc(result.durationMs)} ms</span><span><strong>Throughput:</strong> ${NS.esc(Math.round(result.recordsPerSecond || 0))} records/sec</span></div>`;
  };
  document.addEventListener("DOMContentLoaded", () => {
    document
      .getElementById("download-json")
      .addEventListener("click", async () => {
        try {
          const data = await NS.api("/api/reports/latest");
          const blob = new Blob([JSON.stringify(data, null, 2)], {
            type: "application/json",
          });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = "netsentry-report.json";
          a.click();
          URL.revokeObjectURL(url);
        } catch (e) {
          NS.toast(e.message, true);
        }
      });
    document.getElementById("download-csv").addEventListener("click", () => {
      window.location.href = "/api/reports/latest.csv";
    });
    window.addEventListener("resize", () => {
      if (NS.result) NS.drawTrend(NS.result.trafficTrend || []);
    });
  });
})();
