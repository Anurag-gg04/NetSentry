(() => {
  const NS = window.NetSentry;
  let selectedId = null;
  function filtered() {
    let list = [...(NS.alerts || [])];
    const ip =
      document.getElementById("ip-filter")?.value.trim().toLowerCase() || "";
    const sev = document.getElementById("severity-filter")?.value || "";
    const rule = document.getElementById("rule-filter")?.value || "";
    const sort = document.getElementById("sort-filter")?.value || "newest";
    list = list.filter(
      (a) =>
        (!ip ||
          String(a.srcIp || "")
            .toLowerCase()
            .includes(ip) ||
          String(a.dstIp || "")
            .toLowerCase()
            .includes(ip)) &&
        (!sev || a.severity === sev) &&
        (!rule || a.ruleName === rule),
    );
    if (sort === "oldest")
      list.sort(
        (a, b) =>
          new Date(a.detectionTimestamp) - new Date(b.detectionTimestamp),
      );
    else if (sort === "severity") {
      const weight = { HIGH: 3, MEDIUM: 2, LOW: 1 };
      list.sort(
        (a, b) =>
          (weight[b.severity] || 0) - (weight[a.severity] || 0) ||
          new Date(b.detectionTimestamp) - new Date(a.detectionTimestamp),
      );
    } else
      list.sort(
        (a, b) =>
          new Date(b.detectionTimestamp) - new Date(a.detectionTimestamp),
      );
    return list;
  }
  NS.renderAlerts = function () {
    const body = document.getElementById("alerts-table-body");
    if (!body) return;
    const all = filtered();
    body.replaceChildren();
    document.getElementById("alert-summary").textContent =
      `Showing ${all.length} of ${(NS.alerts || []).length} alert(s)`;
    const ruleSelect = document.getElementById("rule-filter");
    const current = ruleSelect.value;
    const rules = [
      ...new Set([
        "Port Scan Detection",
        "Connection Burst Detection",
        "Repeated Failed Connections",
        "Traffic Spike Detection",
        "Host Sweep Detection",
        ...(NS.alerts || []).map((a) => a.ruleName),
      ]),
    ].sort();
    ruleSelect.replaceChildren(new Option("All rules", ""));
    rules.forEach((r) => ruleSelect.add(new Option(r, r)));
    ruleSelect.value = rules.includes(current) ? current : "";
    if (!all.length) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="5" class="empty-cell">${NS.alerts?.length ? "No alerts match these filters." : "No alerts yet. Analyze a dataset first."}</td>`;
      body.appendChild(tr);
      document.getElementById("alert-detail").innerHTML =
        '<div class="detail-empty"><span>⌕</span><strong>No alert selected</strong><p>Try changing filters or run an analysis.</p></div>';
      return;
    }
    all.forEach((a) => {
      const tr = document.createElement("tr");
      tr.dataset.alertId = a.id;
      tr.classList.toggle("selected", a.id === selectedId);
      tr.innerHTML = `<td><span class="severity-pill ${NS.esc(a.severity)}">${NS.esc(a.severity)}</span></td><td class="rule-name">${NS.esc(a.ruleName)}</td><td><span class="ip-cell">${NS.esc(a.srcIp)}</span><br><span class="ip-cell">${NS.esc(a.dstIp)}</span></td><td class="metric-cell">${NS.esc(a.observedMetric)} / ${NS.esc(a.configuredThreshold)}<br><span style="color:#718899;font-size:9px">${NS.esc(a.metricName)}</span></td><td>${NS.esc(NS.fmtDate(a.detectionTimestamp))}</td>`;
      tr.addEventListener("click", () => NS.selectAlert(a.id));
      body.appendChild(tr);
    });
    const selected = all.find((a) => a.id === selectedId) || all[0];
    NS.selectAlert(selected.id, false);
  };
  NS.selectAlert = function (id, rerender = true) {
    selectedId = id;
    const a = (NS.alerts || []).find((x) => x.id === id);
    if (!a) return;
    const detail = document.getElementById("alert-detail");
    detail.innerHTML = `<div class="detail-severity-row"><span class="severity-pill ${NS.esc(a.severity)}">${NS.esc(a.severity)} SEVERITY</span><span class="panel-tag">${NS.esc(a.id.slice(0, 8))}</span></div><h2 class="detail-title">${NS.esc(a.ruleName)}</h2><p class="detail-subtitle">Detected ${NS.esc(NS.fmtDate(a.detectionTimestamp))}</p><div class="detail-block"><h3>Evidence</h3><div class="evidence-grid"><div class="evidence-item"><span>Observed</span><strong>${NS.esc(a.observedMetric)} ${NS.esc(a.metricName)}</strong></div><div class="evidence-item"><span>Threshold</span><strong>${NS.esc(a.configuredThreshold)}</strong></div><div class="evidence-item"><span>Source IP</span><strong>${NS.esc(a.srcIp)}</strong></div><div class="evidence-item"><span>Destination IP</span><strong>${NS.esc(a.dstIp)}</strong></div></div><p style="margin-top:10px">Window: ${NS.esc(NS.fmtDate(a.windowStart))} – ${NS.esc(NS.fmtDate(a.windowEnd))}</p></div><div class="detail-block"><h3>Why this alert was generated</h3><p>${NS.esc(a.explanation)}</p></div><div class="detail-block"><h3>Recommended investigation</h3><ul class="recommendations">${(a.recommendations || []).map((t) => `<li>${NS.esc(t)}</li>`).join("")}</ul></div><div class="detail-block"><button class="primary-btn full-width" id="create-incident-btn">＋ Create incident from this alert</button></div><div class="detail-block"><p style="color:#7f95a4;font-size:10px">This is a heuristic indicator. Validate it with authorized logs and context before responding.</p></div>`;
    document
      .getElementById("create-incident-btn")
      ?.addEventListener("click", () => NS.createIncident?.(a));
    document
      .querySelectorAll("#alerts-table-body tr")
      .forEach((tr) =>
        tr.classList.toggle("selected", tr.dataset.alertId === String(id)),
      );
  };
  document.addEventListener("DOMContentLoaded", () => {
    ["ip-filter", "severity-filter", "rule-filter", "sort-filter"].forEach(
      (id) =>
        document
          .getElementById(id)
          .addEventListener(id === "ip-filter" ? "input" : "change", () =>
            NS.renderAlerts(),
          ),
    );
    document.getElementById("reset-filters").addEventListener("click", () => {
      document.getElementById("ip-filter").value = "";
      document.getElementById("severity-filter").value = "";
      document.getElementById("rule-filter").value = "";
      document.getElementById("sort-filter").value = "newest";
      selectedId = null;
      NS.renderAlerts();
    });
    document
      .getElementById("refresh-alerts")
      .addEventListener("click", async () => {
        try {
          await NS.refreshFromApi();
          NS.toast("Alert list refreshed");
        } catch (e) {
          NS.toast(e.message, true);
        }
      });
  });
})();
