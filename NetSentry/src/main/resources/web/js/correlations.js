(() => {
  const NS = window.NetSentry;
  let selectedId = null;
  let current = [];
  const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  NS.renderCorrelations = async function () {
    const body = document.getElementById("correlations-table-body");
    if (!body) return;
    body.innerHTML =
      '<tr><td colspan="6" class="empty-cell">Loading correlated alerts…</td></tr>';
    try {
      current = await NS.api("/api/correlations");
      current.sort(
        (a, b) =>
          (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0) ||
          b.alertCount - a.alertCount,
      );
      body.replaceChildren();
      document.getElementById("correlation-summary").textContent =
        `${current.length} correlated source host(s) · a source must trigger at least two different rules`;
      if (!current.length) {
        const row = document.createElement("tr");
        row.innerHTML =
          '<td colspan="6" class="empty-cell">No multi-rule correlations found. Analyze a dataset with related alerts to populate this view.</td>';
        body.appendChild(row);
        document.getElementById("correlation-detail").innerHTML =
          '<div class="detail-empty"><span>✓</span><strong>No correlated alerts</strong><p>This does not prove the network is safe; it only means the current dataset did not meet the correlation rule.</p></div>';
        return;
      }
      current.forEach((item) => {
        const row = document.createElement("tr");
        row.dataset.id = item.id;
        row.classList.toggle("selected", item.id === selectedId);
        row.innerHTML = `<td><span class="severity-pill ${NS.esc(item.severity)}">${NS.esc(item.severity)}</span></td><td class="ip-cell">${NS.esc(item.sourceIp)}</td><td>${NS.esc(item.alertCount)}</td><td>${NS.esc(item.ruleNames.join(", "))}</td><td>${NS.esc(NS.fmtDate(item.firstSeen))}</td><td>${NS.esc(NS.fmtDate(item.lastSeen))}</td>`;
        row.addEventListener("click", () => select(item.id));
        body.appendChild(row);
      });
      select(
        current.some((x) => x.id === selectedId) ? selectedId : current[0].id,
      );
    } catch (error) {
      body.innerHTML = `<tr><td colspan="6" class="empty-cell">${NS.esc(error.message)}</td></tr>`;
    }
  };
  function select(id) {
    selectedId = id;
    const item = current.find((x) => x.id === id);
    if (!item) return;
    document
      .querySelectorAll("#correlations-table-body tr")
      .forEach((row) =>
        row.classList.toggle("selected", row.dataset.id === id),
      );
    document.getElementById("correlation-detail").innerHTML =
      `<div class="detail-severity-row"><span class="severity-pill ${NS.esc(item.severity)}">${NS.esc(item.severity)} PRIORITY</span><span class="panel-tag">${NS.esc(item.alertCount)} ALERTS</span></div><h2 class="detail-title">Source host ${NS.esc(item.sourceIp)}</h2><p class="detail-subtitle">${NS.esc(item.summary)}</p><div class="detail-block"><h3>Correlated detection rules</h3><ul class="recommendations">${item.ruleNames.map((rule) => `<li>${NS.esc(rule)}</li>`).join("")}</ul></div><div class="detail-block"><h3>Recommended investigation</h3><p>${NS.esc(item.recommendedAction)}</p></div><div class="detail-block"><button class="primary-btn full-width" id="view-correlated-alerts">View related alerts</button></div>`;
    document
      .getElementById("view-correlated-alerts")
      ?.addEventListener("click", () => {
        NS.navigate("alerts");
        const filter = document.getElementById("ip-filter");
        if (filter) {
          filter.value = item.sourceIp;
          NS.renderAlerts();
        }
      });
  }
  document.addEventListener("DOMContentLoaded", () => {
    document
      .getElementById("refresh-correlations")
      ?.addEventListener("click", () => NS.renderCorrelations());
  });
})();
