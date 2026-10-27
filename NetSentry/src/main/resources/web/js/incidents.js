(() => {
  const NS = window.NetSentry;
  const STATUS_LABELS = {
    OPEN: "Open",
    INVESTIGATING: "Investigating",
    RESOLVED: "Resolved",
    FALSE_POSITIVE: "False positive",
  };
  let incidents = [];
  let selectedIncidentId = null;
  const el = (id) => document.getElementById(id);
  NS.renderHosts = function () {
    const alerts = NS.alerts || [];
    const hosts = new Map();
    const add = (ip, role, alert) => {
      if (!ip || ip === "—") return;
      if (!hosts.has(ip))
        hosts.set(ip, {
          ip,
          roles: new Set(),
          alerts: [],
          rules: new Set(),
          high: 0,
          last: "",
        });
      const h = hosts.get(ip);
      h.roles.add(role);
      h.alerts.push(alert);
      h.rules.add(alert.ruleName);
      if (alert.severity === "HIGH") h.high++;
      if (!h.last || new Date(alert.detectionTimestamp) > new Date(h.last))
        h.last = alert.detectionTimestamp;
    };
    alerts.forEach((a) => {
      add(a.srcIp, "Source", a);
      add(a.dstIp, "Destination", a);
    });
    const values = [...hosts.values()].sort(
      (a, b) => b.alerts.length - a.alerts.length || a.ip.localeCompare(b.ip),
    );
    el("host-count").textContent = NS.fmt(values.length);
    el("host-source-count").textContent = NS.fmt(
      values.filter((h) => h.roles.has("Source")).length,
    );
    el("host-destination-count").textContent = NS.fmt(
      values.filter((h) => h.roles.has("Destination")).length,
    );
    el("host-high-count").textContent = NS.fmt(
      alerts.filter((a) => a.severity === "HIGH").length,
    );
    const body = el("hosts-table-body");
    body.replaceChildren();
    const q = (el("host-search")?.value || "").trim().toLowerCase();
    const shown = values.filter((h) => !q || h.ip.toLowerCase().includes(q));
    if (!shown.length) {
      body.innerHTML = `<tr><td colspan="6" class="empty-cell">${alerts.length ? "No hosts match this search." : "Analyze a dataset to populate host intelligence."}</td></tr>`;
      return;
    }
    shown.forEach((h) => {
      const tr = document.createElement("tr");
      tr.className = "clickable-row";
      tr.innerHTML = `<td class="ip-cell">${NS.esc(h.ip)}</td><td>${NS.esc([...h.roles].join(" / "))}</td><td>${h.alerts.length}</td><td>${h.high}</td><td>${NS.esc([...h.rules].join(", "))}</td><td>${NS.esc(NS.fmtDate(h.last))}</td>`;
      tr.addEventListener("click", () => showHost(h));
      body.appendChild(tr);
    });
  };
  function showHost(host) {
    const detail = el("host-detail");
    const related = host.alerts
      .slice()
      .sort(
        (a, b) =>
          new Date(b.detectionTimestamp) - new Date(a.detectionTimestamp),
      );
    detail.innerHTML = `<div class="panel-heading"><div><h2>${NS.esc(host.ip)}</h2><p class="muted">${NS.esc([...host.roles].join(" and "))} · ${host.alerts.length} related alert(s)</p></div><button class="secondary-btn" id="host-open-alerts">View alerts</button></div><div class="report-summary-grid"><div class="report-metric"><span>High severity</span><strong>${host.high}</strong></div><div class="report-metric"><span>Unique rules</span><strong>${host.rules.size}</strong></div><div class="report-metric"><span>Latest activity</span><strong>${NS.esc(NS.fmtDate(host.last))}</strong></div></div><div class="table-scroll"><table><thead><tr><th>Severity</th><th>Rule</th><th>Peer IP</th><th>Observed</th><th>Timestamp</th></tr></thead><tbody>${related.map((a) => `<tr><td><span class="severity-pill ${NS.esc(a.severity)}">${NS.esc(a.severity)}</span></td><td>${NS.esc(a.ruleName)}</td><td class="ip-cell">${NS.esc(a.srcIp === host.ip ? a.dstIp : a.srcIp)}</td><td>${NS.esc(a.observedMetric)} ${NS.esc(a.metricName)}</td><td>${NS.esc(NS.fmtDate(a.detectionTimestamp))}</td></tr>`).join("")}</tbody></table></div><p class="helper-text">Host information is inferred from alert endpoints only. It does not establish ownership, compromise, or complete network activity.</p>`;
    el("host-open-alerts").addEventListener("click", () => {
      NS.navigate("alerts");
      el("ip-filter").value = host.ip;
      NS.renderAlerts();
    });
  }
  NS.loadIncidents = async function () {
    try {
      incidents = await NS.api("/api/incidents");
    } catch (e) {
      incidents = [];
      NS.toast(`Could not load incidents: ${e.message}`, true);
    }
    NS.renderIncidents();
  };
  NS.renderIncidents = function () {
    el("nav-incident-count").textContent = NS.fmt(incidents.length);
    el("incident-total").textContent = NS.fmt(incidents.length);
    el("incident-open").textContent = NS.fmt(
      incidents.filter((i) => i.status === "OPEN").length,
    );
    el("incident-investigating").textContent = NS.fmt(
      incidents.filter((i) => i.status === "INVESTIGATING").length,
    );
    el("incident-closed").textContent = NS.fmt(
      incidents.filter((i) => ["RESOLVED", "FALSE_POSITIVE"].includes(i.status))
        .length,
    );
    const filter = el("incident-status-filter")?.value || "";
    const body = el("incidents-table-body");
    body.replaceChildren();
    const shown = incidents.filter((i) => !filter || i.status === filter);
    if (!shown.length) {
      body.innerHTML = `<tr><td colspan="7" class="empty-cell">${incidents.length ? "No incidents match this status." : "No incidents yet. Open an alert and choose Create incident."}</td></tr>`;
      el("incident-editor-content").textContent = "No incident selected.";
      return;
    }
    shown.forEach((i) => {
      const tr = document.createElement("tr");
      tr.className = "clickable-row";
      tr.classList.toggle("selected", i.id === selectedIncidentId);
      tr.innerHTML = `<td><span class="severity-pill ${NS.esc(i.severity)}">${NS.esc(i.severity)}</span></td><td>${NS.esc(i.title)}</td><td class="ip-cell">${NS.esc(i.srcIp)}</td><td><span class="status-pill status-${NS.esc(i.status)}">${NS.esc(STATUS_LABELS[i.status] || i.status)}</span></td><td>${NS.esc(i.assignedTo || "Unassigned")}</td><td>${NS.esc(NS.fmtDate(i.updatedAt))}</td><td><button class="icon-btn incident-delete" title="Delete incident" aria-label="Delete incident">×</button></td>`;
      tr.addEventListener("click", (e) => {
        if (e.target.closest(".incident-delete")) return;
        selectedIncidentId = i.id;
        NS.renderIncidents();
      });
      tr.querySelector(".incident-delete").addEventListener(
        "click",
        async (e) => {
          e.stopPropagation();
          if (!confirm("Delete this incident permanently?")) return;
          try {
            await NS.api(`/api/incidents/${encodeURIComponent(i.id)}`, {
              method: "DELETE",
            });
            incidents = incidents.filter((x) => x.id !== i.id);
            if (selectedIncidentId === i.id) selectedIncidentId = null;
            NS.renderIncidents();
            NS.toast("Incident deleted");
          } catch (err) {
            NS.toast(err.message, true);
          }
        },
      );
      body.appendChild(tr);
    });
    const selected = shown.find((i) => i.id === selectedIncidentId) || shown[0];
    selectedIncidentId = selected.id;
    renderIncidentEditor(selected);
  };
  function renderIncidentEditor(i) {
    el("incident-editor-content").innerHTML =
      `<form id="incident-edit-form" class="incident-form"><div class="detail-severity-row"><span class="severity-pill ${NS.esc(i.severity)}">${NS.esc(i.severity)}</span><span class="panel-tag">${NS.esc(i.id.slice(0, 8))}</span></div><h3>${NS.esc(i.title)}</h3><p class="muted">${NS.esc(i.ruleName)} · ${NS.esc(i.srcIp)} → ${NS.esc(i.dstIp)}</p><label class="field-label" for="edit-status">Status</label><select class="select-field" id="edit-status"><option value="OPEN">Open</option><option value="INVESTIGATING">Investigating</option><option value="RESOLVED">Resolved</option><option value="FALSE_POSITIVE">False positive</option></select><label class="field-label" for="edit-assignee">Assigned to</label><input class="text-input" id="edit-assignee" maxlength="100" value="${NS.esc(i.assignedTo || "")}" placeholder="Analyst name"><label class="field-label" for="edit-notes">Investigation notes</label><textarea class="text-input notes-input" id="edit-notes" maxlength="5000" placeholder="Evidence checked, findings, next steps…">${NS.esc(i.notes || "")}</textarea><p class="helper-text">Created ${NS.esc(NS.fmtDate(i.createdAt))}</p><button class="primary-btn full-width" type="submit">Save case updates</button><div class="muted" id="incident-save-status" role="status"></div></form>`;
    el("edit-status").value = i.status;
    el("incident-edit-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const button = e.currentTarget.querySelector('button[type="submit"]');
      button.disabled = true;
      try {
        const updated = await NS.api(
          `/api/incidents/${encodeURIComponent(i.id)}`,
          {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              status: el("edit-status").value,
              assignedTo: el("edit-assignee").value,
              notes: el("edit-notes").value,
            }),
          },
        );
        incidents = incidents.map((x) => (x.id === updated.id ? updated : x));
        NS.renderIncidents();
        NS.toast("Incident updated");
      } catch (err) {
        el("incident-save-status").textContent = err.message;
        NS.toast(err.message, true);
        button.disabled = false;
      }
    });
  }
  NS.createIncident = async function (alert) {
    try {
      const existing = incidents.find(
        (i) =>
          i.alertId === alert.id &&
          !["RESOLVED", "FALSE_POSITIVE"].includes(i.status),
      );
      if (existing) {
        NS.navigate("incidents");
        selectedIncidentId = existing.id;
        await NS.loadIncidents();
        NS.toast("An active incident already exists for this alert");
        return;
      }
      const created = await NS.api("/api/incidents", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alertId: alert.id }),
      });
      incidents.unshift(created);
      selectedIncidentId = created.id;
      NS.navigate("incidents");
      NS.renderIncidents();
      NS.toast("Incident created");
    } catch (e) {
      NS.toast(`Could not create incident: ${e.message}`, true);
    }
  };
  document.addEventListener("DOMContentLoaded", () => {
    el("host-search").addEventListener("input", () => NS.renderHosts());
    el("refresh-hosts").addEventListener("click", async () => {
      try {
        await NS.refreshFromApi();
        NS.renderHosts();
        NS.toast("Host intelligence refreshed");
      } catch (e) {
        NS.toast(e.message, true);
      }
    });
    el("refresh-incidents").addEventListener("click", () => NS.loadIncidents());
    el("incident-status-filter").addEventListener("change", () =>
      NS.renderIncidents(),
    );
  });
})();
