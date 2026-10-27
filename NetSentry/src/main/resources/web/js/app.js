(() => {
  const NS = {
    result: null,
    stats: null,
    alerts: [],
    rules: null,
    samples: [],
    selectedAlert: null,
    pageNames: {
      overview: "Overview",
      analysis: "Traffic analysis",
      alerts: "Alerts explorer",
      hosts: "Host intelligence",
      correlations: "Alert correlations",
      incidents: "Incident desk",
      rules: "Detection rules",
      reports: "Reports",
    },
    async api(url, options = {}) {
      const response = await fetch(url, options);
      const type = response.headers.get("content-type") || "";
      const body = type.includes("json")
        ? await response.json()
        : await response.text();
      if (!response.ok)
        throw new Error(
          body && body.message
            ? body.message
            : `Request failed (${response.status})`,
        );
      return body;
    },
    esc(value) {
      return String(value ?? "—").replace(
        /[&<>"']/g,
        (c) =>
          ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;",
          })[c],
      );
    },
    fmt(value) {
      return new Intl.NumberFormat("en-IN").format(Number(value || 0));
    },
    fmtDate(value) {
      if (!value) return "—";
      const d = new Date(value);
      return Number.isNaN(d.getTime())
        ? String(value)
        : d.toLocaleString([], {
            month: "short",
            day: "2-digit",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
            hour12: false,
          });
    },
    toast(message, bad = false) {
      const node = document.getElementById("toast");
      if (!node) return;
      node.textContent = message;
      node.style.borderColor = bad ? "#86414a" : "#38616c";
      node.style.background = bad ? "#2a171d" : "#152b34";
      node.classList.add("show");
      clearTimeout(this.toastTimer);
      this.toastTimer = setTimeout(() => node.classList.remove("show"), 3200);
    },
    navigate(page) {
      if (!this.pageNames[page]) return;
      document
        .querySelectorAll(".page")
        .forEach((el) =>
          el.classList.toggle("active", el.id === `page-${page}`),
        );
      document
        .querySelectorAll(".nav-item")
        .forEach((el) =>
          el.classList.toggle("active", el.dataset.page === page),
        );
      document.getElementById("page-crumb").textContent = this.pageNames[page];
      document.getElementById("sidebar").classList.remove("open");
      if (page === "alerts" && this.renderAlerts) this.renderAlerts();
      if (page === "rules" && this.renderRules && this.rules)
        this.renderRules(this.rules);
      if (page === "reports" && this.renderReports)
        this.renderReports(this.result);
      if (page === "hosts" && this.renderHosts) this.renderHosts();
      if (page === "correlations" && this.renderCorrelations)
        this.renderCorrelations();
      if (page === "incidents" && this.loadIncidents) this.loadIncidents();
    },
    setResult(result) {
      this.result = result;
      this.stats = result;
      this.alerts = Array.isArray(result.alerts) ? result.alerts : [];
      document.getElementById("nav-alert-count").textContent = this.fmt(
        this.alerts.length,
      );
      document
        .getElementById("first-run-banner")
        .classList.toggle("hidden", true);
      if (this.renderDashboard) this.renderDashboard(result);
      if (this.renderAlerts) this.renderAlerts();
      if (this.renderHosts) this.renderHosts();
      if (this.renderCorrelations) this.renderCorrelations();
      if (this.renderAnalysisResult) this.renderAnalysisResult(result);
      if (this.renderReports) this.renderReports(result);
    },
    async refreshFromApi() {
      const [stats, alerts] = await Promise.all([
        this.api("/api/stats"),
        this.api("/api/alerts"),
      ]);
      this.alerts = alerts;
      if (stats.status !== "empty") {
        const report = await this.api("/api/reports/latest");
        this.setResult(report);
      } else {
        this.stats = stats;
        document.getElementById("first-run-banner").classList.remove("hidden");
        if (this.renderDashboard) this.renderDashboard(null);
        if (this.renderAlerts) this.renderAlerts();
        if (this.renderReports) this.renderReports(null);
      }
    },
    async init() {
      try {
        const health = await this.api("/api/health");
        document.getElementById("engine-status").textContent =
          `Connected · v${health.version}`;
        document.getElementById("version-label").textContent =
          `v${health.version}`;
        this.rules = await this.api("/api/rules");
        this.samples = await this.api("/api/samples");
        if (this.renderRules) this.renderRules(this.rules);
        if (this.populateSamples) this.populateSamples(this.samples);
        await this.refreshFromApi();
        if (this.loadIncidents) await this.loadIncidents();
      } catch (error) {
        document.getElementById("engine-status").textContent =
          "API connection unavailable";
        this.toast(`Backend connection failed: ${error.message}`, true);
      }
    },
  };
  window.NetSentry = NS;
  document.addEventListener("DOMContentLoaded", () => {
    document
      .querySelectorAll(".nav-item")
      .forEach((button) =>
        button.addEventListener("click", () =>
          NS.navigate(button.dataset.page),
        ),
      );
    document
      .querySelectorAll("[data-go]")
      .forEach((button) =>
        button.addEventListener("click", () => NS.navigate(button.dataset.go)),
      );
    document
      .getElementById("mobile-menu")
      .addEventListener("click", () =>
        document.getElementById("sidebar").classList.toggle("open"),
      );
    NS.init();
  });
})();
