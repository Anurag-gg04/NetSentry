(() => {
  const NS = window.NetSentry;

  const definitions = [
    {
      key: "portScan",
      name: "Port Scan Detection",
      symbol: "⌁",
      description:
        "Finds a source contacting many destination ports on one target within a time window.",
      metric: "Unique destination ports",
      window: "windowSeconds",
    },
    {
      key: "connectionBurst",
      name: "Connection Burst Detection",
      symbol: "↗",
      description:
        "Flags a high number of flow records from one source within a time window.",
      metric: "Flow records per source",
      window: "windowSeconds",
    },
    {
      key: "failedConnections",
      name: "Repeated Failed Connections",
      symbol: "⊘",
      description:
        "Counts failed connection records between one source and one destination.",
      metric: "Failed connection records",
      window: "windowSeconds",
    },
    {
      key: "trafficSpike",
      name: "Traffic Spike Detection",
      symbol: "⌁",
      description:
        "Compares a time bucket with the median count of other observed buckets.",
      metric: "Flows in a time bucket",
      window: "bucketSeconds",
    },
    {
      key: "hostSweep",
      name: "Host Sweep Detection",
      symbol: "⌖",
      description:
        "Finds a source contacting many different destination hosts in a short window.",
      metric: "Unique destination hosts",
      window: "windowSeconds",
    },
  ];

  NS.renderRules = function (config) {
    if (!config) return;

    const host = document.getElementById("rules-grid");
    host.replaceChildren();

    definitions.forEach((rule) => {
      const settings = config[rule.key] || {};
      const card = document.createElement("article");
      const enabled = Boolean(settings.enabled);
      const extraMetric =
        rule.key === "trafficSpike"
          ? `<div class="rule-value"><span>Baseline multiplier</span><strong>${NS.esc(settings.baselineMultiplier ?? 2)}×</strong></div>`
          : "";

      card.className = "panel rule-card";
      card.innerHTML = `
                <div class="rule-card-top">
                    <span class="rule-symbol">${rule.symbol}</span>
                    <div>
                        <h2>${rule.name}</h2>
                        <p>${rule.description}</p>
                    </div>
                    <span class="enabled-pill ${enabled ? "" : "disabled"}">
                        ${enabled ? "Enabled" : "Disabled"}
                    </span>
                </div>
                <div class="rule-values">
                    <div class="rule-value">
                        <span>Threshold</span>
                        <strong>${NS.esc(settings.threshold)}</strong>
                    </div>
                    <div class="rule-value">
                        <span>${rule.window === "bucketSeconds" ? "Bucket size" : "Time window"}</span>
                        <strong>${NS.esc(settings[rule.window])} sec</strong>
                    </div>
                    <div class="rule-value">
                        <span>Severity</span>
                        <strong>${NS.esc(settings.severity)}</strong>
                    </div>
                    ${extraMetric}
                </div>
                <p class="rule-policy">Main metric: ${rule.metric}. To change thresholds, edit the config file and restart NetSentry.</p>
            `;
      host.appendChild(card);
    });

    const allowlist = document.getElementById("allowlist-values");
    allowlist.replaceChildren();
    (config.allowlist || []).forEach((ip) => {
      const item = document.createElement("code");
      item.textContent = ip;
      allowlist.appendChild(item);
    });
    if (!(config.allowlist || []).length) {
      allowlist.textContent = "No source IPs are allowlisted.";
    }
    document.getElementById("rules-loaded").textContent = "CONFIG LOADED";

    const ruleFilter = document.getElementById("rule-filter");
    if (ruleFilter) {
      const selectedRule = ruleFilter.value;
      ruleFilter.replaceChildren(new Option("All rules", ""));
      definitions.forEach((rule) =>
        ruleFilter.add(new Option(rule.name, rule.name)),
      );
      ruleFilter.value = selectedRule;
    }
  };
})();
