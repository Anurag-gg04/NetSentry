(() => {
  const NS = window.NetSentry;
  let selectedFile = null;
  let busy = false;
  const input = () => document.getElementById("file-input");
  function setFile(file) {
    const error = document.getElementById("analysis-error");
    error.classList.add("hidden");
    error.textContent = "";
    if (!file) {
      selectedFile = null;
      document.getElementById("selected-file").classList.add("hidden");
      document.getElementById("drop-zone").classList.remove("hidden");
      document.getElementById("upload-analyze").disabled = true;
      return;
    }
    const name = file.name.toLowerCase();
    if (!(name.endsWith(".csv") || name.endsWith(".json"))) {
      showError("Choose a .csv or .json file.");
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      showError("File exceeds the 10 MiB limit.");
      return;
    }
    selectedFile = file;
    document.getElementById("selected-file-name").textContent = file.name;
    document.getElementById("selected-file-size").textContent =
      `${(file.size / 1024).toFixed(1)} KiB`;
    document.getElementById("selected-file").classList.remove("hidden");
    document.getElementById("drop-zone").classList.add("hidden");
    document.getElementById("upload-analyze").disabled = false;
  }
  function showError(message) {
    const el = document.getElementById("analysis-error");
    el.textContent = message;
    el.classList.remove("hidden");
    NS.toast(message, true);
  }
  async function runUpload() {
    if (!selectedFile || busy) return;
    busy = true;
    const btn = document.getElementById("upload-analyze");
    btn.disabled = true;
    btn.textContent = "Analyzing…";
    try {
      const type = selectedFile.name.toLowerCase().endsWith(".json")
        ? "application/json"
        : "text/csv";
      const result = await NS.api(
        `/api/analyze?filename=${encodeURIComponent(selectedFile.name)}`,
        {
          method: "POST",
          headers: { "Content-Type": type },
          body: selectedFile,
        },
      );
      NS.setResult(result);
      document.getElementById("result-status").textContent = "COMPLETED";
      NS.toast(`Analysis completed · ${result.alertCount} alert(s)`);
      if (result.rejectedRecords)
        NS.toast(
          `Analysis completed with ${result.rejectedRecords} rejected record(s).`,
        );
    } catch (e) {
      showError(e.message);
    } finally {
      busy = false;
      btn.disabled = !selectedFile;
      btn.innerHTML = "Analyze uploaded file <span>→</span>";
    }
  }
  async function runSample() {
    if (busy) return;
    const name = document.getElementById("sample-select").value;
    if (!name) {
      showError("Select a sample dataset first.");
      return;
    }
    busy = true;
    const btn = document.getElementById("sample-analyze");
    btn.disabled = true;
    btn.textContent = "Analyzing sample…";
    document.getElementById("analysis-error").classList.add("hidden");
    try {
      const result = await NS.api("/api/analyze/sample", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sample: name }),
      });
      NS.setResult(result);
      document.getElementById("result-status").textContent = "COMPLETED";
      NS.toast(`Sample analyzed · ${result.alertCount} alert(s)`);
      if (result.rejectedRecords)
        NS.toast(
          `Validation rejected ${result.rejectedRecords} sample record(s).`,
        );
    } catch (e) {
      showError(e.message);
    } finally {
      busy = false;
      btn.disabled = false;
      btn.innerHTML = "Analyze selected sample <span>→</span>";
    }
  }
  NS.populateSamples = function (samples) {
    const select = document.getElementById("sample-select");
    select.replaceChildren();
    const empty = document.createElement("option");
    empty.value = "";
    empty.textContent = "Select a sample dataset";
    select.appendChild(empty);
    samples.forEach((s) => {
      const o = document.createElement("option");
      o.value = s.name;
      o.textContent = s.name;
      o.dataset.description = s.description;
      select.appendChild(o);
    });
    document.getElementById("sample-description").textContent = samples.length
      ? "Choose a synthetic scenario. All bundled data is generated for this project."
      : "No samples returned by backend.";
  };
  NS.renderAnalysisResult = function (r) {
    const host = document.getElementById("analysis-result-content");
    if (!r) {
      host.className = "result-placeholder";
      host.textContent =
        "Results will appear here after a dataset is analyzed.";
      return;
    }
    host.className = "";
    host.innerHTML = `<div class="result-stats"><div class="result-stat"><span>Accepted</span><strong>${NS.fmt(r.acceptedRecords)}</strong></div><div class="result-stat"><span>Rejected</span><strong>${NS.fmt(r.rejectedRecords)}</strong></div><div class="result-stat"><span>Alerts</span><strong>${NS.fmt(r.alertCount)}</strong></div></div><p class="result-foot">Dataset: ${NS.esc(r.datasetName)} · ${NS.esc(r.durationMs)} ms · ${NS.esc(NS.fmtDate(r.analysisTimestamp))}</p>${r.validationErrors?.length ? `<div class="detail-block"><h3>Validation messages (first ${r.validationErrors.length})</h3><ul class="recommendations">${r.validationErrors.map((e) => `<li>${NS.esc(e)}</li>`).join("")}</ul></div>` : ""}`;
  };
  document.addEventListener("DOMContentLoaded", () => {
    input().addEventListener("change", (e) =>
      setFile(e.target.files?.[0] || null),
    );
    document.getElementById("clear-file").addEventListener("click", () => {
      input().value = "";
      setFile(null);
    });
    document
      .getElementById("upload-analyze")
      .addEventListener("click", runUpload);
    document
      .getElementById("sample-analyze")
      .addEventListener("click", runSample);
    document.getElementById("sample-select").addEventListener("change", (e) => {
      const o = e.target.selectedOptions[0];
      document.getElementById("sample-description").textContent =
        o?.dataset.description ||
        "Synthetic data works offline and is safe to use for demos.";
    });
    const drop = document.getElementById("drop-zone");
    drop.addEventListener("dragover", (e) => {
      e.preventDefault();
      drop.classList.add("dragging");
    });
    drop.addEventListener("dragleave", () => drop.classList.remove("dragging"));
    drop.addEventListener("drop", (e) => {
      e.preventDefault();
      drop.classList.remove("dragging");
      setFile(e.dataTransfer.files?.[0] || null);
    });
  });
})();
