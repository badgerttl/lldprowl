(function () {
  const API = "/api";
  let logPage = 1;
  let logRequestSequence = 0;
  const logPerPage = 20;
  const refreshIntervalMs = 4000;
  let pingTargets = [];
  let refreshInFlight = false;
  let refreshTimer = null;

  function el(id) {
    return document.getElementById(id);
  }

  async function apiFetch(path, options = {}) {
    const r = await fetch(API + path, {
      headers: { "Content-Type": "application/json", ...options.headers },
      ...options,
    });
    if (!r.ok) throw new Error(await r.text());
    return r;
  }

  async function fetchJson(path, options = {}) {
    const r = await apiFetch(path, options);
    return r.json();
  }

  async function loadInterfaces() {
    const list = await fetchJson("/interfaces");
    const select = el("interface-select");
    const current = await fetchJson("/interface").then((d) => d.interface);
    select.innerHTML = "";
    list.forEach((iface) => {
      const opt = document.createElement("option");
      opt.value = iface.name;
      opt.textContent = iface.name;
      if (iface.name === current) opt.selected = true;
      select.appendChild(opt);
    });
  }

  const localPortFieldDefinitions = [
    ["Interface", "name"],
    ["IP Address", "ipv4"],
    ["Subnet", "netmask"],
    ["Gateway", "default_gateway"],
    ["Network", "network_address"],
    ["Broadcast", "broadcast"],
    ["Speed", "speed"],
    ["Duplex", "duplex"],
    ["MTU", "mtu"],
  ];

  function renderLocalPortFields(data = {}) {
    const rows = localPortFieldDefinitions.map(([label, key]) => {
      const value = data[key];
      return [label, value != null && value !== "" ? value : "—"];
    });
    el("local-port-fields").innerHTML = rows
      .map(([label, value]) =>
        `<div class="row"><span class="label">${escapeHtml(label)}</span><span>${escapeHtml(String(value))}</span></div>`)
      .join("");
    return rows;
  }

  function renderLinkState(state = {}) {
    const span = el("link-state");
    if (typeof state.connected !== "boolean") {
      span.textContent = "Unknown";
      span.className = "link-state";
      return;
    }
    span.textContent = state.connected ? "Connected" : "Not connected";
    span.className = "link-state " + (state.connected ? "connected" : "disconnected");
  }

  async function saveInterface() {
    const iface = el("interface-select").value;
    await apiFetch("/interface", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ interface: iface }),
    });
    await loadLocalPort();
  }

  let lastInterfaceConnected = undefined;
  let lastInterfaceIp = "";
  let lastPingTargets = "";  // joined "ip|ip|..." so we run ping when targets change
  let lastLocalCardKey = null;
  let lastConnectedCardKey = null;

  function flashCard(cardId) {
    const card = el(cardId);
    if (!card) return;
    card.classList.remove("card-flash");
    void card.offsetWidth;
    card.classList.add("card-flash");
    setTimeout(() => card.classList.remove("card-flash"), 600);
  }

  async function loadLocalPort() {
    try {
      const d = await fetchJson("/interface/details");
      renderLinkState(d);
      const targets = pingTargets;
      const targetsKey = (targets || []).join("|");

      const hasIp = d.ipv4 && d.ipv4 !== "—";
      if (d.connected && hasIp) {
        const shouldPing = lastInterfaceConnected === false ||
          lastInterfaceConnected === undefined ||
          lastInterfaceIp !== d.ipv4 ||
          lastPingTargets !== targetsKey;
        if (shouldPing && targets.length) {
          try {
            await apiFetch("/ping/run", { method: "POST" });
          } catch (_) {}
          lastInterfaceIp = d.ipv4;
          lastInterfaceConnected = true;
          lastPingTargets = targetsKey;
        }
      } else {
        lastInterfaceConnected = false;
        lastInterfaceIp = "";
        lastPingTargets = "";
      }

      const rows = renderLocalPortFields(d);
      const localKey = rows.map((r) => r[1]).join("|");
      if (lastLocalCardKey !== null && localKey !== lastLocalCardKey) flashCard("local-interface-card");
      lastLocalCardKey = localKey;

      // Ping results under Ping IPs: pass green, fail red (cleared when interface is down)
      const pingResultsEl = el("local-ping-results");
      if (!d.connected) {
        pingResultsEl.innerHTML = "";
      } else {
        let pingHtml = "—";
        try {
          if (!targets.length) {
            pingResultsEl.innerHTML = pingHtml;
            return;
          }
          const status = await fetchJson("/ping/status");
          const parts = (targets || []).map((ip) => {
            const res = status[ip];
            const ok = res && res.success === true;
            const resultClass = ok ? "ping-pass" : "ping-fail";
            const resultText = ok ? "pass" : "fail";
            return "<div class=\"ping-result\">" + escapeHtml(ip) + ": <span class=\"" +
              resultClass + "\">" + resultText + "</span></div>";
          });
          if (parts.length) pingHtml = parts.join("");
        } catch (_) {}
        pingResultsEl.innerHTML = pingHtml;
      }
    } catch (e) {
      lastLocalCardKey = null;
      renderLinkState();
      renderLocalPortFields();
      el("local-ping-results").innerHTML = "";
    }
  }

  async function loadCurrentPort() {
    try {
      const data = await fetchJson("/current");
      const container = el("current-port-fields");
      if (!data || Object.keys(data).length === 0) {
        if (lastConnectedCardKey !== null) flashCard("connected-switch-card");
        lastConnectedCardKey = "";
        container.innerHTML = '<div class="row"><span class="label">—</span> No LLDP or CDP data yet. Start sniff.</div>';
        return;
      }
      const sysDesc = (data.system_description || "").slice(0, 60) + ((data.system_description || "").length > 60 ? "…" : "");
      const rows = [
        ["Protocol", data.protocol || "—"],
        ["Sys Name", data.system_name],
        ["Sys Desc", sysDesc],
        ["Mgmt Addr", data.management_address || "—"],
        ["Port ID", data.port_id],
        ["Port Desc", data.port_description],
        ["VLAN", data.vlan_id != null && data.vlan_id !== "" ? data.vlan_id : "—"],
        ["VLAN Name", data.vlan_name || "—"],
        ["Observed Tags", data.observed_vlan_tags || "—"],
        ["MAC", data.switch_mac != null && data.switch_mac !== "" ? data.switch_mac : "—"],
        ["Chassis", data.chassis_id],
        ["Caps", data.caps != null && data.caps !== "" ? data.caps : "—"],
      ];
      const connectedKey = rows.map((r) => r[1]).join("|");
      if (lastConnectedCardKey !== null && connectedKey !== lastConnectedCardKey) flashCard("connected-switch-card");
      lastConnectedCardKey = connectedKey;
      container.innerHTML = rows
        .map(([label, val]) => {
          const content = label === "Observed Tags"
            ? formatObservedTags(val)
            : escapeHtml(String(val || "—"));
          return `<div class="row"><span class="label">${label}</span><span>${content}</span></div>`;
        })
        .join("");
      // Notes are never refreshed from the server; only change when the user types or clicks Save.
    } catch (e) {
      lastConnectedCardKey = null;
      el("current-port-fields").innerHTML = '<div class="row"><span class="label">—</span> No data.</div>';
    }
  }

  function escapeHtml(s) {
    if (s == null || s === undefined) return "";
    const div = document.createElement("div");
    div.textContent = String(s).replace(/\r?\n/g, " ");
    return div.innerHTML;
  }

  function formatSavedPingResults(value) {
    if (!value || value === "—") return "—";
    const results = String(value).split(",").map((part) => {
      const text = part.trim();
      const separator = text.lastIndexOf(":");
      if (separator < 1) return escapeHtml(text);
      const target = text.slice(0, separator).trim();
      const result = text.slice(separator + 1).trim().toLowerCase();
      const resultClass = result === "pass" ? "history-ping-pass" :
        result === "fail" ? "history-ping-fail" : "";
      return "<span class=\"history-ping " + resultClass + "\">" +
        escapeHtml(target) + ": " + escapeHtml(result) + "</span>";
    }).join("");
    return "<span class=\"history-ping-list\">" + results + "</span>";
  }

  function formatObservedTags(value) {
    if (!value || value === "—") return "—";
    const tags = String(value).split(",")
      .map((tag) => tag.trim())
      .filter(Boolean)
      .map((tag) => `<span class="observed-tag">${escapeHtml(tag)}</span>`)
      .join("");
    return tags ? `<span class="observed-tag-list">${tags}</span>` : "—";
  }

  function summarizePingResults(value) {
    if (!value || value === "—") return "—";
    let passed = 0;
    let failed = 0;
    let other = 0;
    String(value).split(",").forEach((part) => {
      const result = part.slice(part.lastIndexOf(":") + 1).trim().toLowerCase();
      if (result === "pass") passed++;
      else if (result === "fail") failed++;
      else other++;
    });
    const parts = [];
    if (passed) parts.push(`<span class="ping-summary-pass">${passed} pass</span>`);
    if (failed) parts.push(`<span class="ping-summary-fail">${failed} fail</span>`);
    if (other) parts.push(`<span>${other} other</span>`);
    return parts.length ? `<span class="ping-summary">${parts.join("")}</span>` : "—";
  }

  function summarizeObservedTags(value) {
    if (!value || value === "—") return "No tags";
    const tags = String(value).split(",").map((tag) => tag.trim()).filter(Boolean);
    return tags.length ? `Tags: ${tags.join(", ")}` : "No tags";
  }

  function historySummary(primary, secondary) {
    return `<span class="history-summary-value">${escapeHtml(primary || "—")}</span>` +
      `<span class="history-summary-meta">${escapeHtml(secondary || "—")}</span>`;
  }

  function historyDetail(label, value, extraClass = "") {
    return `<div class="history-detail-item ${extraClass}">` +
      `<span class="history-detail-label">${escapeHtml(label)}</span>` +
      `<span class="history-detail-value">${value}</span></div>`;
  }

  async function saveNote() {
    const note = el("port-notes").value.trim();
    try {
      await apiFetch("/notes", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ note }),
      });
      el("port-notes").value = "";
      loadCurrentPort();
      loadLogPage();
    } catch (e) {
      console.error(e);
    }
  }

  async function sniffStart() {
    try {
      await apiFetch("/sniff/start", { method: "POST" });
      const startBtn = el("sniff-start-btn");
      const stopBtn = el("sniff-stop-btn");
      if (startBtn) startBtn.disabled = true;
      if (stopBtn) stopBtn.disabled = false;
    } catch (e) {
      console.error(e);
    }
  }

  async function sniffStop() {
    try {
      await apiFetch("/sniff/stop", { method: "POST" });
      const startBtn = el("sniff-start-btn");
      const stopBtn = el("sniff-stop-btn");
      if (startBtn) startBtn.disabled = false;
      if (stopBtn) stopBtn.disabled = true;
      loadCurrentPort();
    } catch (e) {
      console.error(e);
    }
  }

  async function loadPingTargets() {
    const data = await fetchJson("/ping-targets");
    const ips = data.ips || [];
    pingTargets = ips;
    el("ping-ips").value = ips.join(", ");
  }

  async function savePingTargets() {
    const ips = (el("ping-ips").value || "").split(",").map((s) => s.trim()).filter(Boolean);
    try {
      const response = await fetchJson("/ping-targets", {
        method: "PUT",
        body: JSON.stringify({ ips }),
      });
      pingTargets = response.ips || [];
      el("ping-ips").value = pingTargets.join(", ");
      await runPingAndRefresh();
    } catch (e) {
      console.error(e);
    }
  }

  async function runPingAndRefresh() {
    const button = el("ping-now-btn");
    button.disabled = true;
    try {
      await apiFetch("/ping/run", { method: "POST" });
      lastPingTargets = pingTargets.join("|");
      await loadLocalPort();
    } catch (e) {
      console.error(e);
    } finally {
      button.disabled = false;
    }
  }

  async function loadLogPage() {
    const requestSequence = ++logRequestSequence;
    try {
      const data = await fetchJson(buildLogUrl(logPage, logPerPage));
      if (requestSequence !== logRequestSequence) return;
      const tbody = el("log-tbody");
      tbody.innerHTML = "";
      const entries = data.entries || [];
      const total = data.total || 0;
      entries.forEach((entry, i) => {
        const summaryRow = document.createElement("tr");
        summaryRow.className = "type-snapshot history-summary-row";
        const v = (key) => entry[key] != null && entry[key] !== "" ? String(entry[key]) : "—";
        const sourceIndex = Number.isInteger(entry._source_index) ?
          entry._source_index : (logPage - 1) * logPerPage + i;
        const protocol = v("protocol");
        const protocolClass = protocol === "CDP" ? "protocol-cdp" : "protocol-lldp";
        summaryRow.innerHTML =
          "<td data-label=\"Time\">" + escapeHtml(entry.timestamp || "—") + "</td>" +
          "<td data-label=\"Protocol\"><span class=\"protocol-badge " + protocolClass + "\">" + escapeHtml(protocol) + "</span></td>" +
          "<td data-label=\"Switch\">" + historySummary(v("system_name"), v("management_address")) + "</td>" +
          "<td data-label=\"Port\">" + historySummary(v("port_id"), v("port_description")) + "</td>" +
          "<td data-label=\"VLAN\">" + historySummary(v("vlan_name"), summarizeObservedTags(v("observed_vlan_tags"))) + "</td>" +
          "<td data-label=\"Ping\">" + summarizePingResults(v("ping_results")) + "</td>" +
          "<td data-label=\"Actions\" class=\"log-actions-col\">" +
            "<div class=\"history-row-actions\">" +
              "<button type=\"button\" class=\"btn btn-small btn-history-details\" aria-expanded=\"false\">Details</button>" +
              "<button type=\"button\" class=\"btn btn-small btn-delete-row\" data-index=\"" + sourceIndex + "\" title=\"Delete this entry\">Delete</button>" +
            "</div></td>";
        tbody.appendChild(summaryRow);

        const detailRow = document.createElement("tr");
        detailRow.className = "history-detail-row";
        detailRow.hidden = true;
        const detailHtml = [
          historyDetail("System Name", escapeHtml(v("system_name"))),
          historyDetail("Management Address", escapeHtml(v("management_address"))),
          historyDetail("Protocol", escapeHtml(protocol)),
          historyDetail("Port ID", escapeHtml(v("port_id"))),
          historyDetail("Port Description", escapeHtml(v("port_description"))),
          historyDetail("Local IP", escapeHtml(v("local_ip"))),
          historyDetail("VLAN ID", escapeHtml(v("vlan_id"))),
          historyDetail("VLAN Name", escapeHtml(v("vlan_name"))),
          historyDetail("Observed Tags", formatObservedTags(v("observed_vlan_tags"))),
          historyDetail("Switch MAC", escapeHtml(v("switch_mac"))),
          historyDetail("Chassis ID", escapeHtml(v("chassis_id"))),
          historyDetail("Capabilities", escapeHtml(v("caps"))),
          historyDetail("Ping Results", formatSavedPingResults(v("ping_results")), "history-detail-wide"),
          historyDetail(
            "Notes",
            `<div class="history-note">${escapeHtml(v("notes"))}</div>`,
            "history-detail-wide history-detail-notes"
          ),
        ].join("");
        detailRow.innerHTML = `<td colspan="7" class="history-detail-cell">` +
          `<div class="history-detail-grid">${detailHtml}</div></td>`;
        tbody.appendChild(detailRow);
      });
      tbody.querySelectorAll(".btn-history-details").forEach((btn) => {
        btn.addEventListener("click", () => {
          const summaryRow = btn.closest(".history-summary-row");
          const detailRow = summaryRow ? summaryRow.nextElementSibling : null;
          if (!detailRow || !detailRow.classList.contains("history-detail-row")) return;
          const willShow = detailRow.hidden;
          detailRow.hidden = !willShow;
          btn.setAttribute("aria-expanded", String(willShow));
          btn.textContent = willShow ? "Hide" : "Details";
          summaryRow.classList.toggle("is-expanded", willShow);
        });
      });
      tbody.querySelectorAll(".btn-delete-row").forEach((btn) => {
        btn.addEventListener("click", () => openDeleteEntryModal(parseInt(btn.getAttribute("data-index"), 10)));
      });
      const pages = Math.max(1, Math.ceil(total / logPerPage));
      el("log-page-info").textContent = `Page ${logPage} of ${pages} (${total} entries)`;
      el("log-prev-btn").disabled = logPage <= 1;
      el("log-next-btn").disabled = logPage >= pages;
    } catch (e) {
      if (requestSequence !== logRequestSequence) return;
      el("log-tbody").innerHTML = "<tr><td colspan='7'>Failed to load log.</td></tr>";
    }
  }

  function buildLogUrl(page, perPage) {
    const params = new URLSearchParams({
      page: String(page),
      per_page: String(perPage),
    });
    const filters = [
      ["q", el("log-search").value.trim()],
      ["protocol", el("log-protocol-filter").value],
      ["ping", el("log-ping-filter").value],
      ["date_from", el("log-date-from").value],
      ["date_to", el("log-date-to").value],
    ];
    filters.forEach(([key, value]) => {
      if (value) params.set(key, value);
    });
    return "/log?" + params.toString();
  }

  function filtersChanged() {
    logPage = 1;
    loadLogPage();
  }

  function setupLogFilters() {
    let searchTimer = null;
    const filters = el("log-filters");
    const toggle = el("log-filters-toggle");
    toggle.addEventListener("click", () => {
      const willShow = filters.hidden;
      filters.hidden = !willShow;
      toggle.setAttribute("aria-expanded", String(willShow));
      toggle.textContent = willShow ? "Hide Filters" : "Show Filters";
    });
    el("log-search").addEventListener("input", () => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(filtersChanged, 250);
    });
    ["log-protocol-filter", "log-ping-filter", "log-date-from", "log-date-to"]
      .forEach((id) => el(id).addEventListener("change", filtersChanged));
    el("log-clear-filters").addEventListener("click", () => {
      el("log-search").value = "";
      el("log-protocol-filter").value = "";
      el("log-ping-filter").value = "";
      el("log-date-from").value = "";
      el("log-date-to").value = "";
      filtersChanged();
    });
  }

  let pendingDeleteEntryIndex = null;

  function openDeleteEntryModal(index) {
    pendingDeleteEntryIndex = index;
    const modal = el("delete-entry-modal");
    modal.classList.add("is-open");
    modal.setAttribute("aria-hidden", "false");
    el("delete-entry-confirm-btn").focus();
  }

  function closeDeleteEntryModal() {
    pendingDeleteEntryIndex = null;
    const modal = el("delete-entry-modal");
    modal.classList.remove("is-open");
    modal.setAttribute("aria-hidden", "true");
  }

  async function confirmDeleteEntry() {
    const index = pendingDeleteEntryIndex;
    closeDeleteEntryModal();
    if (index == null) return;
    try {
      await apiFetch("/log/entry?index=" + encodeURIComponent(index), { method: "DELETE" });
      const total = (await fetchJson(buildLogUrl(1, 1))).total || 0;
      const pages = Math.max(1, Math.ceil(total / logPerPage));
      if (logPage > pages) logPage = Math.max(1, pages);
      loadLogPage();
    } catch (e) {
      console.error(e);
    }
  }

  function logPrev() {
    if (logPage > 1) {
      logPage--;
      loadLogPage();
    }
  }

  function logNext() {
    logPage++;
    loadLogPage();
  }

  async function downloadLog() {
    try {
      const r = await apiFetch("/log/download");
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "detection_history.csv";
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error(e);
    }
  }

  function openDeleteLogModal() {
    const modal = el("delete-log-modal");
    modal.classList.add("is-open");
    modal.setAttribute("aria-hidden", "false");
    el("delete-log-confirm-btn").focus();
  }

  function closeDeleteLogModal() {
    const modal = el("delete-log-modal");
    modal.classList.remove("is-open");
    modal.setAttribute("aria-hidden", "true");
  }

  async function confirmDeleteLog() {
    closeDeleteLogModal();
    try {
      await apiFetch("/log", { method: "DELETE" });
      logPage = 1;
      loadLogPage();
    } catch (e) {
      console.error(e);
    }
  }

  function setupDeleteLogModal() {
    el("log-purge-btn").addEventListener("click", openDeleteLogModal);
    el("delete-log-cancel-btn").addEventListener("click", closeDeleteLogModal);
    el("delete-log-backdrop").addEventListener("click", closeDeleteLogModal);
    el("delete-log-confirm-btn").addEventListener("click", confirmDeleteLog);
    el("delete-entry-cancel-btn").addEventListener("click", closeDeleteEntryModal);
    el("delete-entry-backdrop").addEventListener("click", closeDeleteEntryModal);
    el("delete-entry-confirm-btn").addEventListener("click", confirmDeleteEntry);
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && el("delete-log-modal").classList.contains("is-open")) {
        closeDeleteLogModal();
      }
      if (e.key === "Escape" && el("delete-entry-modal").classList.contains("is-open")) {
        closeDeleteEntryModal();
      }
    });
  }

  async function refreshSniffStatus() {
    try {
      const s = await fetchJson("/sniff/status");
      const startBtn = el("sniff-start-btn");
      const stopBtn = el("sniff-stop-btn");
      if (startBtn) startBtn.disabled = s.sniffing;
      if (stopBtn) stopBtn.disabled = !s.sniffing;
      const toggleBtn = el("connected-start-sniff-btn");
      if (toggleBtn) {
        toggleBtn.title = s.error || "";
        if (s.sniffing) {
          toggleBtn.textContent = "Stop Sniff";
          toggleBtn.className = "btn btn-card-red";
        } else {
          toggleBtn.textContent = "Start Sniff";
          toggleBtn.className = "btn btn-card-green";
        }
      }
    } catch (_) {}
  }

  async function toggleConnectedSniff() {
    try {
      const s = await fetchJson("/sniff/status");
      if (s.sniffing) {
        await apiFetch("/sniff/stop", { method: "POST" });
      } else {
        await apiFetch("/sniff/start", { method: "POST" });
      }
      await refreshSniffStatus();
    } catch (e) {
      console.error(e);
    }
  }

  async function refreshAll() {
    if (refreshInFlight || document.hidden) return;
    refreshInFlight = true;
    try {
      await Promise.allSettled([
        loadLocalPort(),
        refreshSniffStatus(),
        loadCurrentPort(),
      ]);
    } finally {
      refreshInFlight = false;
    }
  }

  function scheduleRefresh(delay = refreshIntervalMs) {
    clearTimeout(refreshTimer);
    if (document.hidden) return;
    refreshTimer = setTimeout(async () => {
      await refreshAll();
      scheduleRefresh();
    }, delay);
  }

  el("interface-select").addEventListener("change", saveInterface);
  el("save-note-btn").addEventListener("click", saveNote);
  const startBtn = el("sniff-start-btn");
  const stopBtn = el("sniff-stop-btn");
  if (startBtn) startBtn.addEventListener("click", sniffStart);
  if (stopBtn) stopBtn.addEventListener("click", sniffStop);
  const connectedSniffBtn = el("connected-start-sniff-btn");
  if (connectedSniffBtn) connectedSniffBtn.addEventListener("click", toggleConnectedSniff);
  el("ping-save-btn").addEventListener("click", () => savePingTargets());
  el("ping-now-btn").addEventListener("click", () => runPingAndRefresh());
  el("log-download-btn").addEventListener("click", downloadLog);
  el("log-prev-btn").addEventListener("click", logPrev);
  el("log-next-btn").addEventListener("click", logNext);
  setupDeleteLogModal();
  setupLogFilters();
  renderLinkState();
  renderLocalPortFields();

  (async function init() {
    try {
      await Promise.allSettled([loadInterfaces(), loadPingTargets()]);
      await Promise.allSettled([refreshAll(), loadLogPage()]);
      scheduleRefresh();
    } catch (e) {
      console.error("Init failed", e);
    }
  })();

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      clearTimeout(refreshTimer);
      return;
    }
    refreshAll().finally(() => scheduleRefresh());
  });
})();
