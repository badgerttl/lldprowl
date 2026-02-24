(function () {
  const API = "/api";
  let logPage = 1;
  const logPerPage = 20;

  function el(id) {
    return document.getElementById(id);
  }

  async function fetchJson(path, options = {}) {
    const r = await fetch(API + path, {
      headers: { "Content-Type": "application/json", ...options.headers },
      ...options,
    });
    if (!r.ok) throw new Error(await r.text());
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

  async function refreshLinkState() {
    const state = await fetchJson("/interface/state");
    const span = el("link-state");
    span.textContent = state.connected ? "Connected" : "Not connected";
    span.className = "link-state " + (state.connected ? "connected" : "disconnected");
  }

  async function saveInterface() {
    const iface = el("interface-select").value;
    await fetch(API + "/interface", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ interface: iface }),
    });
    refreshLinkState();
    loadLocalPort();
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
      const container = el("local-port-fields");
      let targets = [];
      try {
        const r = await fetchJson("/ping-targets");
        targets = r.ips || [];
      } catch (_) {}
      const targetsKey = (targets || []).join("|");

      const hasIp = d.ipv4 && d.ipv4 !== "—";
      if (d.connected && hasIp) {
        const shouldPing = lastInterfaceConnected === false ||
          lastInterfaceConnected === undefined ||
          lastInterfaceIp !== d.ipv4 ||
          lastPingTargets !== targetsKey;
        if (shouldPing) {
          try {
            await fetch(API + "/ping/run", { method: "POST" });
            loadLogPage();
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

      const rows = [
        ["Interface", d.name || "—"],
        ["IP Address", d.ipv4 || "—"],
        ["Subnet", d.netmask || "—"],
        ["Gateway", d.default_gateway || "—"],
        ["Network", d.network_address || "—"],
        ["Broadcast", d.broadcast || "—"],
        ["Speed", d.speed || "—"],
        ["Duplex", d.duplex || "—"],
        ["MTU", d.mtu || "—"],
      ];
      const localKey = rows.map((r) => r[1]).join("|");
      if (lastLocalCardKey !== null && localKey !== lastLocalCardKey) flashCard("local-interface-card");
      lastLocalCardKey = localKey;
      container.innerHTML = rows
        .map(([label, val]) => `<div class="row"><span class="label">${escapeHtml(label)}</span><span>${escapeHtml(String(val))}</span></div>`)
        .join("");

      // Ping results under Ping IPs: pass green, fail red (cleared when interface is down)
      const pingResultsEl = el("local-ping-results");
      if (!d.connected) {
        pingResultsEl.innerHTML = "";
      } else {
        let pingHtml = "—";
        try {
          const status = await fetchJson("/ping/status");
          const parts = (targets || []).map((ip) => {
            const res = status[ip];
            const ok = res && res.success === true;
            const resultClass = ok ? "ping-pass" : "ping-fail";
            const resultText = ok ? "pass" : "fail";
            return escapeHtml(ip) + ":<span class=\"" + resultClass + "\">" + resultText + "</span>";
          });
          if (parts.length) pingHtml = parts.join(", ");
        } catch (_) {}
        pingResultsEl.innerHTML = pingHtml;
      }
    } catch (e) {
      lastLocalCardKey = null;
      el("local-port-fields").innerHTML = '<div class="row"><span class="label">—</span> Unable to load local port.</div>';
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
        container.innerHTML = '<div class="row"><span class="label">—</span> No LLDP data yet. Start sniff.</div>';
        return;
      }
      const sysDesc = (data.system_description || "").slice(0, 60) + ((data.system_description || "").length > 60 ? "…" : "");
      const rows = [
        ["Sys Name", data.system_name],
        ["Sys Desc", sysDesc],
        ["Mgmt Addr", data.management_address || "—"],
        ["Port ID", data.port_id],
        ["Port Desc", data.port_description],
        ["VLAN", data.vlan_id != null && data.vlan_id !== "" ? data.vlan_id : "—"],
        ["MAC", data.switch_mac != null && data.switch_mac !== "" ? data.switch_mac : "—"],
        ["Chassis", data.chassis_id],
        ["Caps", data.caps != null && data.caps !== "" ? data.caps : "—"],
      ];
      const connectedKey = rows.map((r) => r[1]).join("|");
      if (lastConnectedCardKey !== null && connectedKey !== lastConnectedCardKey) flashCard("connected-switch-card");
      lastConnectedCardKey = connectedKey;
      container.innerHTML = rows
        .map(([label, val]) => `<div class="row"><span class="label">${label}</span><span>${escapeHtml(String(val || "—"))}</span></div>`)
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

  async function saveNote() {
    const note = el("port-notes").value.trim();
    try {
      await fetch(API + "/notes", {
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
      await fetch(API + "/sniff/start", { method: "POST" });
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
      await fetch(API + "/sniff/stop", { method: "POST" });
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
    el("ping-ips").value = ips.join(", ");
  }

  async function savePingTargets() {
    const ips = (el("ping-ips").value || "").split(",").map((s) => s.trim()).filter(Boolean);
    try {
      await fetch(API + "/ping-targets", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ips }),
      });
      await runPingAndRefresh();
    } catch (e) {
      console.error(e);
    }
  }

  async function runPingAndRefresh() {
    try {
      await fetch(API + "/ping/run", { method: "POST" });
      const t = await fetchJson("/ping-targets");
      lastPingTargets = (t.ips || []).join("|");
      loadLogPage();
      await loadLocalPort();
    } catch (e) {
      console.error(e);
    }
  }

  async function loadLogPage() {
    try {
      const data = await fetchJson(`/log?page=${logPage}&per_page=${logPerPage}`);
      const tbody = el("log-tbody");
      tbody.innerHTML = "";
      const entries = data.entries || [];
      const total = data.total || 0;
      entries.forEach((entry, i) => {
        const tr = document.createElement("tr");
        tr.className = "type-snapshot";
        const v = (key) => entry[key] != null && entry[key] !== "" ? String(entry[key]) : "—";
        const globalIndex = (logPage - 1) * logPerPage + i;
        tr.innerHTML =
          "<td>" + escapeHtml(entry.timestamp || "—") + "</td>" +
          "<td>" + escapeHtml(v("system_name")) + "</td>" +
          "<td>" + escapeHtml(v("management_address")) + "</td>" +
          "<td>" + escapeHtml(v("port_id")) + "</td>" +
          "<td>" + escapeHtml(v("port_description")) + "</td>" +
          "<td>" + escapeHtml(v("notes")) + "</td>" +
          "<td class=\"log-actions-col\"><button type=\"button\" class=\"btn btn-small btn-delete-row\" data-index=\"" + globalIndex + "\" title=\"Delete this entry\">Delete</button></td>";
        tbody.appendChild(tr);
      });
      tbody.querySelectorAll(".btn-delete-row").forEach((btn) => {
        btn.addEventListener("click", () => openDeleteEntryModal(parseInt(btn.getAttribute("data-index"), 10)));
      });
      const pages = Math.max(1, Math.ceil(total / logPerPage));
      el("log-page-info").textContent = `Page ${logPage} of ${pages} (${total} entries)`;
      el("log-prev-btn").disabled = logPage <= 1;
      el("log-next-btn").disabled = logPage >= pages;
    } catch (e) {
      el("log-tbody").innerHTML = "<tr><td colspan='7'>Failed to load log.</td></tr>";
    }
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
      await fetch(API + "/log/entry?index=" + encodeURIComponent(index), { method: "DELETE" });
      const total = (await fetchJson("/log?page=1&per_page=1")).total || 0;
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
      const r = await fetch(API + "/log/download");
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
      await fetch(API + "/log", { method: "DELETE" });
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
        await fetch(API + "/sniff/stop", { method: "POST" });
      } else {
        await fetch(API + "/sniff/start", { method: "POST" });
      }
      await refreshSniffStatus();
    } catch (e) {
      console.error(e);
    }
  }

  function refreshAll() {
    refreshLinkState();
    loadLocalPort();
    refreshSniffStatus();
    loadCurrentPort();
    loadLogPage();
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

  (async function init() {
    try {
      await loadInterfaces();
      await loadPingTargets();
      refreshLinkState();
      loadLocalPort();
      refreshSniffStatus();
      loadCurrentPort();
      loadLogPage();
      setInterval(refreshAll, 4000);
    } catch (e) {
      console.error("Init failed", e);
    }
  })();
})();
