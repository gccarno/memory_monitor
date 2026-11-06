"use strict";
(function () {
  const TOKEN = new URLSearchParams(location.search).get("t") || "";
  const HEADERS = { "X-Memwatch-Token": TOKEN, "Content-Type": "application/json" };
  const SVGNS = "http://www.w3.org/2000/svg";

  let report = null;
  let sortDesc = true;
  const results = {};   // app_key -> {status, message}
  const forceable = new Set(); // app_keys that returned still_open
  const busy = new Set();

  // ---- formatting -------------------------------------------------------
  function fmtSize(b) {
    if (b == null) return "unknown";
    const mb = b / 1048576;
    if (mb >= 1024) return (mb / 1024).toFixed(1) + " GB";
    return Math.round(mb) + " MB";
  }
  function plural(n, unit) { return n + " " + unit + (n === 1 ? "" : "s") + " ago"; }
  function fmtAgo(ts, now) {
    if (ts == null) return "no recent use recorded";
    const s = Math.max(0, (now || Date.now() / 1000) - ts);
    if (s < 90) return "just now";
    if (s < 3600) return plural(Math.round(s / 60), "minute");
    if (s < 86400) return plural(Math.round(s / 3600), "hour");
    return plural(Math.round(s / 86400), "day");
  }
  function fmtUptime(s) {
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
    if (d > 0) return d + (d === 1 ? " day " : " days ") + h + " h";
    return h + " h " + Math.floor((s % 3600) / 60) + " min";
  }

  // ---- dom helpers ------------------------------------------------------
  function el(tag, props, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (k === "class") e.className = v;
      else if (k === "text") e.textContent = v;
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else if (v !== false && v != null) e.setAttribute(k, v === true ? "" : v);
    }
    for (const kid of kids) if (kid != null) e.append(kid);
    return e;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function $(id) { return document.getElementById(id); }

  function sparkline(values) {
    const svg = document.createElementNS(SVGNS, "svg");
    svg.setAttribute("class", "spark");
    svg.setAttribute("viewBox", "0 0 90 24");
    svg.setAttribute("aria-hidden", "true");
    if (values && values.length > 1) {
      const max = Math.max(...values), min = Math.min(...values);
      const span = max - min || 1;
      const pts = values.map((v, i) => {
        const x = (i / (values.length - 1)) * 90;
        const y = 22 - ((v - min) / span) * 20;
        return x.toFixed(1) + "," + y.toFixed(1);
      }).join(" ");
      const line = document.createElementNS(SVGNS, "polyline");
      line.setAttribute("points", pts);
      svg.append(line);
    }
    return svg;
  }

  // ---- api --------------------------------------------------------------
  async function api(path, body) {
    const opts = body === undefined
      ? { headers: HEADERS }
      : { method: "POST", headers: HEADERS, body: JSON.stringify(body) };
    const r = await fetch(path, opts);
    if (!r.ok) throw new Error("HTTP " + r.status);
    return r.json();
  }
  function showError(msg) {
    const b = $("error");
    b.hidden = !msg;
    b.textContent = msg || "";
  }
  async function load() {
    try {
      report = await api("/api/report");
      showError("");
      render();
    } catch (e) {
      showError("Could not reach memwatch. The report may have closed; run it again to reopen.");
    }
  }

  async function act(key, body, label) {
    busy.add(key);
    render();
    try {
      const res = await api("/api/action", body);
      results[key] = res;
      if (res.status === "still_open") forceable.add(key);
      else forceable.delete(key);
    } catch (e) {
      results[key] = { status: "failed", message: "Request failed (" + e.message + ")." };
    }
    busy.delete(key);
    await load();
  }

  // ---- sections ---------------------------------------------------------
  function metric(k, v, frac) {
    const m = el("div", { class: "metric" }, el("div", { class: "v", text: v }), el("div", { class: "k", text: k }));
    if (frac != null) m.append(el("div", { class: "bar" }, el("span", { style: "width:" + Math.min(100, Math.round(frac * 100)) + "%" })));
    return m;
  }

  function renderPressure() {
    const body = $("pressure-body");
    clear(body);
    const s = report.system;
    if (!s) {
      body.append(el("div", { class: "muted", text: "No samples recorded yet. Is the memwatch logger running?" }));
    } else {
      const used = s.ram_total - s.ram_avail;
      const grid = el("div", { class: "metrics" },
        metric("RAM in use", fmtSize(used) + " of " + fmtSize(s.ram_total), used / s.ram_total),
        metric("Commit charge", fmtSize(s.commit_used) + " of " + fmtSize(s.commit_limit), s.commit_used / s.commit_limit),
        metric("Memory Compression", s.compression_ws == null ? "unknown" : fmtSize(s.compression_ws)));
      body.append(grid);
    }
    body.append(el("div", { class: "free" },
      "You could free about ", el("strong", { text: fmtSize(report.reclaimable) }),
      " by acting on the suggestions below."));
    if (report.partial_note) body.append(el("div", { class: "note caution", text: report.partial_note }));
  }

  function suggestionCard(s) {
    const isBusy = busy.has(s.app_key);
    const card = el("article", { class: "card" });
    const name = el("span", { class: "name", text: s.label });
    if (s.limited) name.append(el("span", { class: "tag", text: "limited data" }));
    card.append(el("div", { class: "sug-head" }, name, el("span", { class: "size", text: fmtSize(s.private_bytes) })));
    card.append(el("div", { class: "sub", text: "Last used " + fmtAgo(s.last_used, report.now) }));
    if (s.reasons.length) {
      const ul = el("ul", { class: "reasons" });
      for (const r of s.reasons) ul.append(el("li", { text: r }));
      card.append(ul);
    }
    if (s.caution) card.append(el("div", { class: "note caution", text: s.caution }));
    if (s.has_windows) card.append(el("div", { class: "note windows", text: "Has open windows — unsaved work may be lost" }));

    const actions = el("div", { class: "actions" });
    actions.append(el("button", {
      class: "btn", type: "button", disabled: isBusy, text: "Stop now",
      onclick: () => {
        if (s.has_windows && !confirm("Ask " + s.label + " to close? It has open windows; unsaved work may be lost if it cannot save.")) return;
        if (!s.has_windows && !confirm("Stop " + s.label + " now?")) return;
        act(s.app_key, { action: "stop", app_key: s.app_key });
      },
    }));
    if (forceable.has(s.app_key)) {
      actions.append(el("button", {
        class: "btn danger", type: "button", disabled: isBusy, text: "Force kill",
        onclick: () => {
          if (confirm("Force kill " + s.label + "? It is ended immediately and any unsaved work will be lost."))
            act(s.app_key, { action: "force", app_key: s.app_key });
        },
      }));
    }
    if (s.startup && s.startup.length) {
      const grp = el("span", { class: "group" });
      let sel = null;
      if (s.service_modes && s.service_modes.length) {
        sel = el("select", { "aria-label": "Startup type for " + s.label });
        for (const m of s.service_modes) sel.append(el("option", { value: m, text: m === "manual" ? "Manual" : "Disabled" }));
        grp.append(sel);
      }
      grp.append(el("button", {
        class: "btn danger", type: "button", disabled: isBusy, text: "Stop starting with Windows",
        onclick: () => {
          const mode = sel ? sel.value : null;
          const what = mode ? "Set " + s.label + " startup to " + mode + "?" : "Stop " + s.label + " starting with Windows?";
          if (confirm(what + " You can undo this from the Undo section."))
            act(s.app_key, { action: "disable_startup", app_key: s.app_key, mode: mode });
        },
      }));
      actions.append(grp);
    }
    card.append(actions);
    const res = results[s.app_key];
    if (res) card.append(resultNode(res));
    return card;
  }

  function resultNode(res) {
    const bad = res.status === "failed" || res.status === "declined";
    return el("div", { class: "result" + (bad ? " bad" : ""), role: "status", text: res.message });
  }

  function renderSuggestions() {
    const box = $("suggestions");
    clear(box);
    const keys = new Set(report.suggestions.map((s) => s.app_key));
    // results for apps that are no longer suggested (e.g. just stopped)
    for (const [k, res] of Object.entries(results)) {
      if (keys.has(k) || k === "__undo") continue;
      const app = report.apps.find((a) => a.app_key === k);
      const card = el("article", { class: "card" }, el("div", { class: "sug-head" }, el("span", { class: "name", text: app ? app.label : k })));
      card.append(resultNode(res));
      box.append(card);
    }
    if (!report.suggestions.length) {
      box.append(el("div", { class: "card muted", text: "Nothing to suggest right now." }));
    }
    for (const s of report.suggestions) box.append(suggestionCard(s));
  }

  function renderApps() {
    const tbody = $("apps").querySelector("tbody");
    clear(tbody);
    const apps = report.apps.slice().sort((a, b) => sortDesc ? b.private_bytes - a.private_bytes : a.private_bytes - b.private_bytes);
    for (const a of apps) {
      tbody.append(el("tr", {},
        el("td", { class: "app", text: a.label }),
        el("td", { class: "num", text: fmtSize(a.private_bytes) }),
        el("td", { class: "hide-narrow" }, sparkline(a.spark)),
        el("td", { text: fmtAgo(a.last_used, report.now) }),
        el("td", { text: a.autostart ? "Yes" : "—" })));
    }
    if (!apps.length) tbody.append(el("tr", {}, el("td", { colspan: "5", class: "muted", text: "No apps recorded yet." })));
    $("sort-arrow").textContent = sortDesc ? "▼" : "▲";
  }

  function renderFixed() {
    const body = $("fixed-body");
    clear(body);
    if (report.kernel_note) body.append(el("div", { class: "kv", text: report.kernel_note }));
    body.append(el("div", { class: "kv muted", text: "Windows has been up for " + fmtUptime(report.uptime_s) + "." }));
    const cap = (report.logger_cap_mb);
    const capText = cap != null ? cap : 50;
    body.append(el("div", { class: "kv" + (report.logger_over_cap ? " red" : ""),
      text: "memwatch logger: " + (report.logger_ws == null ? "unknown" : fmtSize(report.logger_ws)) + " (cap " + capText + " MB)" }));
  }

  function renderUndo() {
    const body = $("undo-body");
    clear(body);
    const recs = report.undo || [];
    if (!recs.length) {
      body.append(el("div", { class: "muted", text: "Nothing to undo." }));
      return;
    }
    for (const r of recs) {
      const what = (r.entry && r.entry.name) || r.app_key;
      const row = el("div", { class: "undo-row" },
        el("div", {}, el("div", { text: "Stopped starting with Windows: " + what }),
          el("div", { class: "sub", text: fmtAgo(r.ts, report.now) })),
        el("button", {
          class: "btn ghost", type: "button", disabled: busy.has("__undo"), text: "Undo",
          onclick: () => act("__undo", { action: "undo", action_id: r.id }),
        }));
      body.append(row);
    }
    if (results.__undo) body.append(resultNode(results.__undo));
  }

  function render() {
    if (!report) return;
    renderPressure();
    renderSuggestions();
    renderApps();
    renderFixed();
    renderUndo();
  }

  $("sort-size").addEventListener("click", () => { sortDesc = !sortDesc; if (report) renderApps(); });
  $("refresh").addEventListener("click", load);

  function heartbeat() {
    fetch("/api/heartbeat", { method: "POST", headers: HEADERS, body: "{}" }).catch(() => {});
  }
  heartbeat();
  setInterval(heartbeat, 15000);
  load();
})();
