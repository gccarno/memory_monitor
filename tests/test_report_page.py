"""Page view logic (static/report.js helpers), run under Node with TZ=UTC."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

JS = Path(__file__).parent.parent / "src" / "memwatch" / "static" / "report.js"
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")


def view(expr: str):
    """Evaluate `expr` with `V` bound to the page's View helpers; returns its JSON value."""
    script = f"const V = require({json.dumps(str(JS))}); process.stdout.write(JSON.stringify({expr}));"
    r = subprocess.run([NODE, "-e", script], capture_output=True, text=True, encoding="utf-8", timeout=30,
                       env={**os.environ, "TZ": "UTC"})
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def entry(source, name, location="loc", enabled=True, can_disable=True, note=None):
    return dict(source=source, name=name, location=location, command="", enabled=enabled,
                needs_admin=False, can_disable=can_disable, note=note, app_key="suite:x")


ENTRIES = [
    entry("run", "Discord"),
    entry("service", "Tobii Pkg", can_disable=False, note="Windows blocks changes"),
    entry("task", "FamilySafety", location="\\Microsoft\\Windows\\Shell\\FamilySafety"),
    entry("startup_folder", "Old.lnk", enabled=False),
]


def test_freshness_text_and_stale_warning():
    ts = 13 * 3600 + 5 * 60  # 13:05 UTC
    assert view(f"V.freshness({{data_ts: {ts}, stale: false}})") == {
        "text": "Data as of 13:05", "warning": None}
    assert view(f"V.freshness({{data_ts: {ts}, stale: true}})")["warning"] == (
        "The memwatch logger hasn't recorded anything since 13:05 — run `memwatch status`.")
    assert view("V.freshness({data_ts: null, stale: false})") is None


def test_size_line_shows_now_typical_and_working_set():
    s = {"private_bytes": 600 << 20, "typical_private": 2 << 30, "working_set": 300 << 20}
    assert view(f"V.sizeLine({json.dumps(s)})") == (
        "now 600 MB · typical 2.0 GB · working set 300 MB")


def test_startup_entries_view():
    views = view(f"{json.dumps(ENTRIES)}.map(V.entryView)")
    assert views[0] == {"text": "Discord — Run key", "readOnly": False, "note": None,
                        "off": False}
    assert views[1]["readOnly"] and views[1]["note"] == "Windows blocks changes"
    assert views[2]["readOnly"] and views[2]["note"] == "Windows system task"
    assert views[3]["off"] and not views[3]["readOnly"]


def test_only_actionable_entries_are_switched_off_and_listed_in_confirm():
    assert view(f"V.actionableEntries({json.dumps(ENTRIES)}).map(e => e.name)") == ["Discord"]
    msg = view(f"V.disableConfirm('Discord', {json.dumps(ENTRIES)}, null)")
    assert msg.startswith("Stop Discord starting with Windows?")
    assert "• Discord (Run key)" in msg
    assert "FamilySafety" not in msg and "Tobii" not in msg and "Old.lnk" not in msg
    msg = view(f"V.disableConfirm('Tobii', {json.dumps([entry('service', 'Tobii Service')])}, 'manual')")
    assert "(services set to Manual)" in msg and "• Tobii Service (Service (Automatic))" in msg


def test_parts_list_is_read_only_text():
    assert view("V.partsList({n_procs: 3, services: ['TobiiSvc']})") == [
        "3 processes", "Service: TobiiSvc"]
    assert view("V.partsList({n_procs: 0, services: []})") == []


_HARNESS = r"""
const fs = require("fs"), vm = require("vm");
const [jsPath, reportPath] = process.argv.slice(2);
const REPORT = JSON.parse(fs.readFileSync(reportPath, "utf8"));
function El(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.textContent = ""; this.hidden = false; this.listeners = {}; }
El.prototype.append = function (...kids) { for (const k of kids) this.children.push(typeof k === "string" ? { textContent: k, children: [] } : k); };
El.prototype.setAttribute = function (k, v) { this.attrs[k] = v; };
El.prototype.addEventListener = function (t, f) { this.listeners[t] = f; };
El.prototype.removeChild = function (c) { this.children.splice(this.children.indexOf(c), 1); };
Object.defineProperty(El.prototype, "firstChild", { get() { return this.children[0] || null; } });
El.prototype.querySelector = function () { return this._q || (this._q = new El("tbody")); };
const ids = {};
const document = { createElement: (t) => new El(t), createElementNS: (ns, t) => new El(t),
                   getElementById: (id) => ids[id] || (ids[id] = new El("div")) };
const text = (n) => (n.textContent || "") + " " + (n.children || []).map(text).join(" ");
const ctx = { document, location: { search: "?t=x" }, URLSearchParams, console, Promise, JSON,
  Math, Date, String, Object, Set, Array, Number,
  setInterval: () => 0, confirm: () => false,
  fetch: async (path) => ({ ok: true, json: async () => (path === "/api/report" ? REPORT : { ok: true }) }) };
vm.runInNewContext(fs.readFileSync(jsPath, "utf8"), ctx);
setTimeout(() => {
  if (!ids.error.hidden && ids.error.textContent) { console.error("page error banner: " + ids.error.textContent); process.exit(1); }
  process.stdout.write(JSON.stringify({ pressure: text(ids["pressure-body"]), suggestions: text(ids.suggestions) }));
}, 100);
"""


def test_page_renders_a_real_report(tmp_path, conn, cfg):
    from conftest import seed_ticks

    from memwatch.db import replace_startup
    from memwatch.models import StartupEntry
    from memwatch.server import report_to_json
    from memwatch.suggest import build_report

    seed_ticks(conn, "suite:tobii", n=10, priv=900 << 20, label="Tobii", services=["TobiiSvc"])
    replace_startup(conn, [
        StartupEntry("service", "Tobii Service", "TobiiSvc", "", True, True, True, None, "suite:tobii"),
        StartupEntry("task", "Tobii Logon", r"\Microsoft\Windows\Tobii", "", True, True, False,
                     "Windows system task", "suite:tobii"),
    ])
    rep = report_to_json(build_report(conn, cfg, now=10_000, dependents=lambda s: []))
    assert rep["stale"] is True
    path = tmp_path / "r.json"
    path.write_text(json.dumps(rep), encoding="utf-8")
    harness = tmp_path / "h.js"
    harness.write_text(_HARNESS, encoding="utf-8")
    r = subprocess.run([NODE, str(harness), str(JS), str(path)], capture_output=True, text=True,
                       encoding="utf-8", timeout=30, env={**os.environ, "TZ": "UTC"})
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert "Data as of 00:09" in out["pressure"]
    assert "hasn't recorded anything since 00:09" in out["pressure"]
    sug = out["suggestions"]
    assert "now 900 MB" in sug and "typical 900 MB" in sug and "working set 900 MB" in sug
    assert "Tobii Service" in sug and "Windows system task" in sug
    assert "Stop starting with Windows" in sug and "Parts (2)" in sug
