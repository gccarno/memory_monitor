// Page view helpers (static/report.js), run under Node with TZ=UTC. usage: node view_tests.js <report.js>
"use strict";
const assert = require("assert");
const V = require(require("path").resolve(process.argv[2]));

const entry = (source, name, o = {}) => Object.assign(
  { source, name, location: "loc", command: "", enabled: true, needs_admin: false,
    can_disable: true, note: null, app_key: "suite:x" }, o);
const ENTRIES = [
  entry("run", "Discord"),
  entry("service", "Tobii Pkg", { can_disable: false, note: "Windows blocks changes" }),
  entry("task", "FamilySafety", { location: "\\Microsoft\\Windows\\Shell\\FamilySafety" }),
  entry("startup_folder", "Old.lnk", { enabled: false }),
];

// freshness text and stale warning
const ts = 13 * 3600 + 5 * 60; // 13:05 UTC
assert.deepStrictEqual(V.freshness({ data_ts: ts, stale: false }), { text: "Data as of 13:05", warning: null });
assert.strictEqual(V.freshness({ data_ts: ts, stale: true }).warning,
  "The memwatch logger hasn't recorded anything since 13:05 — run `memwatch status`.");
assert.strictEqual(V.freshness({ data_ts: null, stale: false }), null);

// size line shows now, typical and working set
assert.strictEqual(
  V.sizeLine({ private_bytes: 600 * 2 ** 20, typical_private: 2 * 2 ** 30, working_set: 300 * 2 ** 20 }),
  "now 600 MB · typical 2.0 GB · working set 300 MB");

// startup entries view
const views = ENTRIES.map(V.entryView);
assert.deepStrictEqual(views[0], { text: "Discord — Run key", readOnly: false, note: null, off: false });
assert.ok(views[1].readOnly && views[1].note === "Windows blocks changes");
assert.ok(views[2].readOnly && views[2].note === "Windows system task");
assert.ok(views[3].off && !views[3].readOnly);

// only actionable entries are switched off and listed in the confirm
assert.deepStrictEqual(V.actionableEntries(ENTRIES).map((e) => e.name), ["Discord"]);
let msg = V.disableConfirm("Discord", ENTRIES, null);
assert.ok(msg.startsWith("Stop Discord starting with Windows?"));
assert.ok(msg.includes("• Discord (Run key)"));
for (const bad of ["FamilySafety", "Tobii", "Old.lnk"]) assert.ok(!msg.includes(bad), bad);
msg = V.disableConfirm("Tobii", [entry("service", "Tobii Service")], "manual");
assert.ok(msg.includes("(services set to Manual)") && msg.includes("• Tobii Service (Service (Automatic))"));

// parts list is read-only text
assert.deepStrictEqual(V.partsList({ n_procs: 3, services: ["TobiiSvc"] }), ["3 processes", "Service: TobiiSvc"]);
assert.deepStrictEqual(V.partsList({ n_procs: 0, services: [] }), []);
console.log("ok");
