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
