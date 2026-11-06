"""On-demand local report: a short-lived, token-protected server on 127.0.0.1."""
from __future__ import annotations

import dataclasses
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlsplit

import psutil

from memwatch import actions, db, grouping, probe
from memwatch.config import Config
from memwatch.models import ActionResult, Report
from memwatch.suggest import build_report, startup_by_app

STATIC_DIR = Path(__file__).parent / "static"
_STATIC = {
    "report.html": "text/html; charset=utf-8",
    "report.js": "text/javascript; charset=utf-8",
    "report.css": "text/css; charset=utf-8",
}
_ACTIONS = {"stop", "force", "disable_startup", "undo"}
_MAX_BODY = 65536
_DRAIN_LIMIT = 1 << 20  # oversized bodies are read (and dropped) up to this, then 413
_SELF_MSG = "memwatch will not stop itself"
log = logging.getLogger(__name__)


def report_to_json(r: Report) -> dict:
    return dataclasses.asdict(r)


def _own_pids() -> set[int]:
    """This process, its launching tree, and anything it started (such as a browser
    opened by webbrowser.open)."""
    mine = {os.getpid()}
    me = psutil.Process()
    for rel in (me.parents, lambda: me.children(recursive=True)):
        try:
            mine |= {p.pid for p in rel()}
        except psutil.Error:
            pass
    return mine


def _exclude_keys(cfg: Config) -> set[str]:
    """Groups holding this server, its launching tree, or any memwatch process."""
    procs = probe.snapshot_processes()
    mine = _own_pids()
    groups = grouping.group_processes(procs, probe.services_by_pid(), cfg)
    by_pid = {p.pid: p for p in procs}
    keys: set[str] = set()
    for key, g in groups.items():
        for pid, _ in g.pids:
            p = by_pid.get(pid)
            if pid in mine or (p is not None and p.cmdline and actions.is_memwatch_cmdline(p.cmdline)):
                keys.add(key)
                break
    return keys


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, cfg, conn_factory, token, actions_impl, resolve):
        super().__init__(addr, handler)
        self.cfg = cfg
        self.conn_factory = conn_factory
        self.token = token
        self.actions_impl = actions_impl
        self.resolve = resolve
        self.last_request = time.monotonic()
        self.last_heartbeat: float | None = None
        self.inflight = 0
        self.lock = threading.Lock()

    def action_started(self) -> None:
        with self.lock:
            self.inflight += 1

    def action_finished(self) -> None:
        with self.lock:
            self.inflight -= 1
            if self.last_heartbeat is not None:
                self.last_heartbeat = time.monotonic()  # the page cannot beat while we worked


class _Handler(BaseHTTPRequestHandler):
    server: _Server
    server_version = "memwatch"
    sys_version = ""

    def log_message(self, *args):  # silence
        pass

    # -- plumbing -----------------------------------------------------------
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json")

    def _deny(self) -> None:
        self._send(403, b"Forbidden", "text/plain; charset=utf-8")

    def _too_large(self) -> None:
        self.close_connection = True
        self.send_response(413)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", "17")
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(b"Payload too large")

    def _notfound(self) -> None:
        self._send(404, b"Not found", "text/plain; charset=utf-8")

    def _gate(self, api: bool) -> bool:
        self.server.last_request = time.monotonic()
        port = self.server.server_address[1]
        if self.headers.get("Host") != f"127.0.0.1:{port}":
            self._deny()
            return False
        if api:
            origin = self.headers.get("Origin")
            if origin is not None and origin != f"http://127.0.0.1:{port}":
                self._deny()
                return False
            sent = self.headers.get("X-Memwatch-Token") or ""
            if not secrets.compare_digest(sent.encode(), self.server.token.encode()):
                self._deny()
                return False
        return True

    # -- GET ----------------------------------------------------------------
    def do_GET(self):
        url = urlsplit(self.path)
        path = url.path
        if path.startswith("/api/"):
            if not self._gate(True):
                return
            if path == "/api/report":
                return self._report()
            return self._notfound()
        if not self._gate(False):
            return
        if path == "/":
            t = (parse_qs(url.query).get("t") or [""])[0]
            if not secrets.compare_digest(t.encode(), self.server.token.encode()):
                return self._deny()
            return self._static("report.html")
        if path.startswith("/static/"):
            return self._static(path[len("/static/"):])
        self._notfound()

    def _static(self, name: str) -> None:
        if name not in _STATIC:
            return self._notfound()
        self._send(200, (STATIC_DIR / name).read_bytes(), _STATIC[name])

    def _build(self, conn: sqlite3.Connection, exclude: set[str]) -> Report:
        return build_report(conn, self.server.cfg, int(time.time()), exclude_keys=exclude)

    def _internal_error(self, what: str) -> None:
        log.exception("%s failed", what)
        self._json(500, {"error": "internal error"})

    def _report(self) -> None:
        try:
            conn = self.server.conn_factory()
            try:
                out = report_to_json(self._build(conn, _exclude_keys(self.server.cfg)))
            finally:
                conn.close()
            out["logger_cap_mb"] = self.server.cfg.logger_cap_mb  # for the page only
        except Exception:
            return self._internal_error("report")
        self._json(200, out)

    # -- POST ---------------------------------------------------------------
    def do_POST(self):
        path = urlsplit(self.path).path
        # Read the whole body before any reply, denials included: closing a socket with
        # unread data makes Windows send RST, and the client sees a reset, not a status.
        body = self._body()
        if body is None:
            return self._too_large()
        if not self._gate(True):
            return
        if path == "/api/heartbeat":
            self.server.last_heartbeat = time.monotonic()
            return self._json(200, {"ok": True})
        if path != "/api/action":
            return self._notfound()
        try:
            req = json.loads(body or b"")
        except (ValueError, UnicodeDecodeError):
            return self._json(400, {"error": "malformed JSON"})
        if not isinstance(req, dict) or req.get("action") not in _ACTIONS:
            return self._json(400, {"error": "unknown action"})
        for k in ("app_key", "mode"):
            if req.get(k) is not None and not isinstance(req[k], str):
                return self._json(400, {"error": f"bad {k}"})
        if req["action"] == "undo":
            aid = req.get("action_id")
            if isinstance(aid, bool) or not isinstance(aid, int):
                return self._json(400, {"error": "bad action_id"})
        elif not req.get("app_key"):
            return self._json(400, {"error": "app_key required"})
        if req.get("mode") not in (None, "manual", "disabled"):
            return self._json(400, {"error": "bad mode"})
        self.server.action_started()
        try:
            conn = self.server.conn_factory()
            try:
                res = self._act(conn, req)
            finally:
                conn.close()
            self._json(200, dataclasses.asdict(res))
        except Exception:
            self._internal_error("action")
        finally:
            self.server.action_finished()

    def _body(self) -> bytes | None:
        """The request body, or None when it is over the cap (drained up to a limit)."""
        try:
            n = max(int(self.headers.get("Content-Length") or 0), 0)
        except ValueError:
            n = 0
        if n <= _MAX_BODY:
            return self.rfile.read(n)
        left = min(n, _DRAIN_LIMIT)
        while left > 0:
            chunk = self.rfile.read(min(left, 65536))
            if not chunk:
                break
            left -= len(chunk)
        return None

    def _act(self, conn: sqlite3.Connection, req: dict) -> ActionResult:
        srv = self.server
        impl, cfg, action = srv.actions_impl, srv.cfg, req["action"]
        if action == "undo":
            return impl.undo(conn, req["action_id"], cfg)
        key = req["app_key"]
        exclude = _exclude_keys(cfg)
        if key in exclude:
            return ActionResult("failed", _SELF_MSG)
        if action == "disable_startup":
            mode = req.get("mode")
            if mode == "disabled":
                sug = next((s for s in self._build(conn, exclude).suggestions if s.app_key == key), None)
                if sug is None or "disabled" not in sug.service_modes:
                    return ActionResult("failed", "Disabling is not offered for this app; "
                                                  "use Manual instead.")
            entries = startup_by_app(conn).get(key, [])
            return impl.disable_startup(conn, key, entries, mode, cfg)
        group = srv.resolve(key, cfg)
        if group is None:
            return ActionResult("already_stopped", "It is no longer running.")
        return impl.stop_now(group, cfg) if action == "stop" else impl.force_kill(group, cfg)


def make_server(cfg: Config, conn_factory: Callable[[], sqlite3.Connection], token: str,
                actions_impl=actions, resolve=grouping.group_for_key) -> ThreadingHTTPServer:
    return _Server(("127.0.0.1", 0), _Handler, cfg, conn_factory, token, actions_impl, resolve)


def _run(srv: _Server, cfg: Config, poll_s: float = 0.25) -> None:
    """Serve until a heartbeat lapses or the server sits idle too long."""
    done = threading.Event()

    def watchdog():
        while not done.wait(poll_s):
            now = time.monotonic()
            hb = srv.last_heartbeat
            if srv.inflight > 0:
                continue
            if hb is not None:
                lapsed = now - hb > cfg.heartbeat_timeout_s
            else:
                lapsed = now - srv.last_request > cfg.server_idle_timeout_s
            if lapsed:
                srv.shutdown()
                return

    threading.Thread(target=watchdog, daemon=True).start()
    try:
        srv.serve_forever()
    finally:
        done.set()
        while srv.inflight > 0:  # let a half-finished change complete (and be recorded)
            time.sleep(0.05)
        srv.server_close()


def serve_report(cfg: Config, open_browser: bool = True) -> None:
    token = secrets.token_urlsafe(32)
    path = cfg.data_dir / "memwatch.db"
    srv = make_server(cfg, lambda: db.connect(path), token)
    url = f"http://127.0.0.1:{srv.server_address[1]}/?t={token}"
    if open_browser:
        webbrowser.open(url)
    else:
        print(url, flush=True)
    _run(srv, cfg)  # type: ignore[arg-type]
