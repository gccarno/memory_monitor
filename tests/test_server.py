from __future__ import annotations

import http.client
import json
import threading
import time
from types import SimpleNamespace

import pytest

from conftest import mk_group, seed_ticks
from memwatch import server
from memwatch.db import connect
from memwatch.models import ActionResult

TOKEN = "tok-123"


class FakeActions:
    def __init__(self):
        self.calls = []

    def stop_now(self, group, cfg, elevator=None):
        self.calls.append(("stop_now", group.app_key))
        return ActionResult("done", "stopped")

    def force_kill(self, group, cfg, elevator=None):
        self.calls.append(("force_kill", group.app_key))
        return ActionResult("done", "killed")

    def disable_startup(self, conn, app_key, entries, mode, cfg, elevator=None, root=""):
        self.calls.append(("disable_startup", app_key, mode, [e.name for e in entries]))
        return ActionResult("done", "disabled")

    def undo(self, conn, action_id, cfg, elevator=None, root=""):
        self.calls.append(("undo", action_id))
        return ActionResult("done", "undone")


@pytest.fixture(autouse=True)
def _no_live_exclude(monkeypatch):
    monkeypatch.setattr(server, "_exclude_keys", lambda cfg: {"suite:self"})


@pytest.fixture
def fake():
    return FakeActions()


@pytest.fixture
def srv(tmp_path, cfg, fake):
    path = tmp_path / "s.db"
    c = connect(path)
    seed_ticks(c, "suite:steam", 30, 600 << 20, label="Steam")
    c.commit()
    c.close()
    s = server.make_server(cfg, lambda: connect(path), TOKEN, actions_impl=fake,
                           resolve=lambda key, cfg: mk_group(key, 1) if key != "suite:gone" else None)
    t = threading.Thread(target=s.serve_forever, daemon=True)
    t.start()
    yield s
    s.shutdown()
    s.server_close()


def req(srv, method, path, body=None, headers=None, raw=None):
    port = srv.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    hdrs = {"Host": f"127.0.0.1:{port}"}
    hdrs.update(headers or {})
    data = raw if raw is not None else (json.dumps(body) if body is not None else None)
    conn.request(method, path, body=data, headers=hdrs)
    r = conn.getresponse()
    out = SimpleNamespace(status=r.status, body=r.read(), headers=r.getheaders())
    conn.close()
    return out


def get(srv, path, headers=None):
    return req(srv, "GET", path, headers=headers)


def post(srv, path, body=None, headers=None, raw=None):
    return req(srv, "POST", path, body, headers, raw)


AUTH = {"X-Memwatch-Token": TOKEN}


def post_json(srv, path, body):
    r = post(srv, path, body, AUTH)
    assert r.status == 200
    return json.loads(r.body)


def test_page_requires_token(srv):
    assert get(srv, "/?t=wrong").status == 403
    assert get(srv, "/").status == 403
    assert get(srv, f"/?t={TOKEN}").status == 200


def test_api_requires_header_and_rejects_foreign_origin(srv, fake):
    body = {"action": "stop", "app_key": "suite:x"}
    assert post(srv, "/api/action", body).status == 403
    r = post(srv, "/api/action", body, {**AUTH, "Origin": "https://evil.example"})
    assert r.status == 403 and fake.calls == []
    assert get(srv, "/api/report").status == 403
    assert post(srv, "/api/action", body, {"X-Memwatch-Token": "nope"}).status == 403


def test_same_origin_allowed_and_no_cors_headers(srv):
    port = srv.server_address[1]
    r = get(srv, "/api/report", {**AUTH, "Origin": f"http://127.0.0.1:{port}"})
    assert r.status == 200
    assert not [k for k, _ in r.headers if k.lower().startswith("access-control")]


def test_wrong_host_header_rejected(srv):
    assert get(srv, f"/?t={TOKEN}", headers={"Host": "attacker.example:80"}).status == 403
    assert get(srv, "/static/report.js", headers={"Host": "attacker.example:80"}).status == 403


def test_static_whitelist(srv):
    for name in ("report.html", "report.js", "report.css"):
        assert get(srv, f"/static/{name}").status == 200
    assert get(srv, "/static/../server.py").status == 404
    assert get(srv, "/static/%2e%2e/server.py").status == 404
    assert get(srv, "/static/.gitkeep").status == 404


def test_report_json_and_action_dispatch(srv, fake):
    rep = json.loads(get(srv, "/api/report", AUTH).body)
    assert "suggestions" in rep and "system" in rep and "apps" in rep and "undo" in rep
    r = post_json(srv, "/api/action", {"action": "stop", "app_key": "suite:steam"})
    assert fake.calls == [("stop_now", "suite:steam")] and r["status"] == "done"
    post_json(srv, "/api/action", {"action": "force", "app_key": "suite:steam"})
    post_json(srv, "/api/action", {"action": "undo", "action_id": 7})
    assert fake.calls[1:] == [("force_kill", "suite:steam"), ("undo", 7)]


def test_missing_group_is_already_stopped(srv, fake):
    r = post_json(srv, "/api/action", {"action": "stop", "app_key": "suite:gone"})
    assert r["status"] == "already_stopped" and fake.calls == []


def test_self_keys_are_refused(srv, fake):
    r = post_json(srv, "/api/action", {"action": "force", "app_key": "suite:self"})
    assert r["status"] == "failed" and r["message"] == "memwatch will not stop itself"
    r = post_json(srv, "/api/action", {"action": "disable_startup", "app_key": "suite:self"})
    assert r["status"] == "failed" and fake.calls == []


def test_bad_requests_are_400(srv, fake):
    assert post(srv, "/api/action", {"action": "format_c", "app_key": "a"}, AUTH).status == 400
    assert post(srv, "/api/action", headers=AUTH, raw="{not json").status == 400
    assert post(srv, "/api/action", [1, 2], AUTH).status == 400
    assert post(srv, "/api/action", {"action": "stop"}, AUTH).status == 400
    assert post(srv, "/api/action", {"action": "undo", "action_id": "x"}, AUTH).status == 400
    assert post(srv, "/api/action", {"action": "disable_startup", "app_key": "a",
                                     "mode": "rm -rf"}, AUTH).status == 400
    assert fake.calls == []


def test_disabled_mode_rejected_unless_offered(srv, fake):
    r = post_json(srv, "/api/action", {"action": "disable_startup", "app_key": "suite:steam",
                                       "mode": "disabled"})
    assert r["status"] == "failed" and fake.calls == []
    r = post_json(srv, "/api/action", {"action": "disable_startup", "app_key": "suite:steam",
                                       "mode": "manual"})
    assert r["status"] == "done"
    assert fake.calls == [("disable_startup", "suite:steam", "manual", [])]


def test_heartbeat_ok(srv):
    assert post(srv, "/api/heartbeat", {}, AUTH).status == 200
    assert post(srv, "/api/heartbeat", {}).status == 403


def test_shuts_down_after_heartbeat_timeout(tmp_path, cfg):
    cfg.heartbeat_timeout_s = 1
    s = server.make_server(cfg, lambda: connect(tmp_path / "h.db"), TOKEN)
    t = threading.Thread(target=server._run, args=(s, cfg, 0.1), daemon=True)
    t.start()
    assert post(s, "/api/heartbeat", {}, AUTH).status == 200
    t.join(3)
    assert not t.is_alive()


def test_shuts_down_when_idle(tmp_path, cfg):
    cfg.server_idle_timeout_s = 1
    s = server.make_server(cfg, lambda: connect(tmp_path / "i.db"), TOKEN)
    t = threading.Thread(target=server._run, args=(s, cfg, 0.1), daemon=True)
    t.start()
    t.join(3)
    assert not t.is_alive()
