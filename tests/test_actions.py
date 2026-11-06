"""Actions against processes this test spawned and registry values under
HKCU\\Software\\memwatch-test only. Elevation is always a fake injected here."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import winreg
from pathlib import Path

import psutil
import pytest

from memwatch import actions
from memwatch.actions import _SELF_MSG, disable_startup, force_kill, stop_now, undo
from memwatch.db import get_action, list_actions
from memwatch.models import AppGroup, StartupEntry
from memwatch.probe import window_pids
from memwatch.startup import APPROVED_PATHS, approved_is_enabled

FIXTURES = Path(__file__).parent / "fixtures"
PY = getattr(sys, "_base_executable", sys.executable)  # no venv launcher: pid == script
ROOT = r"Software\memwatch-test"


def no_elev(ops):
    raise AssertionError(f"unexpected elevation: {ops}")


class FakeElevator:
    """Records ops; answers every op with `ok` (never touches the system)."""

    def __init__(self, ok=True, declined=False):
        self.calls, self.ok, self.declined = [], ok, declined

    def __call__(self, ops):
        self.calls.append(ops)
        if self.declined:
            return "declined"
        return [{"ok": self.ok, "error": None if self.ok else "boom"} for _ in ops]


class Spawned:
    """A fixture process started through launch.py, so it is NOT a descendant of the
    test process (memwatch never acts on its own descendants). Popen-like API."""

    def __init__(self, pid: int):
        self.pid = pid
        self.proc = psutil.Process(pid)

    def poll(self):
        try:
            alive = self.proc.is_running() and self.proc.status() != psutil.STATUS_ZOMBIE
        except psutil.Error:
            alive = False
        return None if alive else 0

    def kill(self):
        if self.poll() is None:  # is_running() re-checks create_time: still ours
            os.kill(self.pid, signal.SIGTERM)  # TerminateProcess, bypasses psutil patches

    def wait(self, timeout=10):
        try:
            code = self.proc.wait(timeout)
        except psutil.NoSuchProcess:
            return 0
        return 0 if code is None else code


@pytest.fixture
def spawn():
    procs: list = []

    def _spawn(script, *args, direct=False):
        cmd = [str(FIXTURES / script), *args]
        if direct:  # a real child of the test process
            p = subprocess.Popen([PY, *cmd])
        else:
            r = subprocess.run([PY, str(FIXTURES / "launch.py"), *cmd], capture_output=True,
                               text=True, timeout=30, check=True)
            p = Spawned(int(r.stdout.strip()))
        procs.append(p)
        return p

    yield _spawn
    for p in procs:  # only ever the processes spawned above
        if p.poll() is None:
            p.kill()
        p.wait(10)


def group_of(*ps, kind="suite", services=()):
    return AppGroup("suite:test", "Test app", kind,
                    [(p.pid, psutil.Process(p.pid).create_time()) for p in ps],
                    0, 0, list(services), False, False)


def wait_for_window(pid, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        if pid in window_pids():
            return
        time.sleep(0.2)
    pytest.fail("fixture window never appeared")


def _delete_tree(path):
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_ALL_ACCESS)
    except FileNotFoundError:
        return
    with k:
        while True:
            try:
                sub = winreg.EnumKey(k, 0)
            except OSError:
                break
            _delete_tree(path + "\\" + sub)
    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)


@pytest.fixture
def test_root():
    _delete_tree(ROOT)
    try:
        yield ROOT
    finally:
        _delete_tree(ROOT)


def dummy_run_entry(root):
    path = root + r"\Software\Microsoft\Windows\CurrentVersion\Run"
    cmd = r'"C:\Program Files\Dummy\dummy.exe" --min'
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "DummyApp", 0, winreg.REG_SZ, cmd)
    return StartupEntry("run", "DummyApp", r"HKCU\DummyApp", cmd, True, False, True, None,
                        "suite:dummy")


def entry_enabled(root, name):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, root + "\\" + APPROVED_PATHS["run"]) as k:
            data = bytes(winreg.QueryValueEx(k, name)[0])
    except FileNotFoundError:
        data = None
    return approved_is_enabled(data)


# ---- stop / force ---------------------------------------------------------

def test_stop_closes_window_app(cfg, spawn):
    p = spawn("window_app.py"); wait_for_window(p.pid)
    r = stop_now(group_of(p), cfg, elevator=no_elev)
    assert r.status == "done" and not psutil.pid_exists(p.pid)


def test_stubborn_window_needs_force(cfg, spawn):
    p = spawn("window_app.py", "--stubborn"); wait_for_window(p.pid)
    cfg.close_timeout_s = 2
    r = stop_now(group_of(p), cfg, elevator=no_elev)
    assert r.status == "still_open" and r.remaining_pids == [p.pid]
    assert r.message == "Still open; it may be waiting for you (unsaved work?)"
    assert force_kill(group_of(p), cfg, elevator=no_elev).status == "done"
    assert p.wait(10) is not None


def test_stop_on_vanished_app(cfg, spawn):
    p = spawn("sleeper.py"); g = group_of(p); p.kill(); p.wait()
    assert stop_now(g, cfg, elevator=no_elev).status == "already_stopped"


def test_stop_skips_reused_pid(cfg, spawn):
    p = spawn("sleeper.py"); g = group_of(p)
    g.pids = [(p.pid, psutil.Process(p.pid).create_time() - 100)]  # simulate reuse
    assert stop_now(g, cfg, elevator=no_elev).status == "already_stopped"
    assert psutil.pid_exists(p.pid)


def test_force_kill_skips_reused_pid(cfg, spawn):
    p = spawn("sleeper.py"); g = group_of(p)
    g.pids = [(p.pid, psutil.Process(p.pid).create_time() - 100)]
    assert force_kill(g, cfg, elevator=no_elev).status == "already_stopped"
    assert p.poll() is None


def test_stop_terminates_windowless(cfg, spawn):
    p = spawn("sleeper.py")
    assert stop_now(group_of(p), cfg, elevator=no_elev).status == "done"
    assert p.wait(10) is not None


def test_protected_group_is_never_touched(cfg, spawn):
    p = spawn("sleeper.py")
    for fn in (stop_now, force_kill):
        r = fn(group_of(p, kind="protected"), cfg, elevator=no_elev)
        assert r.status == "failed" and r.message == "Windows core processes are never stopped"
    assert p.poll() is None


def test_own_process_is_never_touched(cfg):
    me = psutil.Process()
    g = AppGroup("instance:me", "me", "instance", [(me.pid, me.create_time())], 0, 0, [],
                 False, False)
    for fn in (stop_now, force_kill):
        r = fn(g, cfg, elevator=no_elev)
        assert (r.status, r.message) == ("failed", _SELF_MSG)


def test_own_descendant_is_never_touched(cfg, spawn):
    p = spawn("sleeper.py", direct=True)  # a child of this (memwatch) process
    for fn in (stop_now, force_kill):
        r = fn(group_of(p), cfg, elevator=no_elev)
        assert (r.status, r.message) == ("failed", _SELF_MSG)
    assert p.poll() is None


def test_memwatch_cmdline_process_is_never_touched(cfg, spawn):
    p = spawn("sleeper.py", "-m", "memwatch")  # looks like `python -m memwatch ...`
    for fn in (stop_now, force_kill):
        r = fn(group_of(p), cfg, elevator=no_elev)
        assert (r.status, r.message) == ("failed", _SELF_MSG)
        assert r.remaining_pids == [p.pid]
    assert p.poll() is None


def test_force_kill_reports_untouchable_survivor_as_partial(cfg, spawn):
    plain = spawn("sleeper.py")
    mw = spawn("sleeper.py", "-m", "memwatch", "log")
    r = force_kill(group_of(plain, mw), cfg, elevator=no_elev)
    assert r.status == "partial" and r.remaining_pids == [mw.pid]
    assert plain.wait(10) is not None and mw.poll() is None


def test_stop_reports_untouchable_survivor_as_partial(cfg, spawn):
    plain = spawn("sleeper.py")
    mw = spawn("sleeper.py", "-m", "memwatch.report")
    r = stop_now(group_of(plain, mw), cfg, elevator=no_elev)
    assert r.status == "partial" and r.remaining_pids == [mw.pid]
    assert plain.wait(10) is not None and mw.poll() is None


def test_still_open_window_leaves_the_rest_untouched(cfg, spawn, monkeypatch):
    win = spawn("window_app.py", "--stubborn"); wait_for_window(win.pid)
    helper = spawn("sleeper.py")
    monkeypatch.setattr(actions, "_service_running", lambda name: True)
    monkeypatch.setattr(actions, "_dependents", lambda name: [])
    cfg.close_timeout_s = 2
    r = stop_now(group_of(win, helper, services=["FakeSvc"]), cfg, elevator=no_elev)
    assert r.status == "still_open"
    assert r.remaining_pids == sorted([win.pid, helper.pid])
    assert helper.poll() is None and win.poll() is None


def test_force_kill_takes_children(cfg, spawn, tmp_path):
    pidfile = tmp_path / "child.pid"
    p = spawn("sleeper.py", "--child", str(pidfile))
    end = time.time() + 20
    while not (pidfile.exists() and pidfile.read_text()) and time.time() < end:
        time.sleep(0.1)
    child = psutil.Process(int(pidfile.read_text()))
    try:
        assert force_kill(group_of(p), cfg, elevator=no_elev).status == "done"
        assert p.wait(10) is not None and not child.is_running()
    finally:
        if child.is_running():  # is_running re-checks create_time: still our child
            child.kill()


def _deny_terminate(monkeypatch, pid):
    real_t, real_k = psutil.Process.terminate, psutil.Process.kill

    def deny(real):
        def f(self):
            if self.pid == pid:
                raise psutil.AccessDenied(pid)
            return real(self)
        return f
    monkeypatch.setattr(psutil.Process, "terminate", deny(real_t))
    monkeypatch.setattr(psutil.Process, "kill", deny(real_k))


def test_access_denied_goes_to_elevator(cfg, spawn, monkeypatch):
    p = spawn("sleeper.py"); g = group_of(p)
    _deny_terminate(monkeypatch, p.pid)
    seen = []

    def elevator(ops):  # stands in for the runner: kills only our own sleeper
        seen.append(ops)
        p.kill()
        return [{"ok": True, "error": None}]
    r = stop_now(g, cfg, elevator=elevator)
    assert seen == [[{"op": "kill", "pid": p.pid, "create_time": g.pids[0][1]}]]
    assert r.status == "done"


def test_declined_elevation(cfg, spawn, monkeypatch):
    p = spawn("sleeper.py"); g = group_of(p)
    _deny_terminate(monkeypatch, p.pid)
    assert stop_now(g, cfg, elevator=FakeElevator(declined=True)).status == "declined"
    assert force_kill(g, cfg, elevator=FakeElevator(declined=True)).status == "declined"
    assert p.poll() is None


@pytest.mark.parametrize("fn", [stop_now, force_kill])
def test_declined_after_partial_work_is_partial(cfg, spawn, monkeypatch, fn):
    easy, hard = spawn("sleeper.py"), spawn("sleeper.py")
    _deny_terminate(monkeypatch, hard.pid)
    r = fn(group_of(easy, hard), cfg, elevator=FakeElevator(declined=True))
    assert r.status == "partial" and "declined" in r.message
    assert r.remaining_pids == [hard.pid]
    assert easy.wait(10) is not None and hard.poll() is None


def test_services_with_dependents_are_skipped(cfg, monkeypatch):
    monkeypatch.setattr(actions, "_dependents", lambda name: ["Child"] if name == "SvcA" else [])
    running = {"SvcA", "SvcB"}
    monkeypatch.setattr(actions, "_service_running", lambda name: name in running)
    g = AppGroup("suite:x", "X", "suite", [], 0, 0, ["SvcA", "SvcB"], False, False)

    def elevator(ops):
        for op in ops:
            running.discard(op["name"])
        return [{"ok": True, "error": None} for _ in ops]
    ops_seen = []
    r = stop_now(g, cfg, elevator=lambda ops: (ops_seen.append(ops), elevator(ops))[1])
    assert ops_seen == [[{"op": "stop_service", "name": "SvcB"}]]
    assert r.status == "partial" and "SvcA" in r.message and "Child" in r.message


def test_service_host_is_stopped_via_its_service_not_terminated(cfg, spawn, monkeypatch):
    from memwatch.models import ServiceInfo

    p = spawn("sleeper.py")
    host = {p.pid: [ServiceInfo("FakeSvc", "Fake", "", "automatic", p.pid, "")]}
    monkeypatch.setattr(actions.probe, "services_by_pid", lambda: host)
    monkeypatch.setattr(actions, "_service_running", lambda name: True)
    monkeypatch.setattr(actions, "_dependents", lambda name: [])
    monkeypatch.setattr(psutil.Process, "terminate", lambda self: pytest.fail("terminated"))
    seen = []

    def elevator(ops):  # "stopping the service" ends its host: our own sleeper
        seen.append(ops)
        p.kill()
        return [{"ok": True, "error": None}]
    r = stop_now(group_of(p, services=["FakeSvc"]), cfg, elevator=elevator)
    assert seen == [[{"op": "stop_service", "name": "FakeSvc"}]] and r.status == "done"


def test_shared_service_host_is_left_alone(cfg, spawn, monkeypatch):
    from memwatch.models import ServiceInfo

    p = spawn("sleeper.py")
    host = {p.pid: [ServiceInfo(n, n, "", "automatic", p.pid, "") for n in ("FakeSvc", "Other")]}
    monkeypatch.setattr(actions.probe, "services_by_pid", lambda: host)
    monkeypatch.setattr(actions, "_service_running", lambda name: False)
    r = stop_now(group_of(p, services=["FakeSvc"]), cfg, elevator=no_elev)
    assert r.status == "failed" and "other services" in r.message and p.poll() is None


def test_protected_services_are_skipped(cfg, monkeypatch):
    monkeypatch.setattr(actions, "_service_running", lambda name: True)
    monkeypatch.setattr(actions, "_dependents", lambda name: [])
    g = AppGroup("suite:x", "X", "suite", [], 0, 0, ["WinDefend"], False, False)
    r = stop_now(g, cfg, elevator=no_elev)
    assert r.status == "failed" and "WinDefend" in r.message


# ---- startup --------------------------------------------------------------

def test_disable_and_undo_hkcu_entry(conn, cfg, test_root):
    e = dummy_run_entry(test_root)
    assert disable_startup(conn, "suite:dummy", [e], None, cfg, elevator=no_elev, root=test_root).status == "done"
    assert not entry_enabled(test_root, "DummyApp")
    rec = list_actions(conn)[0]
    assert rec.action == "disable_startup" and rec.app_key == "suite:dummy"
    assert rec.before == {"approved": None}
    assert undo(conn, rec.id, cfg, elevator=no_elev, root=test_root).status == "done"
    assert entry_enabled(test_root, "DummyApp")
    assert get_action(conn, rec.id).undone and list_actions(conn) == []
    assert undo(conn, rec.id, cfg, elevator=no_elev, root=test_root).status == "failed"


def test_disable_startup_declined_records_nothing(conn, cfg, monkeypatch):
    monkeypatch.setattr(actions, "_service_start", lambda name: "auto")  # no real SCM read
    e = StartupEntry("service", "Tobii Service", "Tobii Service", "", True, True, True, None, "suite:tobii")
    r = disable_startup(conn, "suite:tobii", [e], "manual", cfg, elevator=lambda ops: "declined")
    assert r.status == "declined" and list_actions(conn) == []


def test_unreadable_service_start_is_refused(conn, cfg, monkeypatch):
    monkeypatch.setattr(actions, "_service_start", lambda name: None)  # unreadable, boot or system
    e = StartupEntry("service", "Tobii Service", "Tobii Service", "", True, True, True, None, "suite:tobii")
    r = disable_startup(conn, "suite:tobii", [e], "manual", cfg, elevator=no_elev)
    assert r.status == "failed" and "start type" in r.message and list_actions(conn) == []


def test_mixed_batch_records_only_successes(conn, cfg, monkeypatch):
    monkeypatch.setattr(actions, "_service_start", lambda name: "auto")
    svc = StartupEntry("service", "Tobii Service", "Tobii Service", "", True, True, True, None, "suite:tobii")
    task = StartupEntry("task", "Tobii Logon", r"\Tobii\Logon", "", True, True, True, None, "suite:tobii")
    calls = []

    def elevator(ops):
        calls.append(ops)
        return [{"ok": True, "error": None}, {"ok": False, "error": "access is denied"}]
    r = disable_startup(conn, "suite:tobii", [svc, task], "manual", cfg, elevator=elevator)
    assert len(calls) == 1 and len(calls[0]) == 2
    assert r.status == "partial" and "Tobii Logon" in r.message and "access is denied" in r.message
    assert [x.entry["name"] for x in list_actions(conn)] == ["Tobii Service"]


def test_admin_entries_share_one_elevation_and_undo(conn, cfg, monkeypatch):
    monkeypatch.setattr(actions, "_service_start", lambda name: "auto")
    monkeypatch.setattr(actions, "_hklm_approved", lambda e: None)
    svc = StartupEntry("service", "Tobii Service", "Tobii Service", "", True, True, True, None, "suite:tobii")
    task = StartupEntry("task", "Tobii Logon", r"\Tobii\Logon", "", True, True, True, None, "suite:tobii")
    run = StartupEntry("run", "TobiiTray", r"HKLM32\TobiiTray", "", True, True, True, None, "suite:tobii")
    nope = StartupEntry("service", "Tobii Pkg", "TobiiPkg", "", True, True, False,
                        "Windows blocks changes", "suite:tobii")
    elev = FakeElevator()
    r = disable_startup(conn, "suite:tobii", [svc, task, run, nope], "disabled", cfg, elevator=elev)
    assert len(elev.calls) == 1
    ops = elev.calls[0]
    assert ops[0] == {"op": "set_service_start", "name": "Tobii Service", "start": "disabled"}
    assert ops[1] == {"op": "set_task", "name": r"\Tobii\Logon", "enabled": False}
    assert ops[2]["op"] == "set_approved" and ops[2]["hive"] == "HKLM"
    assert ops[2]["subkey"] == APPROVED_PATHS["run32"] and ops[2]["value"] == "TobiiTray"
    assert r.status == "partial" and "Windows blocks changes" in r.message
    recs = list_actions(conn)
    assert [x.before for x in recs] == [{"start": "auto"}, {"enabled": True}, {"approved": None}]
    for rec in recs:
        elev = FakeElevator()
        assert undo(conn, rec.id, cfg, elevator=elev).status == "done"
        (op,) = elev.calls[0]
        assert op == {
            "set_service_start": {"op": "set_service_start", "name": "Tobii Service", "start": "auto"},
            "set_task": {"op": "set_task", "name": r"\Tobii\Logon", "enabled": True},
            "set_approved": {"op": "set_approved", "hive": "HKLM", "subkey": APPROVED_PATHS["run32"],
                             "value": "TobiiTray", "data_hex": None},
        }[op["op"]]
    assert list_actions(conn) == []


def test_failed_elevated_op_records_nothing(conn, cfg, monkeypatch):
    monkeypatch.setattr(actions, "_service_start", lambda name: "auto")
    svc = StartupEntry("service", "Tobii Service", "Tobii Service", "", True, True, True, None, "suite:tobii")
    r = disable_startup(conn, "suite:tobii", [svc], "manual", cfg, elevator=FakeElevator(ok=False))
    assert r.status == "failed" and list_actions(conn) == []


def test_undo_declined_keeps_record(conn, cfg, monkeypatch):
    monkeypatch.setattr(actions, "_service_start", lambda name: "auto")
    svc = StartupEntry("service", "Tobii Service", "Tobii Service", "", True, True, True, None, "suite:tobii")
    disable_startup(conn, "suite:tobii", [svc], "manual", cfg, elevator=FakeElevator())
    rec = list_actions(conn)[0]
    assert undo(conn, rec.id, cfg, elevator=FakeElevator(declined=True)).status == "declined"
    assert list_actions(conn) == [rec]


def test_cannot_disable_only(conn, cfg):
    nope = StartupEntry("service", "Tobii Pkg", "TobiiPkg", "", True, True, False,
                        "Windows blocks changes", "suite:tobii")
    r = disable_startup(conn, "suite:tobii", [nope], "manual", cfg, elevator=no_elev)
    assert r.status == "failed" and "Windows blocks changes" in r.message


def test_delayed_auto_service_round_trips_exactly(conn, cfg, monkeypatch):
    monkeypatch.setattr(actions, "_service_start", lambda name: "delayed-auto")
    svc = StartupEntry("service", "Windows Search", "WSearch", "", True, True, True, None,
                       "service:wsearch")
    elev = FakeElevator()
    assert disable_startup(conn, "service:wsearch", [svc], "manual", cfg,
                           elevator=elev).status == "done"
    assert elev.calls == [[{"op": "set_service_start", "name": "WSearch", "start": "demand"}]]
    (rec,) = list_actions(conn)
    assert rec.before == {"start": "delayed-auto"}
    elev = FakeElevator()
    assert undo(conn, rec.id, cfg, elevator=elev).status == "done"
    assert elev.calls == [[{"op": "set_service_start", "name": "WSearch", "start": "delayed-auto"}]]
    from memwatch.elevated_runner import validate
    assert validate(elev.calls[0][0])


# ---- final-review fixes: live state, table sync ---------------------------

def test_double_disable_records_once(conn, cfg, test_root):
    e = dummy_run_entry(test_root)
    assert disable_startup(conn, "suite:dummy", [e], None, cfg, elevator=no_elev,
                           root=test_root).status == "done"
    # the second click still carries the stale enabled=True entry
    r = disable_startup(conn, "suite:dummy", [e], None, cfg, elevator=no_elev, root=test_root)
    assert r.status == "done" and "already off" in r.message
    assert len(list_actions(conn)) == 1
    # undo restores the true original (enabled), not the already-disabled bytes
    assert undo(conn, list_actions(conn)[0].id, cfg, elevator=no_elev, root=test_root).status == "done"
    assert entry_enabled(test_root, "DummyApp")


def test_disable_then_undo_updates_startup_table_and_report(conn, cfg, test_root):
    from conftest import seed_ticks
    from memwatch.db import replace_startup, startup_entries
    from memwatch.suggest import build_report

    e = dummy_run_entry(test_root)
    replace_startup(conn, [e])
    seed_ticks(conn, "suite:dummy", n=10, priv=600 << 20, label="Dummy")
    assert disable_startup(conn, "suite:dummy", [e], None, cfg, elevator=no_elev,
                           root=test_root).status == "done"
    assert [x.enabled for x in startup_entries(conn)] == [False]
    r = build_report(conn, cfg, now=600)
    assert r.apps[0].autostart is False and r.suggestions[0].startup[0].enabled is False
    rec = list_actions(conn)[0]
    assert undo(conn, rec.id, cfg, elevator=no_elev, root=test_root).status == "done"
    assert [x.enabled for x in startup_entries(conn)] == [True]
    r = build_report(conn, cfg, now=600)
    assert r.apps[0].autostart is True and r.suggestions[0].startup[0].enabled is True


def test_live_state_already_off_service_is_skipped(conn, cfg, monkeypatch):
    monkeypatch.setattr(actions, "_service_start", lambda name: "demand")  # already Manual
    svc = StartupEntry("service", "Tobii Service", "TobiiSvc", "", True, True, True, None, "suite:tobii")
    r = disable_startup(conn, "suite:tobii", [svc], "manual", cfg, elevator=no_elev)
    assert r.status == "done" and "already off" in r.message and list_actions(conn) == []


def test_windows_system_task_never_reaches_elevator(conn, cfg):
    t = StartupEntry("task", "FamilySafety", r"\Microsoft\Windows\Shell\FamilySafety", "",
                     True, True, True, None, "suite:x")  # stale row that still says can_disable
    r = disable_startup(conn, "suite:x", [t], None, cfg, elevator=no_elev)
    assert r.status == "failed" and "Windows system task" in r.message
    assert list_actions(conn) == []


def test_elevated_undo_updates_startup_table(conn, cfg, monkeypatch):
    from memwatch.db import replace_startup, startup_entries

    monkeypatch.setattr(actions, "_service_start", lambda name: "auto")
    svc = StartupEntry("service", "Tobii Service", "TobiiSvc", "", True, True, True, None, "suite:tobii")
    replace_startup(conn, [svc])
    disable_startup(conn, "suite:tobii", [svc], "manual", cfg, elevator=FakeElevator())
    assert [x.enabled for x in startup_entries(conn)] == [False]
    undo(conn, list_actions(conn)[0].id, cfg, elevator=FakeElevator())
    assert [x.enabled for x in startup_entries(conn)] == [True]
