from __future__ import annotations

import winreg

import pytest

from memwatch.models import StartupEntry
from memwatch.startup import (
    APPROVED_PATHS, _PKG, _approved_target, apply_toggle, approved_bytes, approved_is_enabled, elevated_ops_for, inventory,
    parse_command, restore,
)

ROOT = r"Software\memwatch-test"


def _delete_tree(hive, path):
    try:
        k = winreg.OpenKey(hive, path, 0, winreg.KEY_ALL_ACCESS)
    except FileNotFoundError:
        return
    with k:
        while True:
            try:
                sub = winreg.EnumKey(k, 0)
            except OSError:
                break
            _delete_tree(hive, path + "\\" + sub)
    winreg.DeleteKey(hive, path)


@pytest.fixture
def test_root():
    _delete_tree(winreg.HKEY_CURRENT_USER, ROOT)
    try:
        yield ROOT
    finally:
        _delete_tree(winreg.HKEY_CURRENT_USER, ROOT)


def raw_approved(path, name):
    """Raw StartupApproved bytes under HKCU, or None when the value is absent."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as k:
            return bytes(winreg.QueryValueEx(k, name)[0])
    except FileNotFoundError:
        return None


def set_hkcu(path, name, value):
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)


def test_approved_bytes_roundtrip():
    assert approved_is_enabled(None)
    assert approved_is_enabled(approved_bytes(True, 0))
    d = approved_bytes(False, 133_000_000_000_000_000)
    assert len(d) == 12 and not approved_is_enabled(d)


def test_inventory_and_toggle_run_entry(test_root, cfg):
    set_hkcu(test_root + r"\Software\Microsoft\Windows\CurrentVersion\Run", "DummyApp",
             r'"C:\Program Files\Dummy\dummy.exe" --min')

    def find():
        return [x for x in inventory(cfg, root=test_root) if x.name == "DummyApp"][0]

    e = find()
    assert e.source == "run" and e.enabled and not e.needs_admin and e.app_key == "suite:dummy"
    assert e.location == r"HKCU\DummyApp"
    before = apply_toggle(e, False, root=test_root)
    assert before == {"approved": None}
    apath = test_root + "\\" + APPROVED_PATHS["run"]
    assert not approved_is_enabled(raw_approved(apath, "DummyApp"))
    assert not find().enabled
    restore(e, before, root=test_root)
    assert raw_approved(apath, "DummyApp") is None  # deleted, not rewritten
    assert find().enabled


def test_restore_previous_bytes(test_root, cfg):
    set_hkcu(test_root + r"\Software\Microsoft\Windows\CurrentVersion\Run", "DummyApp", r"C:\x\y.exe -a")
    e = [x for x in inventory(cfg, root=test_root) if x.name == "DummyApp"][0]
    b1 = apply_toggle(e, False, root=test_root)
    b2 = apply_toggle(e, True, root=test_root)
    assert b2["approved"] is not None and not approved_is_enabled(bytes.fromhex(b2["approved"]))
    restore(e, b2, root=test_root)
    assert not [x for x in inventory(cfg, root=test_root) if x.name == "DummyApp"][0].enabled
    restore(e, b1, root=test_root)
    assert raw_approved(test_root + "\\" + APPROVED_PATHS["run"], "DummyApp") is None


def test_restore_exact_prior_bytes(test_root, cfg):
    set_hkcu(test_root + r"\Software\Microsoft\Windows\CurrentVersion\Run", "DummyApp", r"C:\x\y.exe")
    apath = test_root + "\\" + APPROVED_PATHS["run"]
    prior = bytes([3, 0, 0, 0]) + bytes([0x11] * 8)
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, apath, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "DummyApp", 0, winreg.REG_BINARY, prior)
    e = [x for x in inventory(cfg, root=test_root) if x.name == "DummyApp"][0]
    assert not e.enabled
    before = apply_toggle(e, True, root=test_root)
    assert raw_approved(apath, "DummyApp") == approved_bytes(True, 0)
    restore(e, before, root=test_root)
    assert raw_approved(apath, "DummyApp") == prior


def test_packaged_toggle_roundtrip(test_root):
    loc = r"Pkg_1.0_x64__abc\Task1"
    path = test_root + "\\" + _PKG + "\\" + loc
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "State", 0, winreg.REG_DWORD, 2)
    e = StartupEntry("packaged", "Pkg (Task1)", loc, "", True, False, True, None, "suite:pkg")

    def state():
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as k:
            return winreg.QueryValueEx(k, "State")[0]

    before = apply_toggle(e, False, root=test_root)
    assert before == {"state": 2} and state() == 1
    restore(e, before, root=test_root)
    assert state() == 2


def test_hive_and_subkey_selection():
    def ent(source, location, admin=True):
        return StartupEntry(source, "n", location, "", True, admin, True, None, None)

    cases = [
        (ent("run", r"HKLM\n"), "HKLM", "run", "n"),
        (ent("run", r"HKLM32\n"), "HKLM", "run32", "n"),
        (ent("startup_folder", r"C:\ProgramData\Startup\n.lnk"), "HKLM", "startup_folder", "n.lnk"),
    ]
    for e, hive, kind, value in cases:
        op = elevated_ops_for(e, False, None)[0]
        assert (op["hive"], op["subkey"], op["value"]) == (hive, APPROVED_PATHS[kind], value)
    # non-admin entries resolve to HKCU
    assert _approved_target(ent("run", r"HKCU\n", False)) == ("HKCU", "run", "n")
    assert _approved_target(ent("startup_folder", r"C:\Users\u\Startup\n.lnk", False)) == (
        "HKCU", "startup_folder", "n.lnk")


def test_fail_closed():
    blocked = StartupEntry("service", "G", "G", "", True, True, False, "no", None)
    with pytest.raises(ValueError):
        elevated_ops_for(blocked, False, "manual")
    svc_e = StartupEntry("service", "S", "S", "", True, True, True, None, None)
    for bad in (None, "bogus", "auto"):
        with pytest.raises(ValueError):
            elevated_ops_for(svc_e, False, bad)
    pk = StartupEntry("packaged", "P", r"p\t", "", True, False, True, None, None)
    with pytest.raises(ValueError):
        elevated_ops_for(pk, False, None)
    for src in ("task", "service"):
        with pytest.raises(ValueError):
            restore(StartupEntry(src, "S", "S", "", True, True, True, None, None), {})


def test_service_ops_respect_mode():
    e = StartupEntry("service", "Tobii Service", "Tobii Service", "", True, True, True, None, "suite:tobii")
    assert elevated_ops_for(e, False, "manual") == [{"op": "set_service_start", "name": "Tobii Service", "start": "demand"}]
    assert elevated_ops_for(e, False, "disabled")[0]["start"] == "disabled"
    assert elevated_ops_for(e, True, None)[0]["start"] == "auto"
    assert elevated_ops_for(e, True, "manual")[0]["start"] == "demand"


def test_elevated_ops_task_and_hklm_run():
    t = StartupEntry("task", "Foo", r"\Foo", "", True, True, True, None, None)
    assert elevated_ops_for(t, False, None) == [{"op": "set_task", "name": r"\Foo", "enabled": False}]
    r = StartupEntry("run", "Foo", r"HKLM\Foo", "", True, True, True, None, None)
    op = elevated_ops_for(r, False, None)[0]
    assert op["op"] == "set_approved" and op["hive"] == "HKLM" and op["value"] == "Foo"
    assert not approved_is_enabled(bytes.fromhex(op["data_hex"]))


@pytest.mark.parametrize("cmd,exe", [
    (r'"C:\Program Files\Dummy\dummy.exe" --min', r"C:\Program Files\Dummy\dummy.exe"),
    (r"C:\x\y.exe -a", r"C:\x\y.exe"),
    (r"C:\Program Files\Some App\app.exe /s", r"C:\Program Files\Some App\app.exe"),
    (r'rundll32.exe "C:\Foo\bar.dll",Start', r"C:\Foo\bar.dll"),
    (r'cmd /c "C:\Foo\run.exe" x', r"C:\Foo\run.exe"),
])
def test_parse_command(cmd, exe):
    assert parse_command(cmd) == exe


def test_parse_command_expands_env(monkeypatch):
    monkeypatch.setenv("MWTEST", r"C:\Zed")
    assert parse_command(r"%MWTEST%\z.exe") == r"C:\Zed\z.exe"


_CSV_HEAD = '"TaskName","Schedule Type","Task To Run","Author","Run As User","Scheduled Task State"\n'


def test_windows_system_logon_tasks_are_read_only(monkeypatch, cfg):
    import subprocess

    import memwatch.startup as st

    rows = (_CSV_HEAD
            + r'"\Microsoft\Windows\Shell\FamilySafety","At logon time","C:\Windows\x.exe","Microsoft","SYSTEM","Enabled"' + "\n"
            + r'"\Tobii\Logon","At logon time","C:\Program Files\Tobii\t.exe","Tobii","SYSTEM","Enabled"' + "\n")
    monkeypatch.setattr(st.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, rows, ""))
    ms, tobii = st._task_entries(cfg)
    assert ms.can_disable is False and ms.note == "Windows system task"
    assert tobii.can_disable is True and tobii.note is None
    with pytest.raises(ValueError):
        elevated_ops_for(ms, False, None)
    # even a stale row that still says can_disable never reaches the runner
    stale = StartupEntry("task", "X", r"\Microsoft\Windows\X", "", True, True, True, None, None)
    with pytest.raises(ValueError):
        elevated_ops_for(stale, False, None)
