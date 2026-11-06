from __future__ import annotations

import winreg

import pytest

from memwatch.models import StartupEntry
from memwatch.startup import (
    apply_toggle, approved_bytes, approved_is_enabled, elevated_ops_for, inventory,
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
    assert e.location == "HKCU\DummyApp"
    before = apply_toggle(e, False, root=test_root)
    assert before == {"approved": None}
    assert not find().enabled
    restore(e, before, root=test_root)
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


def test_service_ops_respect_mode():
    e = StartupEntry("service", "Tobii Service", "Tobii Service", "", True, True, True, None, "suite:tobii")
    assert elevated_ops_for(e, False, "manual") == [{"op": "set_service_start", "name": "Tobii Service", "start": "demand"}]
    assert elevated_ops_for(e, False, "disabled")[0]["start"] == "disabled"
    assert elevated_ops_for(e, True, None)[0]["start"] == "auto"


def test_elevated_ops_task_and_hklm_run():
    t = StartupEntry("task", "Foo", r"\Foo", "", True, True, True, None, None)
    assert elevated_ops_for(t, False, None) == [{"op": "set_task", "name": r"\Foo", "enabled": False}]
    r = StartupEntry("run", "Foo", "HKLM\Foo", "", True, True, True, None, None)
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
