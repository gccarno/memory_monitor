"""The whitelisted runner, run without elevation. Only ever kills a sleeper this test
spawned; no registry, service or task op is executed against the real system."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import psutil
import pytest

from memwatch import elevate, elevated_runner
from memwatch.elevated_runner import decode_ops, encode_ops, is_memwatch_cmdline
from memwatch.startup import APPROVED_PATHS

FIXTURES = Path(__file__).parent / "fixtures"
PY = getattr(sys, "_base_executable", sys.executable)  # no venv launcher: pid == script
REJECTED = {"ok": False, "error": "rejected"}


@pytest.fixture
def sleeper():
    p = subprocess.Popen([PY, str(FIXTURES / "sleeper.py")])
    try:
        yield p
    finally:
        if p.poll() is None:
            p.kill()
        p.wait(10)


def run_runner(tmp_path, ops):
    out = tmp_path / "out.json"
    assert elevated_runner.main([encode_ops(ops), str(out)]) == 0
    return json.loads(out.read_text())


def test_runner_rejects_unknown_and_extra_keys(tmp_path):
    out = run_runner(tmp_path, [{"op": "format_c"}, {"op": "kill", "pid": 1, "create_time": 0, "x": 1}])
    assert out == [{"ok": False, "error": "rejected"}] * 2


RUN = APPROVED_PATHS["run"]
BAD_OPS = [
    "not a dict",
    None,
    [1, 2],
    {"pid": 5, "create_time": 1.0},  # no op
    {"op": ["kill"], "pid": 1234, "create_time": 1.0},  # unhashable op name
    {"op": "kill", "pid": 1234},  # missing key
    {"op": "kill", "pid": True, "create_time": 1.0},
    {"op": "kill", "pid": "1234", "create_time": 1.0},
    {"op": "kill", "pid": 1234.0, "create_time": 1.0},
    {"op": "kill", "pid": 4, "create_time": 1.0},  # System
    {"op": "kill", "pid": 0, "create_time": 1.0},
    {"op": "kill", "pid": 1234, "create_time": "1.0"},
    {"op": "kill", "pid": 1234, "create_time": True},
    {"op": "kill", "pid": 1234, "create_time": float("nan")},
    {"op": "kill", "pid": 1234, "create_time": [1.0]},
    {"op": "stop_service", "name": ""},
    {"op": "stop_service", "name": "a\\b"},
    {"op": "stop_service", "name": 7},
    {"op": "stop_service", "name": ["Foo"]},
    {"op": "stop_service", "name": "Foo\x00"},
    {"op": "set_service_start", "name": "Foo", "start": "boot"},
    {"op": "set_service_start", "name": "Foo", "start": "manual"},
    {"op": "set_service_start", "name": "Foo", "start": []},
    {"op": "set_service_start", "name": "Foo", "start": {"auto": 1}},
    {"op": "set_service_start", "name": "Foo", "start": None},
    {"op": "set_approved", "hive": "HKCU", "subkey": RUN, "value": "X", "data_hex": "02"},
    {"op": "set_approved", "hive": ["HKLM"], "subkey": RUN, "value": "X", "data_hex": "02"},
    {"op": "set_approved", "hive": "HKLM", "subkey": {}, "value": "X", "data_hex": "02"},
    {"op": "set_approved", "hive": "HKLM", "subkey": [RUN], "value": "X", "data_hex": "02"},
    {"op": "set_approved", "hive": "HKLM", "subkey": r"Software\Microsoft\Windows\CurrentVersion\Run",
     "value": "X", "data_hex": "02"},
    {"op": "set_approved", "hive": "HKLM", "subkey": RUN, "value": "", "data_hex": "02"},
    {"op": "set_approved", "hive": "HKLM", "subkey": RUN, "value": None, "data_hex": "02"},
    {"op": "set_approved", "hive": "HKLM", "subkey": RUN, "value": "X", "data_hex": "0"},
    {"op": "set_approved", "hive": "HKLM", "subkey": RUN, "value": "X", "data_hex": "zz"},
    {"op": "set_approved", "hive": "HKLM", "subkey": RUN, "value": "X", "data_hex": ""},
    {"op": "set_approved", "hive": "HKLM", "subkey": RUN, "value": "X", "data_hex": 2},
    {"op": "set_approved", "hive": "HKLM", "subkey": RUN, "value": "X", "data_hex": ["02"]},
    {"op": "set_task", "name": r"\Foo", "enabled": "no"},
    {"op": "set_task", "name": r"\Foo", "enabled": 0},
    {"op": "set_task", "name": r"\Foo", "enabled": None},
    {"op": "set_task", "name": r"\Foo\" /DELETE \"x", "enabled": False},
    {"op": "set_task", "name": "Foo", "enabled": False},  # must be a full task path
    {"op": "set_task", "name": "\\Foo\n", "enabled": False},
    {"op": "set_task", "name": ["\\Foo"], "enabled": False},
    {"op": "set_task", "name": r"\Microsoft\Windows\Defrag\ScheduledDefrag", "enabled": False},
    {"op": "set_task", "name": r"\MICROSOFT\windows\UpdateOrchestrator\Reboot", "enabled": False},
    {"op": "set_task", "name": r"\\Microsoft\Windows\X", "enabled": False},
    {"op": "set_task", "name": r"\Vendor\..\Microsoft\Windows\X", "enabled": False},
    {"op": "set_task", "name": "/Microsoft/Windows/X", "enabled": False},
]


def test_runner_rejects_malformed_ops(tmp_path):
    assert run_runner(tmp_path, BAD_OPS) == [REJECTED] * len(BAD_OPS)


def test_validate_never_raises():
    class Weird(dict):
        def keys(self):
            raise RuntimeError("boom")
    assert elevated_runner.validate(Weird(op="kill")) is False
    assert elevated_runner.run_ops([{1: 2}, object()]) == [REJECTED, REJECTED]


def test_validate_accepts_well_formed_ops():
    good = [
        {"op": "kill", "pid": 1234, "create_time": 1.5},
        {"op": "kill", "pid": 1234, "create_time": 2},
        {"op": "stop_service", "name": "Tobii Service"},
        *({"op": "set_service_start", "name": "Foo", "start": s} for s in ("demand", "disabled", "auto")),
        *({"op": "set_approved", "hive": "HKLM", "subkey": sk, "value": "X", "data_hex": "02" + "00" * 11}
          for sk in APPROVED_PATHS.values()),
        {"op": "set_approved", "hive": "HKLM", "subkey": RUN, "value": "X", "data_hex": None},
        {"op": "set_task", "name": r"\Vendor\Updater Logon", "enabled": True},
        {"op": "set_task", "name": r"\Microsoft\Office\Office Feature Updates", "enabled": False},
    ]
    assert all(elevated_runner.validate(op) for op in good)
    assert not any(elevated_runner.validate(op) for op in BAD_OPS)


def test_runner_kill_rechecks_create_time(tmp_path, sleeper):
    ct = psutil.Process(sleeper.pid).create_time()
    out = run_runner(tmp_path, [{"op": "kill", "pid": sleeper.pid, "create_time": ct - 100}])
    assert out[0]["ok"] is False and out[0]["error"] != "rejected"
    assert sleeper.poll() is None  # untouched
    out = run_runner(tmp_path, [{"op": "kill", "pid": sleeper.pid, "create_time": ct}])
    assert out == [{"ok": True, "error": None}]
    assert sleeper.wait(10) is not None


def test_runner_kill_refuses_memwatch_processes(tmp_path):
    p = subprocess.Popen([PY, str(FIXTURES / "sleeper.py"), "-m", "memwatch"])
    try:
        ct = psutil.Process(p.pid).create_time()
        out = run_runner(tmp_path, [{"op": "kill", "pid": p.pid, "create_time": ct}])
        assert out[0]["ok"] is False and "memwatch" in out[0]["error"]
        assert p.poll() is None
    finally:
        p.kill()
        p.wait(10)


def test_is_memwatch_cmdline():
    assert is_memwatch_cmdline(["pythonw.exe", "-m", "memwatch", "log"])
    assert is_memwatch_cmdline(["python", "-I", "-m", "memwatch.elevated_runner", "x", "y"])
    assert is_memwatch_cmdline(["python", "-mmemwatch", "report"])
    assert not is_memwatch_cmdline(["python", "-m", "memwatchers"])
    assert not is_memwatch_cmdline(["python", "-m", "pytest", "memwatch"])
    assert not is_memwatch_cmdline(None)


def test_runner_out_of_time_does_not_execute(sleeper):
    ct = psutil.Process(sleeper.pid).create_time()
    out = elevated_runner.run_ops([{"op": "kill", "pid": sleeper.pid, "create_time": ct}],
                                  budget_s=0)
    assert out[0]["ok"] is False and "time" in out[0]["error"]
    assert sleeper.poll() is None


def test_runner_rejects_too_many_ops(tmp_path):
    ops = [{"op": "stop_service", "name": "Foo"}] * (elevated_runner.MAX_OPS + 1)
    assert run_runner(tmp_path, ops) == [REJECTED] * len(ops)


def test_runner_module_entry_point(tmp_path):
    out = tmp_path / "out.json"
    r = subprocess.run([sys.executable, "-m", "memwatch.elevated_runner",
                        encode_ops([{"op": "nope"}]), str(out)], timeout=60)
    assert r.returncode == 0 and json.loads(out.read_text()) == [REJECTED]


def test_runner_bad_argument(tmp_path):
    out = tmp_path / "out.json"
    for arg in (encode_ops({"op": "kill"}),  # not a list
                "!!not base64!!",
                encode_ops([{"op": "nope"}] * 5000),  # over-long
                ""):
        assert elevated_runner.main([arg, str(out)]) != 0
    assert elevated_runner.main([]) != 0
    assert not out.exists()
    assert decode_ops(encode_ops([{"op": "x"}])) == [{"op": "x"}]


def test_schtasks_from_system_directory():
    import win32api

    exe = elevated_runner._schtasks()
    assert os.path.dirname(exe).lower() == win32api.GetSystemDirectory().lower()
    assert os.path.isfile(exe)


# ---- run_elevated plumbing (the UAC launch itself is replaced) -------------

def _fake_launch(calls):
    def launch(exe, args, timeout_s):
        calls.append((exe, args, timeout_s))
        assert args[:3] == ["-I", "-m", "memwatch.elevated_runner"]
        assert decode_ops(args[3]) == [{"op": "nope"}]
        r = subprocess.run([sys.executable, *args], timeout=60)
        return r.returncode
    return launch


def test_run_elevated_round_trip_cleans_up(cfg, tmp_path, monkeypatch):
    cfg.data_dir = tmp_path
    calls = []
    monkeypatch.setattr(elevate, "_run_as_admin", _fake_launch(calls))
    assert elevate.run_elevated([{"op": "nope"}], cfg) == [REJECTED]
    exe, args, timeout_s = calls[0]
    assert Path(exe).name.lower() == "pythonw.exe" and timeout_s == 120
    assert len(args) == 5 and set(args[3]) <= set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")
    assert Path(args[4]).parent == tmp_path and Path(args[4]).name.startswith("elev-")
    assert args[4].endswith("-out.json")
    assert list(tmp_path.iterdir()) == []  # no ops file is ever written; result deleted


def test_run_elevated_refuses_oversized_batches(cfg, tmp_path, monkeypatch):
    cfg.data_dir = tmp_path
    monkeypatch.setattr(elevate, "_run_as_admin", lambda *a: pytest.fail("launched"))
    out = elevate.run_elevated([{"op": "stop_service", "name": "Foo"}] * 65, cfg)
    assert len(out) == 65 and not any(r["ok"] for r in out)
    long_ops = [{"op": "set_task", "name": "\\" + "x" * 500, "enabled": False}] * 60
    out = elevate.run_elevated(long_ops, cfg)
    assert len(out) == 60 and not any(r["ok"] for r in out)


def test_run_elevated_declined(cfg, tmp_path, monkeypatch):
    cfg.data_dir = tmp_path
    monkeypatch.setattr(elevate, "_run_as_admin", lambda exe, args, t: "declined")
    assert elevate.run_elevated([{"op": "nope"}], cfg) == "declined"
    assert list(tmp_path.iterdir()) == []


def test_run_elevated_missing_or_short_output_fails_every_op(cfg, tmp_path, monkeypatch):
    cfg.data_dir = tmp_path
    monkeypatch.setattr(elevate, "_run_as_admin", lambda exe, args, t: None)  # timed out
    out = elevate.run_elevated([{"op": "a"}, {"op": "b"}], cfg)
    assert len(out) == 2 and all(r["ok"] is False and r["error"] for r in out)

    def short(exe, args, t):
        Path(args[4]).write_text(json.dumps([{"ok": True, "error": None}]))
        return 0
    monkeypatch.setattr(elevate, "_run_as_admin", short)
    out = elevate.run_elevated([{"op": "a"}, {"op": "b"}], cfg)
    assert [r["ok"] for r in out] == [False, False]
    assert list(tmp_path.iterdir()) == []


def test_run_elevated_no_ops_never_launches(cfg, tmp_path, monkeypatch):
    cfg.data_dir = tmp_path
    monkeypatch.setattr(elevate, "_run_as_admin", lambda *a: pytest.fail("launched"))
    assert elevate.run_elevated([], cfg) == []


def test_error_1223_maps_to_declined(monkeypatch):
    import pywintypes
    from win32com.shell import shell

    def boom(**kw):
        raise pywintypes.error(1223, "ShellExecuteEx", "The operation was canceled by the user.")
    monkeypatch.setattr(shell, "ShellExecuteEx", boom)
    assert elevate._run_as_admin("x.exe", ["-I"], 1) == "declined"
