"""The only code memwatch runs as administrator.

Started through UAC as `pythonw -I -m memwatch.elevated_runner <in.json> <out.json>`.
Reads a JSON list of ops, executes only ops on a fixed whitelist after strict
validation, and writes one `{"ok": bool, "error": str | None}` per op. Anything that
does not validate is answered `{"ok": False, "error": "rejected"}` and never runs.
No shell is ever used.
"""
from __future__ import annotations

import json
import math
import os
import subprocess
import sys
import time

ALLOWED = {
    "kill": {"pid", "create_time"},
    "stop_service": {"name"},
    "set_service_start": {"name", "start"},
    "set_approved": {"hive", "subkey", "value", "data_hex"},
    "set_task": {"name", "enabled"},
}
_STARTS = {"demand", "disabled", "auto"}
_MAX_OPS = 64
_REJECTED = {"ok": False, "error": "rejected"}
_CT_TOLERANCE = 1e-3


def _approved_subkeys() -> set[str]:
    from memwatch.startup import APPROVED_PATHS

    return set(APPROVED_PATHS.values())


def _clean_text(v, max_len: int) -> bool:
    return (isinstance(v, str) and 0 < len(v) <= max_len
            and all(ch.isprintable() for ch in v))


def _is_number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _service_name(v) -> bool:
    return _clean_text(v, 256) and "\\" not in v and "/" not in v


def _hex(v) -> bool:
    if v is None:
        return True  # set_approved with null data deletes the value
    if not isinstance(v, str) or not v or len(v) % 2 or len(v) > 128:
        return False
    try:
        bytes.fromhex(v)
    except ValueError:
        return False
    return True


def validate(op) -> bool:
    if not isinstance(op, dict):
        return False
    name = op.get("op")
    if not isinstance(name, str) or name not in ALLOWED:
        return False
    if set(op) != ALLOWED[name] | {"op"}:
        return False
    if name == "kill":
        pid, ct = op["pid"], op["create_time"]
        return (isinstance(pid, int) and not isinstance(pid, bool) and pid > 4
                and _is_number(ct) and ct > 0)
    if name == "stop_service":
        return _service_name(op["name"])
    if name == "set_service_start":
        return _service_name(op["name"]) and op["start"] in _STARTS
    if name == "set_approved":
        return (op["hive"] == "HKLM" and op["subkey"] in _approved_subkeys()
                and _clean_text(op["value"], 260) and _hex(op["data_hex"]))
    if name == "set_task":
        n = op["name"]
        return (_clean_text(n, 512) and n.startswith("\\") and '"' not in n
                and isinstance(op["enabled"], bool))
    return False


# ---- execution ------------------------------------------------------------

class Refused(Exception):
    pass


def _protected():
    from memwatch.config import Config

    c = Config()  # built-in lists only; config.toml can only extend them
    return c.protected_names, c.protected_services


def _kill(pid: int, create_time: float) -> None:
    import psutil

    names, _ = _protected()
    p = psutil.Process(pid)
    if abs(p.create_time() - create_time) > _CT_TOLERANCE:
        raise Refused("process changed since it was checked (pid reused)")
    low = p.name().lower()
    if pid == os.getpid() or low in names or low == "svchost.exe":
        raise Refused(f"{p.name()} is never stopped")
    p.kill()
    p.wait(5)


def _service_guard(name: str) -> None:
    if name.lower() in _protected()[1]:
        raise Refused(f"{name} is a Windows core service")


def _stop_service(name: str) -> None:
    import pywintypes
    import win32service as ws

    _service_guard(name)
    scm = ws.OpenSCManager(None, None, ws.SC_MANAGER_CONNECT)
    try:
        h = ws.OpenService(scm, name, ws.SERVICE_STOP | ws.SERVICE_QUERY_STATUS)
        try:
            try:
                ws.ControlService(h, ws.SERVICE_CONTROL_STOP)
            except pywintypes.error as e:
                if e.winerror != 1062:  # ERROR_SERVICE_NOT_ACTIVE: already stopped
                    raise
            deadline = time.monotonic() + 30
            while ws.QueryServiceStatus(h)[1] != ws.SERVICE_STOPPED:
                if time.monotonic() > deadline:
                    raise TimeoutError(f"{name} did not stop within 30 s")
                time.sleep(0.5)
        finally:
            ws.CloseServiceHandle(h)
    finally:
        ws.CloseServiceHandle(scm)


def _set_service_start(name: str, start: str) -> None:
    import win32service as ws

    _service_guard(name)
    code = {"auto": ws.SERVICE_AUTO_START, "demand": ws.SERVICE_DEMAND_START,
            "disabled": ws.SERVICE_DISABLED}[start]
    scm = ws.OpenSCManager(None, None, ws.SC_MANAGER_CONNECT)
    try:
        h = ws.OpenService(scm, name, ws.SERVICE_CHANGE_CONFIG)
        try:
            ws.ChangeServiceConfig(h, ws.SERVICE_NO_CHANGE, code, ws.SERVICE_NO_CHANGE,
                                   None, None, 0, None, None, None, None)
        finally:
            ws.CloseServiceHandle(h)
    finally:
        ws.CloseServiceHandle(scm)


def _set_approved(subkey: str, value: str, data_hex: str | None) -> None:
    import winreg

    access = winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
    with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, subkey, 0, access) as k:
        if data_hex is None:
            try:
                winreg.DeleteValue(k, value)
            except FileNotFoundError:
                pass
        else:
            winreg.SetValueEx(k, value, 0, winreg.REG_BINARY, bytes.fromhex(data_hex))


def _set_task(name: str, enabled: bool) -> None:
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "schtasks.exe")
    r = subprocess.run([exe, "/Change", "/TN", name, "/ENABLE" if enabled else "/DISABLE"],
                       capture_output=True, text=True, timeout=60, creationflags=0x08000000)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout or f"schtasks exit {r.returncode}").strip())


def execute(op: dict) -> None:
    name = op["op"]
    if name == "kill":
        _kill(op["pid"], op["create_time"])
    elif name == "stop_service":
        _stop_service(op["name"])
    elif name == "set_service_start":
        _set_service_start(op["name"], op["start"])
    elif name == "set_approved":
        _set_approved(op["subkey"], op["value"], op["data_hex"])
    elif name == "set_task":
        _set_task(op["name"], op["enabled"])
    else:  # unreachable after validate()
        raise Refused("unknown op")


def run_ops(ops: list) -> list[dict]:
    if len(ops) > _MAX_OPS:
        return [dict(_REJECTED) for _ in ops]
    out = []
    for op in ops:
        if not validate(op):
            out.append(dict(_REJECTED))
            continue
        try:
            execute(op)
            out.append({"ok": True, "error": None})
        except Exception as e:  # report, never crash: each op answers for itself
            out.append({"ok": False, "error": f"{type(e).__name__}: {e}"[:300]})
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        return 2
    inp, outp = argv
    try:
        with open(inp, encoding="utf-8") as f:
            ops = json.load(f)
    except (OSError, ValueError):
        return 2
    if not isinstance(ops, list):
        return 2
    results = run_ops(ops)
    with open(outp, "w", encoding="utf-8") as f:
        json.dump(results, f)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
