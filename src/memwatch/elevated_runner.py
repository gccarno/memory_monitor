"""The only code memwatch runs as administrator.

Started through UAC as `pythonw -I -m memwatch.elevated_runner <ops_b64> <out.json>`.
The ops arrive as base64url-encoded JSON **on the command line**, which UAC fixes at
approval time, so no user-writable file can change what runs. Only ops on a fixed
whitelist run, after strict validation; anything else is answered
`{"ok": False, "error": "rejected"}` and never runs. Every op always gets an answer.
Results go to `out.json` in memwatch's data dir: a forged result file can only
misreport what happened, never cause anything to execute. No shell is ever used.
"""
from __future__ import annotations

import base64
import binascii
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
_STARTS = ("demand", "disabled", "auto")
MAX_OPS = 64
MAX_ARG_LEN = 30_000  # encoded ops; well under the 32767-char command-line limit
BUDGET_S = 100  # finish before run_elevated stops waiting (120 s)
_REJECTED = {"ok": False, "error": "rejected"}
_CT_TOLERANCE = 1e-3


def encode_ops(ops: list) -> str:
    return base64.urlsafe_b64encode(json.dumps(ops).encode("utf-8")).decode("ascii")


def decode_ops(arg: str) -> list | None:
    """The op list from a command-line argument, or None when it is unusable."""
    if not isinstance(arg, str) or not arg or len(arg) > MAX_ARG_LEN:
        return None
    try:
        ops = json.loads(base64.urlsafe_b64decode(arg.encode("ascii")).decode("utf-8"))
    except (ValueError, UnicodeError, binascii.Error):
        return None
    return ops if isinstance(ops, list) else None


def is_memwatch_cmdline(cmdline: list[str] | None) -> bool:
    """True for any `python -m memwatch[...]` process (logger, report, runner)."""
    args = [str(a).lower() for a in (cmdline or [])]
    for i, a in enumerate(args):
        if a == "-m":
            mod = args[i + 1] if i + 1 < len(args) else ""
        else:
            mod = a[2:] if a.startswith("-m") else ""  # "-mmemwatch"
        if mod == "memwatch" or mod.startswith("memwatch."):
            return True
    return False


# ---- validation -------------------------------------------------------------

def _approved_subkeys() -> tuple[str, ...]:
    from memwatch.startup import APPROVED_PATHS

    return tuple(APPROVED_PATHS.values())


def _text(v, max_len: int) -> bool:
    return isinstance(v, str) and 0 < len(v) <= max_len and v.isprintable()


def _int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _service_name(v) -> bool:
    return _text(v, 256) and "\\" not in v and "/" not in v


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


def _task_name(v) -> bool:
    if not _text(v, 512) or not v.startswith("\\") or '"' in v or "/" in v or "\\\\" in v:
        return False
    if ".." in v.split("\\"):
        return False
    return not v.lower().startswith("\\microsoft\\windows\\")  # Windows' own tasks


def _validate(op) -> bool:
    if not isinstance(op, dict) or not all(isinstance(k, str) for k in op):
        return False
    name = op.get("op")
    if not isinstance(name, str) or name not in ALLOWED:
        return False
    if set(op) != ALLOWED[name] | {"op"}:
        return False
    if name == "kill":
        return _int(op["pid"]) and op["pid"] > 4 and _number(op["create_time"]) \
            and op["create_time"] > 0
    if name == "stop_service":
        return _service_name(op["name"])
    if name == "set_service_start":
        return _service_name(op["name"]) and isinstance(op["start"], str) \
            and op["start"] in _STARTS
    if name == "set_approved":
        return (isinstance(op["hive"], str) and op["hive"] == "HKLM"
                and isinstance(op["subkey"], str) and op["subkey"] in _approved_subkeys()
                and _text(op["value"], 260) and _hex(op["data_hex"]))
    if name == "set_task":
        return _task_name(op["name"]) and isinstance(op["enabled"], bool)
    return False


def validate(op) -> bool:
    """Strict whitelist check. Never raises: anything unexpected is a rejection."""
    try:
        return _validate(op) is True
    except Exception:
        return False


# ---- execution ------------------------------------------------------------

class Refused(Exception):
    pass


def _protected():
    from memwatch.config import Config

    c = Config()  # built-in lists only; config.toml can only extend them
    return c.protected_names, c.protected_services


def _left(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def _kill(pid: int, create_time: float, deadline: float) -> None:
    import psutil

    names, _ = _protected()
    p = psutil.Process(pid)
    if abs(p.create_time() - create_time) > _CT_TOLERANCE:
        raise Refused("process changed since it was checked (pid reused)")
    low = p.name().lower()
    if pid == os.getpid() or low in names or low == "svchost.exe":
        raise Refused(f"{p.name()} is never stopped")
    try:
        cmdline = p.cmdline()
    except psutil.Error:
        cmdline = None
    if is_memwatch_cmdline(cmdline):
        raise Refused("memwatch will not stop itself")
    p.kill()
    try:
        p.wait(min(5.0, _left(deadline)))
    except psutil.TimeoutExpired:
        raise TimeoutError(f"pid {pid} did not exit") from None


def _service_guard(name: str) -> None:
    if name.lower() in _protected()[1]:
        raise Refused(f"{name} is a Windows core service")


def _stop_service(name: str, deadline: float) -> None:
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
            until = time.monotonic() + min(30.0, _left(deadline))
            while ws.QueryServiceStatus(h)[1] != ws.SERVICE_STOPPED:
                if time.monotonic() >= until:
                    raise TimeoutError(f"{name} did not stop in time")
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


def _schtasks() -> str:
    import win32api

    exe = os.path.join(win32api.GetSystemDirectory(), "schtasks.exe")
    if not os.path.isfile(exe):
        raise FileNotFoundError(exe)
    return exe


def _set_task(name: str, enabled: bool, deadline: float) -> None:
    r = subprocess.run([_schtasks(), "/Change", "/TN", name, "/ENABLE" if enabled else "/DISABLE"],
                       capture_output=True, text=True, timeout=max(1.0, min(60.0, _left(deadline))),
                       creationflags=0x08000000)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout or f"schtasks exit {r.returncode}").strip())


def execute(op: dict, deadline: float) -> None:
    name = op["op"]
    if name == "kill":
        _kill(op["pid"], op["create_time"], deadline)
    elif name == "stop_service":
        _stop_service(op["name"], deadline)
    elif name == "set_service_start":
        _set_service_start(op["name"], op["start"])
    elif name == "set_approved":
        _set_approved(op["subkey"], op["value"], op["data_hex"])
    elif name == "set_task":
        _set_task(op["name"], op["enabled"], deadline)
    else:  # unreachable after validate()
        raise Refused("unknown op")


def run_ops(ops: list, budget_s: float = BUDGET_S) -> list[dict]:
    if not isinstance(ops, list):
        return []
    if len(ops) > MAX_OPS:
        return [dict(_REJECTED) for _ in ops]
    deadline = time.monotonic() + budget_s
    out = []
    for op in ops:
        if not validate(op):
            out.append(dict(_REJECTED))
            continue
        if _left(deadline) <= 0:
            out.append({"ok": False, "error": "out of time; not attempted"})
            continue
        try:
            execute(op, deadline)
            out.append({"ok": True, "error": None})
        except Exception as e:  # report, never crash: each op answers for itself
            out.append({"ok": False, "error": f"{type(e).__name__}: {e}"[:300]})
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        return 2
    ops = decode_ops(argv[0])
    if ops is None:
        return 2
    results = run_ops(ops)
    with open(argv[1], "w", encoding="utf-8") as f:
        json.dump(results, f)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
