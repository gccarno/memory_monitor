"""Startup inventory (Run keys, Startup folders, packaged tasks, logon tasks, services)
and Task-Manager-style toggles via StartupApproved / packaged-task State."""
from __future__ import annotations

import csv
import io
import logging
import ntpath
import os
import re
import struct
import subprocess
import time
import winreg

from memwatch import probe
from memwatch.config import Config
from memwatch.grouping import suite_from_path
from memwatch.models import StartupEntry

log = logging.getLogger(__name__)

_APPROVED = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
APPROVED_PATHS = {
    "run": _APPROVED + r"\Run",
    "run32": _APPROVED + r"\Run32",
    "startup_folder": _APPROVED + r"\StartupFolder",
}
_RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
_RUN32 = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
_PKG = (r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion"
        r"\AppModel\SystemAppData")
_PKG_NOTE = "Windows blocks changes to this packaged service; uninstall the app to remove it"
_FILETIME_EPOCH = 11644473600


def approved_bytes(enabled: bool, filetime: int) -> bytes:
    if enabled:
        return b"\x02" + b"\x00" * 11
    return struct.pack("<I", 3) + struct.pack("<Q", filetime)


def approved_is_enabled(data: bytes | None) -> bool:
    return data is None or len(data) == 0 or data[0] & 1 == 0


def _now_filetime() -> int:
    return int((time.time() + _FILETIME_EPOCH) * 10_000_000)


def _p(root: str, path: str) -> str:
    return f"{root}\\{path}" if root else path


def _hive(name: str):
    return winreg.HKEY_LOCAL_MACHINE if name == "HKLM" else winreg.HKEY_CURRENT_USER


# ---- command parsing ------------------------------------------------------

def parse_command(command: str) -> str:
    """Best-effort extraction of the executable (or wrapped target) from a command line."""
    cmd = os.path.expandvars((command or "").strip())
    if not cmd:
        return ""
    if cmd[0] == '"':
        end = cmd.find('"', 1)
        exe = cmd[1:end] if end > 0 else cmd[1:]
        rest = cmd[end + 1:] if end > 0 else ""
    else:
        m = re.match(r'([^"]+?\.(?:exe|com|bat|cmd))(?=[\s"]|$)', cmd, re.I)
        if m:
            exe, rest = m.group(1), cmd[m.end():]
        else:
            exe, _, rest = cmd.partition(" ")
    base = ntpath.basename(exe).lower()
    if base in ("rundll32", "rundll32.exe"):
        m = re.match(r'\s*"?([^",]+?)"?\s*(?:,|$)', rest)
        if m and ("\\" in m.group(1) or m.group(1).lower().endswith(".dll")):
            return m.group(1).strip()
    elif base in ("cmd", "cmd.exe"):
        m = re.search(r"/[ck]\s+(.*)", rest, re.I)
        if m:
            return parse_command(m.group(1))
    return exe


def _key_for(exe: str, name: str, cfg: Config) -> str | None:
    if not exe or not (("\\" in exe) or re.search(r"\.(exe|com|bat|cmd|dll)$", exe, re.I)):
        return None  # e.g. "COM handler"
    return suite_from_path(exe, ntpath.basename(exe) or name, cfg)[0]


# ---- registry helpers -----------------------------------------------------

def _values(hive, path: str) -> dict[str, object]:
    out: dict[str, object] = {}
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    n, v, _t = winreg.EnumValue(k, i)
                except OSError:
                    break
                out[n] = v
                i += 1
    except OSError:
        pass
    return out


def _read_approved(hive_name: str, kind: str, name: str, root: str) -> bytes | None:
    path = _p(root, APPROVED_PATHS[kind]) if hive_name == "HKCU" else APPROVED_PATHS[kind]
    try:
        with winreg.OpenKey(_hive(hive_name), path, 0, winreg.KEY_READ) as k:
            v, t = winreg.QueryValueEx(k, name)
            return bytes(v) if t == winreg.REG_BINARY else None
    except OSError:
        return None


def _write_approved(name: str, kind: str, data: bytes | None, root: str) -> None:
    path = _p(root, APPROVED_PATHS[kind])
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as k:
        if data is None:
            try:
                winreg.DeleteValue(k, name)
            except FileNotFoundError:
                pass
        else:
            winreg.SetValueEx(k, name, 0, winreg.REG_BINARY, data)


# ---- inventory sources ----------------------------------------------------

def _run_entries(cfg: Config, root: str) -> list[StartupEntry]:
    specs = [("HKCU", _p(root, _RUN), "run", False)]
    if not root:
        specs += [("HKLM", _RUN, "run", True), ("HKLM32", _RUN32, "run32", True)]
    out = []
    for hive_name, path, kind, admin in specs:
        hive = _hive("HKLM" if admin else "HKCU")
        for name, cmd in _values(hive, path).items():
            if not isinstance(cmd, str):
                continue
            enabled = approved_is_enabled(
                _read_approved("HKLM" if admin else "HKCU", kind, name, root))
            exe = parse_command(cmd)
            out.append(StartupEntry("run", name, f"{hive_name}\\{name}", cmd, enabled, admin,
                                    True, None, _key_for(exe, name, cfg)))
    return out


def _lnk_target(path: str) -> str:
    try:
        import pythoncom
        from win32com.shell import shell

        pythoncom.CoInitialize()
        link = pythoncom.CoCreateInstance(shell.CLSID_ShellLink, None,
                                          pythoncom.CLSCTX_INPROC_SERVER, shell.IID_IShellLink)
        link.QueryInterface(pythoncom.IID_IPersistFile).Load(path)
        return link.GetPath(0)[0] or ""
    except Exception:
        return ""


def _folder_entries(cfg: Config) -> list[StartupEntry]:
    folders = [
        (os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"), False),
        (os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp"), True),
    ]
    out = []
    for folder, admin in folders:
        try:
            names = os.listdir(folder)
        except OSError:
            continue
        for fn in names:
            if fn.lower() == "desktop.ini":
                continue
            full = os.path.join(folder, fn)
            target = _lnk_target(full) if fn.lower().endswith(".lnk") else full
            enabled = approved_is_enabled(
                _read_approved("HKLM" if admin else "HKCU", "startup_folder", fn, ""))
            out.append(StartupEntry("startup_folder", fn, full, target, enabled, admin, True,
                                    None, _key_for(target, fn, cfg)))
    return out


def _subkeys(hive, path: str) -> list[str]:
    out = []
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return out


def _packaged_entries(cfg: Config) -> list[StartupEntry]:
    out = []
    for pkg in _subkeys(winreg.HKEY_CURRENT_USER, _PKG):
        for task in _subkeys(winreg.HKEY_CURRENT_USER, f"{_PKG}\\{pkg}"):
            state = _values(winreg.HKEY_CURRENT_USER, f"{_PKG}\\{pkg}\\{task}").get("State")
            if not isinstance(state, int):
                continue
            short = pkg.split("_")[0]
            key = suite_from_path(rf"C:\Program Files\WindowsApps\{pkg}\app.exe", short, cfg)[0]
            out.append(StartupEntry("packaged", f"{short} ({task})", f"{pkg}\\{task}", "",
                                    state in (2, 4), False, True, None, key))
    return out


WINDOWS_TASK_NOTE = "Windows system task"


def is_windows_task(location: str) -> bool:
    """Tasks under \\Microsoft\\Windows\\ belong to Windows: shown read-only, never changed."""
    return location.lower().startswith("\\microsoft\\windows\\")


def _user_names() -> set[str]:
    u = os.environ.get("USERNAME", "").lower()
    if not u:
        return set()
    return {u, f"{os.environ.get('USERDOMAIN', '').lower()}\\{u}"}


def _task_entries(cfg: Config) -> list[StartupEntry]:
    try:
        r = subprocess.run(["schtasks", "/query", "/fo", "csv", "/v"], capture_output=True,
                           text=True, timeout=60, creationflags=0x08000000)
        text = r.stdout
    except (OSError, subprocess.SubprocessError) as e:
        log.warning("schtasks query failed: %s", e)
        return []
    me = _user_names()
    seen: set[str] = set()
    out = []
    for row in csv.DictReader(io.StringIO(text)):
        name = row.get("TaskName")
        if not name or name == "TaskName" or name in seen:
            continue
        if "logon" not in (row.get("Schedule Type") or "").lower():
            continue
        seen.add(name)
        cmd = (row.get("Task To Run") or "").strip()
        author = (row.get("Author") or "").lower()
        runas = (row.get("Run As User") or "").lower()
        mine = author in me or (author in ("", "n/a") and runas in me)
        admin = not (name.startswith("\\") and mine)
        exe = parse_command(cmd) if cmd and cmd.upper() != "N/A" else ""
        system = is_windows_task(name)
        out.append(StartupEntry("task", ntpath.basename(name), name, cmd,
                                (row.get("Scheduled Task State") or "").lower() == "enabled",
                                admin, not system, WINDOWS_TASK_NOTE if system else None,
                                _key_for(exe, name, cfg)))
    return out


def task_enabled(name: str) -> bool | None:
    """Live state of one scheduled task; None when it cannot be read."""
    try:
        r = subprocess.run(["schtasks", "/query", "/tn", name, "/fo", "csv", "/nh"],
                           capture_output=True, text=True, timeout=30,
                           creationflags=0x08000000)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    for row in csv.reader(io.StringIO(r.stdout)):
        if len(row) >= 3:
            return row[2].strip().lower() != "disabled"
    return None


def live_enabled(entry: StartupEntry, root: str = "") -> bool | None:
    """Current state of a non-service entry read from Windows, or None when unreadable."""
    try:
        if entry.source in ("run", "startup_folder"):
            hive, kind, name = _approved_target(entry)
            return approved_is_enabled(
                _read_approved(hive, kind, name, root if hive == "HKCU" else ""))
        if entry.source == "packaged":
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _pkg_key(entry, root), 0,
                                winreg.KEY_READ) as k:
                return winreg.QueryValueEx(k, "State")[0] in (2, 4)
        if entry.source == "task":
            return task_enabled(entry.location)
    except OSError:
        return None
    return None


def _service_entries(cfg: Config) -> list[StartupEntry]:
    out = []
    for s in probe.all_services():
        if s.start_type != "automatic":
            continue
        low = s.binpath.lower()
        if "svchost.exe" in low:
            key = f"service:{s.name.lower()}"
        else:
            key = _key_for(parse_command(s.binpath), s.name, cfg)
        packaged = "\\windowsapps\\" in low
        out.append(StartupEntry("service", s.display_name or s.name, s.name, s.binpath, True,
                                True, not packaged, _PKG_NOTE if packaged else None, key))
    return out


def inventory(cfg: Config, root: str = "") -> list[StartupEntry]:
    out = _run_entries(cfg, root)
    if not root:
        out += _folder_entries(cfg) + _packaged_entries(cfg) + _task_entries(cfg)
        out += _service_entries(cfg)
    return out


# ---- toggles --------------------------------------------------------------

def _approved_target(entry: StartupEntry) -> tuple[str, str, str]:
    """(hive, kind, value name) for a StartupApproved-backed entry."""
    if entry.source == "startup_folder":
        return ("HKLM" if entry.needs_admin else "HKCU", "startup_folder",
                ntpath.basename(entry.location))
    hive, _, name = entry.location.partition("\\")
    return ("HKLM" if hive.startswith("HKLM") else "HKCU",
            "run32" if hive == "HKLM32" else "run", name)


def _pkg_key(entry: StartupEntry, root: str) -> str:
    return _p(root, f"{_PKG}\\{entry.location}")


def apply_toggle(entry: StartupEntry, enabled: bool, mode: str | None = None,
                 root: str = "") -> dict:
    """Switch a non-admin entry; returns the `before` state for Undo."""
    if entry.needs_admin or not entry.can_disable:
        raise PermissionError(f"{entry.name} cannot be changed without elevation")
    if entry.source == "packaged":
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _pkg_key(entry, root), 0,
                            winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
            old = winreg.QueryValueEx(k, "State")[0]
            winreg.SetValueEx(k, "State", 0, winreg.REG_DWORD, 2 if enabled else 1)
        return {"state": int(old)}
    if entry.source in ("run", "startup_folder"):
        _, kind, name = _approved_target(entry)
        old = _read_approved("HKCU", kind, name, root)
        _write_approved(name, kind, approved_bytes(enabled, 0 if enabled else _now_filetime()), root)
        return {"approved": old.hex() if old is not None else None}
    raise ValueError(f"unsupported source {entry.source}")


def restore(entry: StartupEntry, before: dict, root: str = "") -> None:
    if entry.source not in ("run", "startup_folder", "packaged") or entry.needs_admin:
        raise ValueError(f"restore does not support {entry.source} entry {entry.name!r}")
    if entry.source == "packaged":
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _pkg_key(entry, root), 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "State", 0, winreg.REG_DWORD, int(before["state"]))
        return
    _, kind, name = _approved_target(entry)
    raw = before.get("approved")
    _write_approved(name, kind, bytes.fromhex(raw) if raw is not None else None, root)


def elevated_ops_for(entry: StartupEntry, enabled: bool, mode: str | None) -> list[dict]:
    """Ops for the UAC runner (admin-only changes). Fails closed on anything unsupported."""
    if not entry.can_disable:
        raise ValueError(f"{entry.name!r} cannot be changed: {entry.note or 'no supported switch'}")
    if entry.source == "task" and is_windows_task(entry.location):
        raise ValueError(f"{entry.name!r} cannot be changed: {WINDOWS_TASK_NOTE}")
    if entry.source in ("run", "startup_folder"):
        hive, kind, name = _approved_target(entry)
        data = approved_bytes(enabled, 0 if enabled else _now_filetime())
        return [{"op": "set_approved", "hive": hive, "subkey": APPROVED_PATHS[kind],
                 "value": name, "data_hex": data.hex()}]
    if entry.source == "task":
        return [{"op": "set_task", "name": entry.location, "enabled": enabled}]
    if entry.source == "service":
        if enabled:
            starts = {None: "auto", "auto": "auto", "demand": "demand", "manual": "demand"}
        else:
            starts = {"manual": "demand", "disabled": "disabled"}
        if mode not in starts:
            raise ValueError(f"invalid service mode {mode!r}")
        return [{"op": "set_service_start", "name": entry.location, "start": starts[mode]}]
    raise ValueError(f"{entry.source} entries are changed with apply_toggle, not elevated ops")
