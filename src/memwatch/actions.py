"""Stop, force-kill, disable-at-startup and undo. Every action re-verifies what it is
about to touch; admin-only work goes through one elevator call."""
from __future__ import annotations

import dataclasses
import sqlite3
import time

import psutil

from memwatch import probe, startup
from memwatch.config import Config
from memwatch.db import get_action, mark_undone, record_action
from memwatch.elevate import Elevator, run_elevated
from memwatch.elevated_runner import is_memwatch_cmdline
from memwatch.models import ActionRecord, ActionResult, AppGroup, StartupEntry
from memwatch.suggest import default_dependents

_CT_TOLERANCE = 1e-3
_STILL_OPEN = "Still open; it may be waiting for you (unsaved work?)"
_PROTECTED_MSG = "Windows core processes are never stopped"
_SELF_MSG = "memwatch will not stop itself"
_DECLINED = "Administrator approval was declined; nothing that needs it was changed"
_FORCE_GRACE_S = 3
_EXIT_WAIT_S = 5
_LOCAL_SOURCES = ("run", "startup_folder", "packaged")

_dependents = default_dependents  # module-level so tests can substitute it


def _elevator(elevator: Elevator | None, cfg: Config) -> Elevator:
    return elevator if elevator is not None else (lambda ops: run_elevated(ops, cfg))


def _call(elevator: Elevator, ops: list[dict]) -> list[dict] | str:
    """Call the elevator; any malformed answer counts as every op failing."""
    res = elevator(ops)
    if res == "declined":
        return "declined"
    if not isinstance(res, list) or len(res) != len(ops):
        return [{"ok": False, "error": "no result"} for _ in ops]
    return [{"ok": True, "error": None}
            if isinstance(r, dict) and r.get("ok") is True
            else {"ok": False, "error": str((r.get("error") if isinstance(r, dict) else None)
                                            or "failed")}
            for r in res]


# ---- process helpers ------------------------------------------------------

def _guarded_pids() -> set[int]:
    """memwatch itself, its descendants, and the process tree that launched it."""
    me = psutil.Process()
    out = {me.pid}
    for rel in (me.parents, lambda: me.children(recursive=True)):
        try:
            out |= {p.pid for p in rel()}
        except psutil.Error:
            pass
    return out


def _live(pids: list[tuple[int, float]]) -> list[psutil.Process]:
    """Processes that still exist with the recorded create_time (pid reuse is dropped)."""
    out = []
    for pid, ct in pids:
        try:
            p = psutil.Process(pid)
            if abs(p.create_time() - ct) <= _CT_TOLERANCE:
                out.append(p)
        except psutil.Error:
            pass
    return out


def _name(p: psutil.Process) -> str:
    try:
        return p.name().lower()
    except psutil.Error:
        return ""


def _is_memwatch(p: psutil.Process) -> bool:
    try:
        return is_memwatch_cmdline(p.cmdline())
    except psutil.Error:
        return False  # unreadable: elevated or other users' processes, never memwatch's


def _untouchable(p: psutil.Process, cfg: Config, guarded: set[int],
                 svchost_ok: bool = False) -> str | None:
    """Why this process must never be stopped directly, or None. `svchost_ok` lets
    stop_now see service hosts; it stops their services and never terminates them."""
    if p.pid in guarded or _is_memwatch(p):
        return _SELF_MSG
    if p.pid in (0, 4):
        return _PROTECTED_MSG
    try:
        name = p.name()
    except psutil.Error:
        return f"pid {p.pid} could not be identified and was left alone."
    low = name.lower()
    if low in cfg.protected_names:
        return f"{name} is a Windows core process and is never stopped."
    if low == "svchost.exe" and not svchost_ok:
        return f"{name} (pid {p.pid}) hosts Windows services and is not terminated directly."
    return None


def _alive(p: psutil.Process) -> bool:
    try:
        return p.is_running() and p.status() != psutil.STATUS_ZOMBIE
    except psutil.Error:
        return False


def _windows_by_pid() -> dict[int, list[int]]:
    """Visible top-level windows per pid (cloaked ones too, e.g. other desktops)."""
    import win32gui
    import win32process

    out: dict[int, list[int]] = {}

    def cb(hwnd, _):
        try:
            if win32gui.IsWindowVisible(hwnd):
                _tid, pid = win32process.GetWindowThreadProcessId(hwnd)
                out.setdefault(pid, []).append(hwnd)
        except Exception:
            pass
        return True

    win32gui.EnumWindows(cb, None)
    return out


def _post_close(hwnds: list[int]) -> None:
    import win32con
    import win32gui

    for h in hwnds:
        try:
            win32gui.PostMessage(h, win32con.WM_CLOSE, 0, 0)
        except Exception:
            pass


def _kill_op(p: psutil.Process) -> dict:
    return {"op": "kill", "pid": p.pid, "create_time": p.create_time()}


def _terminate(procs: list[psutil.Process], how: str) -> list[psutil.Process]:
    """terminate()/kill() each; returns those that need elevation."""
    denied = []
    for p in procs:
        try:
            getattr(p, how)()
        except psutil.NoSuchProcess:
            pass
        except psutil.AccessDenied:
            denied.append(p)
    return denied


def _service_running(name: str) -> bool:
    try:
        return psutil.win_service_get(name).status() not in ("stopped", "stop_pending")
    except psutil.NoSuchProcess:
        return False
    except psutil.Error:
        return True  # cannot tell: try to stop it


def _join(notes: list[str]) -> str:
    return " ".join(dict.fromkeys(notes))


def _remaining(*groups: list[psutil.Process]) -> list[int]:
    return sorted({p.pid for g in groups for p in g if _alive(p)})


def _finish(label: str, targets: list[psutil.Process], left: list[psutil.Process],
            notes: list[str], any_change: bool, incomplete: bool) -> ActionResult:
    """`targets` were acted on; `left` are group processes deliberately left alone."""
    remaining = _remaining(targets, left)
    extra = (" " + _join(notes)) if notes else ""
    if not remaining and not incomplete:
        return ActionResult("done", f"Stopped {label}.{extra}")
    if any_change or any(not _alive(p) for p in targets):
        return ActionResult("partial", f"Stopped part of {label}.{extra}", remaining)
    return ActionResult("failed", f"Could not stop {label}.{extra}", remaining)


def _declined(label: str, changed: bool, notes: list[str], *groups) -> ActionResult:
    """Elevation was declined: 'partial' when unelevated work already took effect."""
    remaining = _remaining(*groups)
    if changed:
        msg = f"Stopped part of {label}. {_DECLINED}. {_join(notes)}".strip()
        return ActionResult("partial", msg, remaining)
    return ActionResult("declined", _DECLINED, remaining)


def _guard_group(group: AppGroup, cfg: Config, svchost_ok: bool = False):
    """(live, usable, left alone, notes), or an ActionResult to return now."""
    if group.kind == "protected":
        return ActionResult("failed", _PROTECTED_MSG)
    live = _live(group.pids)
    guarded = _guarded_pids()
    usable, left, notes = [], [], []
    for p in live:
        why = _untouchable(p, cfg, guarded, svchost_ok)
        if why:
            left.append(p)
            notes.append(why)
        else:
            usable.append(p)
    if live and not usable and set(notes) == {_SELF_MSG}:
        return ActionResult("failed", _SELF_MSG, _remaining(left))
    return live, usable, left, notes


# ---- stop / force ---------------------------------------------------------

def stop_now(group: AppGroup, cfg: Config, elevator: Elevator | None = None) -> ActionResult:
    guard = _guard_group(group, cfg, svchost_ok=True)
    if isinstance(guard, ActionResult):
        return guard
    live, procs, left, notes = guard
    hosts = probe.services_by_pid()
    group_svcs = {s.lower() for s in group.services}
    svc_hosts = []  # exit once their services stop
    for p in list(procs):
        hosted = {s.name.lower() for s in hosts.get(p.pid, [])}
        if hosted:
            procs.remove(p)
            if hosted <= group_svcs:
                svc_hosts.append(p)
            else:
                left.append(p)
                notes.append(f"pid {p.pid} also runs other services and was left alone.")
        elif _name(p) == "svchost.exe":
            procs.remove(p)
            left.append(p)
            notes.append(f"svchost.exe (pid {p.pid}) runs no service of this app "
                         "and was left alone.")
    running = [s for s in group.services if _service_running(s)]
    if not live and not running:
        return ActionResult("already_stopped", f"{group.label} is not running.")
    if not procs and not svc_hosts and not running:
        return ActionResult("failed", _join(notes), _remaining(left))

    # Windowed processes: WM_CLOSE only, then wait. Nothing else is touched until
    # every window has gone.
    windows = _windows_by_pid()
    windowed = [p for p in procs if windows.get(p.pid)]
    windowless = [p for p in procs if not windows.get(p.pid)]
    if windowed:
        for p in windowed:
            _post_close(windows[p.pid])
        _gone, still = psutil.wait_procs(windowed, timeout=cfg.close_timeout_s)
        if still:
            return ActionResult("still_open", _STILL_OPEN, _remaining(procs, svc_hosts))
        psutil.wait_procs(windowless, timeout=1)  # helpers often exit with their window
        windowless = [p for p in windowless if _alive(p)]

    # Windowless processes: terminate(); AccessDenied goes to the elevator.
    ops = [_kill_op(p) for p in _terminate(windowless, "terminate")]

    # Services: only those without running dependents.
    skipped = False
    for name in running:
        if name.lower() in cfg.protected_services:
            notes.append(f"{name} is a Windows core service and was not stopped.")
            skipped = True
            continue
        deps = _dependents(name)
        if deps:
            notes.append(f"{name} was not stopped: other running services depend on it "
                         f"({', '.join(deps)}).")
            skipped = True
            continue
        ops.append({"op": "stop_service", "name": name})

    failed_ops = stopped_svc = False
    if ops:
        res = _call(_elevator(elevator, cfg), ops)
        if res == "declined":
            changed = bool(windowed) or any(not _alive(p) for p in windowless)
            return _declined(group.label, changed, notes, procs, svc_hosts, left)
        for op, r in zip(ops, res):
            if r["ok"]:
                stopped_svc = stopped_svc or op["op"] == "stop_service"
                continue
            failed_ops = True
            what = op["name"] if op["op"] == "stop_service" else f"pid {op['pid']}"
            notes.append(f"Could not stop {what}: {r['error']}.")
    psutil.wait_procs(windowless + svc_hosts, timeout=_EXIT_WAIT_S)
    return _finish(group.label, windowed + windowless + svc_hosts, left, notes,
                   any_change=bool(windowed) or stopped_svc,
                   incomplete=skipped or failed_ops)


def force_kill(group: AppGroup, cfg: Config, elevator: Elevator | None = None) -> ActionResult:
    guard = _guard_group(group, cfg)
    if isinstance(guard, ActionResult):
        return guard
    live, procs, left, notes = guard
    if not live:
        return ActionResult("already_stopped", f"{group.label} is not running.")
    guarded = _guarded_pids()
    targets: dict[int, psutil.Process] = {p.pid: p for p in procs}
    stack = list(procs)
    while stack:  # children(recursive=True) by hand, so untouchable subtrees are pruned
        try:
            kids = stack.pop().children()
        except psutil.Error:
            continue
        for c in kids:
            if c.pid in targets:
                continue
            why = _untouchable(c, cfg, guarded)
            if why:
                notes.append(why)
                continue
            targets[c.pid] = c
            stack.append(c)
    if not targets:
        return ActionResult("failed", _join(notes), _remaining(left))
    procs = list(targets.values())
    denied = {p.pid: p for p in _terminate(procs, "terminate")}
    _gone, survivors = psutil.wait_procs([p for p in procs if p.pid not in denied],
                                         timeout=_FORCE_GRACE_S)
    for p in _terminate(survivors, "kill"):
        denied[p.pid] = p
    failed_ops = False
    if denied:
        ops = [_kill_op(p) for p in denied.values()]
        res = _call(_elevator(elevator, cfg), ops)
        if res == "declined":
            changed = any(not _alive(p) for p in procs if p.pid not in denied)
            return _declined(group.label, changed, notes, procs, left)
        for op, r in zip(ops, res):
            if not r["ok"]:
                failed_ops = True
                notes.append(f"Could not stop pid {op['pid']}: {r['error']}.")
    psutil.wait_procs(procs, timeout=_EXIT_WAIT_S)
    return _finish(group.label, procs, left, notes, any_change=False, incomplete=failed_ops)


# ---- startup --------------------------------------------------------------

def _is_local(e: StartupEntry) -> bool:
    return e.source in _LOCAL_SOURCES and not e.needs_admin


def _service_start(name: str) -> str | None:
    """Current start type as a runner `start` value. None when it cannot be read or is
    anything but plain auto/demand/disabled (boot, system, delayed auto): undo could not
    put it back exactly."""
    try:
        import win32service as ws

        scm = ws.OpenSCManager(None, None, ws.SC_MANAGER_CONNECT)
        try:
            h = ws.OpenService(scm, name, ws.SERVICE_QUERY_CONFIG)
            try:
                code = ws.QueryServiceConfig(h)[1]
                delayed = code == ws.SERVICE_AUTO_START and bool(ws.QueryServiceConfig2(
                    h, ws.SERVICE_CONFIG_DELAYED_AUTO_START_INFO))
            finally:
                ws.CloseServiceHandle(h)
        finally:
            ws.CloseServiceHandle(scm)
    except Exception:
        return None
    if delayed:
        return None
    return {ws.SERVICE_AUTO_START: "auto", ws.SERVICE_DEMAND_START: "demand",
            ws.SERVICE_DISABLED: "disabled"}.get(code)


def _hklm_approved(e: StartupEntry) -> str | None:
    hive, kind, name = startup._approved_target(e)
    data = startup._read_approved(hive, kind, name, "")
    return data.hex() if data is not None else None


def _capture_before(e: StartupEntry) -> dict:
    """What undo needs to put an elevated entry back exactly."""
    if e.source == "service":
        start = _service_start(e.location)
        if start is None:
            raise ValueError("its current start type could not be read exactly, "
                             "so it was left unchanged")
        return {"start": start}
    if e.source == "task":
        return {"enabled": bool(e.enabled)}
    if e.source in ("run", "startup_folder"):
        if not e.needs_admin:
            raise ValueError(f"{e.name!r} is changed without elevation")
        return {"approved": _hklm_approved(e)}
    raise ValueError(f"{e.source} entries cannot be changed with elevation")


def _undo_ops(e: StartupEntry, before: dict) -> list[dict]:
    if e.source == "service":
        return [{"op": "set_service_start", "name": e.location, "start": before["start"]}]
    if e.source == "task":
        return [{"op": "set_task", "name": e.location, "enabled": bool(before["enabled"])}]
    if e.source in ("run", "startup_folder") and e.needs_admin:
        hive, kind, name = startup._approved_target(e)
        return [{"op": "set_approved", "hive": hive, "subkey": startup.APPROVED_PATHS[kind],
                 "value": name, "data_hex": before["approved"]}]
    raise ValueError(f"no elevated undo for {e.source} entry {e.name!r}")


def _record(conn, app_key: str, e: StartupEntry, before: dict) -> None:
    record_action(conn, ActionRecord(None, int(time.time()), app_key, "disable_startup",
                                     dataclasses.asdict(e), before, False))


def disable_startup(conn: sqlite3.Connection, app_key: str, entries: list[StartupEntry],
                    mode: str | None, cfg: Config, elevator: Elevator | None = None,
                    root: str = "") -> ActionResult:
    notes: list[str] = []
    ok = attempted = 0
    pending: list[tuple[StartupEntry, dict, list[dict]]] = []
    for e in entries:
        if not e.can_disable:
            notes.append(f"{e.name}: {e.note or 'cannot be turned off here'}.")
            attempted += 1
            continue
        if not e.enabled:
            notes.append(f"{e.name} is already off.")
            continue
        attempted += 1
        try:
            if _is_local(e):
                before = startup.apply_toggle(e, False, mode, root=root)
                _record(conn, app_key, e, before)
                ok += 1
            else:
                before = _capture_before(e)
                pending.append((e, before, startup.elevated_ops_for(e, False, mode)))
        except (OSError, ValueError) as ex:
            notes.append(f"{e.name}: could not be turned off ({ex}).")

    declined = False
    if pending:
        ops = [op for _e, _b, eops in pending for op in eops]
        res = _call(_elevator(elevator, cfg), ops)
        if res == "declined":
            declined = True
            notes.append(_DECLINED + ".")
        else:
            i = 0
            for e, before, eops in pending:
                rs = res[i:i + len(eops)]
                i += len(eops)
                if all(r["ok"] for r in rs):
                    _record(conn, app_key, e, before)
                    ok += 1
                else:
                    err = "; ".join(r["error"] or "failed" for r in rs if not r["ok"])
                    notes.append(f"{e.name}: could not be turned off ({err}).")

    msg = " ".join(notes)
    if attempted == 0:
        return ActionResult("done", msg or "Nothing to turn off.")
    if ok == attempted:
        return ActionResult("done", ("Turned off at startup. " + msg).strip())
    if ok == 0:
        return ActionResult("declined" if declined else "failed", msg)
    return ActionResult("partial", ("Some entries turned off. " + msg).strip())


def undo(conn: sqlite3.Connection, action_id: int, cfg: Config,
         elevator: Elevator | None = None, root: str = "") -> ActionResult:
    rec = get_action(conn, action_id)
    if rec is None:
        return ActionResult("failed", "That change is not on record.")
    if rec.undone:
        return ActionResult("failed", "That change was already undone.")
    if rec.action != "disable_startup":
        return ActionResult("failed", f"{rec.action} cannot be undone.")
    try:
        e = StartupEntry(**rec.entry)
        if _is_local(e):
            startup.restore(e, rec.before, root=root)
        else:
            ops = _undo_ops(e, rec.before)
            res = _call(_elevator(elevator, cfg), ops)
            if res == "declined":
                return ActionResult("declined", _DECLINED)
            bad = [r["error"] or "failed" for r in res if not r["ok"]]
            if bad:
                return ActionResult("failed", f"Could not undo: {'; '.join(bad)}.")
    except (OSError, ValueError, KeyError, TypeError) as ex:
        return ActionResult("failed", f"Could not undo: {ex}.")
    mark_undone(conn, action_id)
    return ActionResult("done", f"Restored {e.name} at startup.")
