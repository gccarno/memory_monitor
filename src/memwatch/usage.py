"""Per-app usage flags: foreground, active (CPU/IO delta) and has-windows."""
from __future__ import annotations

from memwatch.config import Config
from memwatch.models import AppGroup, ProcInfo, UsageFlags


def _ancestors(pid: int, by_pid: dict[int, ProcInfo]) -> set[int]:
    """PIDs above `pid`, guarding against cycles and PID reuse."""
    out: set[int] = set()
    child = by_pid.get(pid)
    while child is not None:
        parent = by_pid.get(child.ppid)
        if (parent is None or parent.pid in out or parent.pid == pid
                or parent.create_time > child.create_time):
            break
        out.add(parent.pid)
        child = parent
    return out


def mark_usage(
    groups: dict[str, AppGroup],
    procs: list[ProcInfo],
    prev: dict[tuple[int, float], tuple[float, int]],
    fg_pid: int | None,
    win_pids: set[int],
    user_away: bool,
    cfg: Config,
) -> dict[str, UsageFlags]:
    by_pid = {p.pid: p for p in procs}
    by_key = {(p.pid, p.create_time): p for p in procs}
    fg_keys: set[str] = set()
    if fg_pid is not None and not user_away:
        for key, g in groups.items():
            if any(pid == fg_pid for pid, _ in g.pids):
                fg_keys.add(key)
        fg = by_pid.get(fg_pid)
        if fg is not None and fg.name.lower() in cfg.terminal_names:
            for key, g in groups.items():
                if g.kind == "instance" and g.pids and fg_pid in _ancestors(g.pids[0][0], by_pid):
                    fg_keys.add(key)

    flags: dict[str, UsageFlags] = {}
    for key, g in groups.items():
        cpu_d = 0.0
        io_d = 0
        for k in g.pids:
            p = by_key.get(k)
            old = prev.get(k)
            if p is None or old is None:
                continue
            if p.cpu_s is not None:
                cpu_d += max(0.0, p.cpu_s - old[0])
            if p.io_bytes is not None:
                io_d += max(0, p.io_bytes - old[1])
        flags[key] = UsageFlags(
            foreground=key in fg_keys,
            active=cpu_d >= cfg.cpu_active_s or io_d >= cfg.io_active_bytes,
            has_windows=any(pid in win_pids for pid, _ in g.pids),
        )
    return flags
