from __future__ import annotations

import ntpath
import re
from datetime import datetime

from memwatch import probe
from memwatch.config import Config
from memwatch.models import AppGroup, ProcInfo, ServiceInfo

PROTECTED_KEY = "protected:windows"

# Most specific first: `\appdata\local\programs\<v>\` before `\appdata\local\<v>\`.
_PATH_PATTERNS = [
    re.compile(r"\\program files \(x86\)\\([^\\]+)\\", re.I),
    re.compile(r"\\program files\\([^\\]+)\\", re.I),
    re.compile(r"\\appdata\\local\\programs\\([^\\]+)\\", re.I),
    re.compile(r"\\appdata\\local\\([^\\]+)\\", re.I),
    re.compile(r"\\appdata\\roaming\\([^\\]+)\\", re.I),
]
_WINDOWSAPPS = re.compile(r"\\windowsapps\\([^\\_]+)_", re.I)
_MS_NEXT = re.compile(r"\\microsoft\\([^\\]+)\\", re.I)


def suite_from_path(path: str | None, name: str, cfg: Config) -> tuple[str, str, bool]:
    """Map an exe path to (app_key, label, microsoft)."""
    stem = name[:-4] if name.lower().endswith(".exe") else name
    if not path:
        return f"suite:{stem.lower()}", stem, False
    low = path.lower()
    for sub, label in cfg.suite_overrides.items():
        if sub.lower() in low:
            return f"suite:{label.lower()}", label, False
    m = _WINDOWSAPPS.search(path)
    if m:
        label = m.group(1)
        return f"suite:{label.lower()}", label, label.lower().startswith("microsoft")
    for pat in _PATH_PATTERNS:
        m = pat.search(path)
        if not m:
            continue
        label = m.group(1)
        if label.lower() == "microsoft":
            n = _MS_NEXT.search(path[m.start():])
            if n:
                nxt = n.group(1)
                label = nxt if nxt.lower().startswith("microsoft") else f"Microsoft {nxt}"
            return f"suite:{label.lower()}", label, True
        return f"suite:{label.lower()}", label, label.lower().startswith("microsoft")
    if "\\windows\\" in low:
        return f"windows:{name.lower()}", name, True
    return f"suite:{stem.lower()}", stem, False


def _is_protected(p: ProcInfo, services: dict[int, list[ServiceInfo]], cfg: Config) -> bool:
    low = p.name.lower()
    if p.pid in (0, 4) or low in cfg.protected_names:
        return True
    if low == "svchost.exe":
        return any(s.name.lower() in cfg.protected_services for s in services.get(p.pid, []))
    return False


def _python_label(cmdline: list[str] | None) -> str:
    args = cmdline[1:] if cmdline else []
    for i, a in enumerate(args):
        if a == "-m" and i + 1 < len(args):
            return f"Python: -m {args[i + 1]}"
        if a.lower().endswith(".py"):
            return f"Python: {ntpath.basename(a.replace('/', chr(92)))}"
    return "Python: interpreter"


def _instance(p: ProcInfo) -> tuple[str, str] | None:
    """Return (type, label) when this process is its own instance group."""
    low = p.name.lower()
    if low == "claude.exe" and "\\.local\\bin\\" in (p.exe or "").lower():
        started = datetime.fromtimestamp(p.create_time).strftime("%b %d %H:%M")
        label = f"Claude Code session (started {started})"
        if p.cwd:
            label += f" — {p.cwd}"
        return "claude-cli", label
    if low in ("python.exe", "pythonw.exe"):
        return "python", _python_label(p.cmdline)
    if low.startswith("qemu-system-"):
        args = p.cmdline or []
        if "-avd" in args and args.index("-avd") + 1 < len(args):
            return "emulator", f"Android emulator ({args[args.index('-avd') + 1]})"
        return "emulator", "Android emulator"
    return None


def group_processes(
    procs: list[ProcInfo], services: dict[int, list[ServiceInfo]], cfg: Config
) -> dict[str, AppGroup]:
    by_pid = {p.pid: p for p in procs}
    shell = {n.lower() for n in cfg.shell_parent_names}
    groups: dict[str, AppGroup] = {}
    key_of: dict[int, str] = {}

    def ensure(key, label, kind, microsoft=False, svc_names=()):
        g = groups.get(key)
        if g is None:
            g = groups[key] = AppGroup(key, label, kind, [], 0, 0, [], False, microsoft)
        for s in svc_names:
            if s not in g.services:
                g.services.append(s)
        return g

    def resolve(p: ProcInfo, seen: frozenset[int] = frozenset()) -> str:
        if p.pid in key_of:
            return key_of[p.pid]
        if _is_protected(p, services, cfg):
            ensure(PROTECTED_KEY, "Windows core", "protected")
            key = PROTECTED_KEY
        elif (inst := _instance(p)) is not None:
            key = f"{inst[0]}:{p.pid}:{int(p.create_time)}"
            ensure(key, inst[1], "instance")
        elif p.name.lower() == "svchost.exe" and services.get(p.pid):
            svcs = sorted(services[p.pid], key=lambda s: s.name.lower())
            key = "service:" + "+".join(s.name.lower() for s in svcs)
            ensure(key, ", ".join(s.display_name for s in svcs), "windows", True,
                   [s.name for s in svcs])
        else:
            parent = by_pid.get(p.ppid)
            if (parent is not None and parent.pid != p.pid and parent.pid not in seen
                    and parent.create_time <= p.create_time
                    and parent.name.lower() not in shell):
                key = resolve(parent, seen | {p.pid})
            else:
                key, label, ms = suite_from_path(p.exe, p.name, cfg)
                ensure(key, label, "windows" if key.startswith("windows:") else "suite", ms,
                       [s.name for s in services.get(p.pid, [])])
        key_of[p.pid] = key
        return key

    for p in procs:
        g = groups[resolve(p)]
        g.pids.append((p.pid, p.create_time))
        g.private_bytes += p.private_bytes
        g.working_set += p.working_set
        g.limited = g.limited or p.limited
    return groups


def group_for_key(app_key: str, cfg: Config) -> AppGroup | None:
    return group_processes(probe.snapshot_processes(), probe.services_by_pid(), cfg).get(app_key)
