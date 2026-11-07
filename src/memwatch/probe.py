"""Live probes: processes, system memory, windows, input idle and services."""
from __future__ import annotations

import ctypes
import logging
import threading
from ctypes import wintypes

import psutil

from memwatch.models import ProcInfo, ServiceInfo, SystemSnapshot

# (pid, create_time) -> (exe, cmdline, cwd, limited); pruned on every snapshot.
log = logging.getLogger(__name__)

_static_cache: dict[tuple[int, float], tuple[str | None, list[str] | None, str | None, bool]] = {}
# The report server snapshots from several request threads; guard every cache access.
_static_cache_lock = threading.Lock()


def is_terminated(p) -> bool:
    """True for a process that has exited but is still listed (zero threads, e.g.
    stuck in termination). Reading its exe/cmdline/cwd costs ~1 s each while
    psutil retries, and it holds no user memory, so callers skip it. The thread
    count comes from the cheap system process list."""
    try:
        return p.num_threads() == 0
    except psutil.NoSuchProcess:
        return True
    except psutil.Error:
        return False


def _static_fields(p, key):
    with _static_cache_lock:
        cached = _static_cache.get(key)
    if cached is not None:
        return cached
    limited = False
    vals: list = []
    for fn in (p.exe, p.cmdline, p.cwd):
        try:
            vals.append(fn())
        except psutil.NoSuchProcess:
            raise
        except (psutil.AccessDenied, OSError):
            vals.append(None)
            limited = True
    entry = (vals[0], vals[1], vals[2], limited)
    with _static_cache_lock:
        _static_cache[key] = entry
    return entry


def snapshot_processes() -> list[ProcInfo]:
    out: list[ProcInfo] = []
    seen: set[tuple[int, float]] = set()
    for p in psutil.process_iter():
        try:
            with p.oneshot():
                if is_terminated(p):
                    continue
                limited = False
                try:
                    ct = p.create_time()
                except psutil.AccessDenied:
                    ct, limited = 0.0, True
                key = (p.pid, ct)
                try:
                    mi = p.memory_info()
                    private, wset = int(mi.private), int(mi.wset)
                except psutil.AccessDenied:
                    private = wset = 0
                    limited = True
                try:
                    c = p.cpu_times()
                    cpu = c.user + c.system
                except psutil.AccessDenied:
                    cpu, limited = None, True
                try:
                    io = p.io_counters()
                    io_bytes = io.read_bytes + io.write_bytes
                except (psutil.AccessDenied, OSError):
                    io_bytes, limited = None, True
                try:
                    ppid = p.ppid()
                except psutil.AccessDenied:
                    ppid, limited = 0, True
                try:
                    name = p.name()
                except psutil.AccessDenied:
                    name, limited = "", True
                exe, cmdline, cwd, lim2 = _static_fields(p, key)
        except psutil.NoSuchProcess:
            continue
        seen.add(key)
        out.append(ProcInfo(
            pid=p.pid, ppid=ppid, name=name, exe=exe, cmdline=cmdline,
            create_time=ct, private_bytes=private, working_set=wset,
            cpu_s=cpu, io_bytes=io_bytes, cwd=cwd, limited=limited or lim2,
        ))
    with _static_cache_lock:
        for k in [k for k in _static_cache if k not in seen]:
            del _static_cache[k]
    return out


# ---- system -------------------------------------------------------------

class _PERF_INFO(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("CommitTotal", ctypes.c_size_t),
        ("CommitLimit", ctypes.c_size_t),
        ("CommitPeak", ctypes.c_size_t),
        ("PhysicalTotal", ctypes.c_size_t),
        ("PhysicalAvailable", ctypes.c_size_t),
        ("SystemCache", ctypes.c_size_t),
        ("KernelTotal", ctypes.c_size_t),
        ("KernelPaged", ctypes.c_size_t),
        ("KernelNonpaged", ctypes.c_size_t),
        ("PageSize", ctypes.c_size_t),
        ("HandleCount", wintypes.DWORD),
        ("ProcessCount", wintypes.DWORD),
        ("ThreadCount", wintypes.DWORD),
    ]


_psapi = ctypes.WinDLL("psapi", use_last_error=True)
_psapi.GetPerformanceInfo.argtypes = [ctypes.POINTER(_PERF_INFO), wintypes.DWORD]
_psapi.GetPerformanceInfo.restype = wintypes.BOOL

_user32 = ctypes.WinDLL("user32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)

_user32.GetForegroundWindow.restype = wintypes.HWND
_user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
_user32.GetWindowThreadProcessId.restype = wintypes.DWORD
_user32.IsWindowVisible.argtypes = [wintypes.HWND]
_user32.IsWindowVisible.restype = wintypes.BOOL
_user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
_user32.GetWindowTextLengthW.restype = ctypes.c_int
_WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
_user32.EnumWindows.argtypes = [_WNDENUMPROC, wintypes.LPARAM]
_user32.EnumWindows.restype = wintypes.BOOL
_dwmapi.DwmGetWindowAttribute.argtypes = [wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
_dwmapi.DwmGetWindowAttribute.restype = ctypes.c_long


class _LASTINPUTINFO(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]


_user32.GetLastInputInfo.argtypes = [ctypes.POINTER(_LASTINPUTINFO)]
_user32.GetLastInputInfo.restype = wintypes.BOOL
_kernel32.GetTickCount64.restype = ctypes.c_uint64

_DWMWA_CLOAKED = 14


def _compression_ws() -> int | None:
    for p in psutil.process_iter(["name"]):
        if p.info["name"] == "Memory Compression":
            try:
                return int(p.memory_info().wset)
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                return None
    return None


def _compression_from_procs(procs: list[ProcInfo]) -> int | None:
    for pi in procs:
        if pi.name == "Memory Compression":
            return None if pi.limited or not pi.working_set else pi.working_set
    return None


def system_snapshot(ts: int, procs: list[ProcInfo] | None = None) -> SystemSnapshot:
    pi = _PERF_INFO()
    pi.cb = ctypes.sizeof(pi)
    if not _psapi.GetPerformanceInfo(ctypes.byref(pi), pi.cb):
        raise ctypes.WinError(ctypes.get_last_error())
    page = pi.PageSize
    vm = psutil.virtual_memory()
    return SystemSnapshot(
        ts=ts,
        ram_total=int(vm.total),
        ram_avail=int(vm.available),
        commit_used=pi.CommitTotal * page,
        commit_limit=pi.CommitLimit * page,
        compression_ws=_compression_from_procs(procs) if procs is not None else _compression_ws(),
        pool_paged=pi.KernelPaged * page,
        pool_nonpaged=pi.KernelNonpaged * page,
        boot_time=int(psutil.boot_time()),
        logger_ws=None,
    )


# ---- windows / input ----------------------------------------------------

def foreground_pid() -> int | None:
    hwnd = _user32.GetForegroundWindow()
    if not hwnd:
        return None
    pid = wintypes.DWORD(0)
    _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value or None


def window_pids() -> set[int]:
    pids: set[int] = set()

    def cb(hwnd, _lparam):
        try:
            if not _user32.IsWindowVisible(hwnd) or _user32.GetWindowTextLengthW(hwnd) <= 0:
                return True
            cloaked = wintypes.DWORD(0)
            hr = _dwmapi.DwmGetWindowAttribute(
                hwnd, _DWMWA_CLOAKED, ctypes.byref(cloaked), ctypes.sizeof(cloaked))
            if hr == 0 and cloaked.value:
                return True
            pid = wintypes.DWORD(0)
            _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value:
                pids.add(pid.value)
        except Exception:
            pass
        return True

    _user32.EnumWindows(_WNDENUMPROC(cb), 0)
    return pids


def seconds_since_input() -> float:
    lii = _LASTINPUTINFO()
    lii.cbSize = ctypes.sizeof(lii)
    if not _user32.GetLastInputInfo(ctypes.byref(lii)):
        return 0.0
    # dwTime is a 32-bit tick count: compare with the low 32 bits of the 64-bit clock.
    now32 = _kernel32.GetTickCount64() & 0xFFFFFFFF
    return ((now32 - lii.dwTime) & 0xFFFFFFFF) / 1000.0


# ---- services -----------------------------------------------------------

_START_TYPES = {"automatic": "automatic", "manual": "manual", "disabled": "disabled",
                "boot": "automatic", "system": "automatic"}


def all_services() -> list[ServiceInfo]:
    out: list[ServiceInfo] = []
    try:
        it = list(psutil.win_service_iter())
    except (psutil.Error, OSError) as e:
        log.warning("service enumeration failed: %s", e)
        return out
    for s in it:
        try:
            d = s.as_dict()
            out.append(ServiceInfo(
                name=d["name"],
                display_name=d.get("display_name") or "",
                description=d.get("description") or "",
                start_type=_START_TYPES.get(d.get("start_type"), "manual"),
                pid=d.get("pid") or None,
                binpath=d.get("binpath") or "",
            ))
        except (psutil.Error, OSError, KeyError) as e:
            log.debug("skipping service: %s", e)
    return out


def services_by_pid() -> dict[int, list[ServiceInfo]]:
    by_pid: dict[int, list[ServiceInfo]] = {}
    for s in all_services():
        if s.pid:
            by_pid.setdefault(s.pid, []).append(s)
    return by_pid
