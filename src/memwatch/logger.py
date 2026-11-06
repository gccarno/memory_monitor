"""Background logger: probes every interval and writes one tick to SQLite."""
from __future__ import annotations

import ctypes
import dataclasses
import logging
import logging.handlers
import sqlite3
import time
from collections.abc import Callable
from ctypes import wintypes

import psutil

from memwatch import probe
from memwatch.config import Config
from memwatch.db import prune, replace_startup, write_tick
from memwatch.grouping import group_processes
from memwatch.startup import inventory
from memwatch.usage import mark_usage

log = logging.getLogger(__name__)

_SERVICES_EVERY = 10
_STARTUP_EVERY = 30
_PRUNE_EVERY = 1440


def setup_logging(cfg: Config) -> logging.Handler:
    """Attach a rotating file handler (1 MB x 3) to the memwatch logger, once per file."""
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    path = cfg.data_dir / "logger.log"
    root = logging.getLogger("memwatch")
    for h in root.handlers:
        if getattr(h, "baseFilename", None) == str(path.resolve()):
            return h
    h = logging.handlers.RotatingFileHandler(
        path, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(h)
    root.setLevel(logging.INFO)
    return h


class Logger:
    def __init__(self, cfg: Config, conn: sqlite3.Connection,
                 clock: Callable[[], float] = time.time):
        self.cfg = cfg
        self.conn = conn
        self.clock = clock
        self._handler = setup_logging(cfg)
        self._n = 0
        self._services: dict = {}
        self._prev: dict[tuple[int, float], tuple[float, int]] = {}
        self._self = psutil.Process()

    def close(self) -> None:
        logging.getLogger("memwatch").removeHandler(self._handler)
        self._handler.close()

    def tick(self) -> None:
        n = self._n
        self._n += 1
        try:
            self._tick(n)
        except Exception:
            log.exception("tick %d failed", n)

    def _tick(self, n: int) -> None:
        cfg = self.cfg
        ts = int(self.clock())
        if n % _SERVICES_EVERY == 0:
            try:
                self._services = probe.services_by_pid()
            except Exception:
                log.exception("service refresh failed")
        procs = probe.snapshot_processes()
        groups = group_processes(procs, self._services, cfg)
        flags = mark_usage(
            groups, procs, self._prev, probe.foreground_pid(), probe.window_pids(),
            probe.seconds_since_input() >= cfg.user_away_s, cfg)
        system = probe.system_snapshot(ts, procs)
        system = dataclasses.replace(system, logger_ws=int(self._self.memory_info().wset))
        write_tick(self.conn, system, [(g, flags[k]) for k, g in groups.items()])
        self._prev = {(p.pid, p.create_time): (p.cpu_s or 0.0, p.io_bytes or 0) for p in procs}
        if n % _STARTUP_EVERY == 0:
            try:
                replace_startup(self.conn, inventory(cfg))
            except Exception:
                log.exception("startup inventory failed")
        if n % _PRUNE_EVERY == 0:
            try:
                prune(self.conn, ts, cfg.retention_days)
            except Exception:
                log.exception("prune failed")

    def run_forever(self) -> None:
        interval = self.cfg.sample_interval_s
        while True:
            self.tick()
            time.sleep(interval - (self.clock() % interval))


_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
_kernel32.CreateMutexW.restype = wintypes.HANDLE
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_ERROR_ALREADY_EXISTS = 183


class _Mutex:
    def __init__(self, handle):
        self.handle = handle

    def close(self) -> None:
        if self.handle:
            _kernel32.CloseHandle(self.handle)
            self.handle = None


def acquire_single_instance(name: str = "Local\\memwatch-logger") -> object | None:
    """Return an object holding the mutex, or None if another instance has it."""
    ctypes.set_last_error(0)
    handle = _kernel32.CreateMutexW(None, False, name)
    err = ctypes.get_last_error()
    if not handle:
        return None
    if err == _ERROR_ALREADY_EXISTS:
        _kernel32.CloseHandle(handle)
        return None
    return _Mutex(handle)
