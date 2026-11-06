from __future__ import annotations

import os
from collections import namedtuple
from contextlib import contextmanager

import psutil

from memwatch import probe
from memwatch.models import ProcInfo
from memwatch.probe import (
    all_services,
    foreground_pid,
    seconds_since_input,
    services_by_pid,
    snapshot_processes,
    system_snapshot,
    window_pids,
)

MemInfo = namedtuple("MemInfo", "private wset")
CpuTimes = namedtuple("CpuTimes", "user system")
IoCounters = namedtuple("IoCounters", "read_bytes write_bytes")


class FakeProc:
    def __init__(self, pid, vanish=False, denied=False):
        self.pid = pid
        self._vanish = vanish
        self._denied = denied

    @contextmanager
    def oneshot(self):
        yield

    def _deny(self):
        if self._denied:
            raise psutil.AccessDenied(self.pid)

    def name(self):
        return f"p{self.pid}"

    def ppid(self):
        return 1

    def create_time(self):
        return 1000.0 + self.pid

    def memory_info(self):
        if self._vanish:
            raise psutil.NoSuchProcess(self.pid)
        return MemInfo(private=100, wset=200)

    def cpu_times(self):
        return CpuTimes(user=1.5, system=0.5)

    def io_counters(self):
        self._deny()
        return IoCounters(read_bytes=3, write_bytes=4)

    def exe(self):
        self._deny()
        return r"C:\x\p.exe"

    def cmdline(self):
        self._deny()
        return ["p.exe", "-a"]

    def cwd(self):
        self._deny()
        return r"C:\x"


def test_snapshot_survives_vanishing_and_denied(monkeypatch):
    def fake_iter(*a, **k):
        return iter([FakeProc(10), FakeProc(20, vanish=True), FakeProc(30, denied=True)])

    monkeypatch.setattr(psutil, "process_iter", fake_iter)
    procs = snapshot_processes()
    assert [p.pid for p in procs] == [10, 30]
    healthy, denied = procs
    assert not healthy.limited and healthy.cpu_s == 2.0 and healthy.io_bytes == 7
    assert healthy.private_bytes == 100 and healthy.working_set == 200
    assert denied.limited and denied.exe is None and denied.io_bytes is None
    assert denied.cmdline is None and denied.cwd is None


def test_static_cache_pruned(monkeypatch):
    monkeypatch.setattr(psutil, "process_iter", lambda *a, **k: iter([FakeProc(10)]))
    snapshot_processes()
    assert (10, 1010.0) in probe._static_cache
    monkeypatch.setattr(psutil, "process_iter", lambda *a, **k: iter([FakeProc(11)]))
    snapshot_processes()
    assert (10, 1010.0) not in probe._static_cache


def test_real_snapshot_contains_self():
    me = [p for p in snapshot_processes() if p.pid == os.getpid()][0]
    assert me.private_bytes > 0 and me.create_time > 0 and not me.limited


def test_system_snapshot_sane():
    s = system_snapshot(1)
    assert s.ram_total > 8 * 2**30 and 0 < s.commit_used <= s.commit_limit and s.pool_nonpaged > 0
    assert s.boot_time > 0 and s.logger_ws is None


def test_seconds_since_input_nonnegative():
    assert seconds_since_input() >= 0


def test_window_probes_return_sane_types():
    pids = window_pids()
    assert isinstance(pids, set) and all(isinstance(p, int) for p in pids)
    fg = foreground_pid()
    assert fg is None or fg > 0


def test_services():
    svcs = all_services()
    assert svcs and all(s.start_type in ("automatic", "manual", "disabled") for s in svcs)
    assert any(s.start_type == "automatic" for s in svcs)
    by_pid = services_by_pid()
    assert all(pid > 0 and lst for pid, lst in by_pid.items())


def _pi(name, ws, limited=False):
    return ProcInfo(pid=4, ppid=0, name=name, exe=None, cmdline=None, create_time=1.0,
                    private_bytes=0, working_set=ws, cpu_s=None, io_bytes=None,
                    cwd=None, limited=limited)


def test_compression_ws_from_procs_found_denied_absent(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not rescan when procs given")

    monkeypatch.setattr(psutil, "process_iter", boom)
    assert system_snapshot(1, [_pi("Memory Compression", 123)]).compression_ws == 123
    assert system_snapshot(1, [_pi("Memory Compression", 0, limited=True)]).compression_ws is None
    assert system_snapshot(1, [_pi("other", 5)]).compression_ws is None


def test_all_services_enumeration_failure_logged(monkeypatch, caplog):
    def bad():
        raise OSError("scm down")

    monkeypatch.setattr(psutil, "win_service_iter", bad)
    with caplog.at_level("WARNING", logger="memwatch.probe"):
        assert all_services() == []
    assert "service enumeration failed" in caplog.text
