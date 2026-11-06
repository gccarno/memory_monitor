from __future__ import annotations

import pytest

from memwatch import probe
from memwatch.db import all_apps, connect, latest_system
from memwatch.logger import Logger, acquire_single_instance


@pytest.fixture
def lg(tmp_path, cfg, monkeypatch):
    # services and the startup inventory (schtasks) take ~25 s; stub them for speed
    monkeypatch.setattr(probe, "services_by_pid", lambda: {})
    monkeypatch.setattr("memwatch.logger.inventory", lambda cfg: [])
    cfg.data_dir = tmp_path
    lg = Logger(cfg, connect(tmp_path / "m.db"), clock=lambda: 1000.0)
    yield lg
    lg.close()
    lg.conn.close()


def test_tick_writes_rows_and_survives_probe_error(lg, monkeypatch):
    lg.tick()
    assert latest_system(lg.conn).logger_ws > 0 and all_apps(lg.conn)
    monkeypatch.setattr(probe, "snapshot_processes", lambda: 1 / 0)
    lg.tick()  # must not raise
    lg._handler.flush()
    assert "ZeroDivisionError" in (lg.cfg.data_dir / "logger.log").read_text(encoding="utf-8")


def test_system_snapshot_reuses_process_list(lg, monkeypatch):
    seen = []
    real = probe.system_snapshot

    def spy(ts, procs=None):
        seen.append(procs)
        return real(ts, procs)

    monkeypatch.setattr(probe, "system_snapshot", spy)
    lg.tick()
    assert seen and seen[0] is not None


def test_single_instance():
    a = acquire_single_instance("Local\\memwatch-test")
    assert a is not None and acquire_single_instance("Local\\memwatch-test") is None
    a.close()
    b = acquire_single_instance("Local\\memwatch-test")
    assert b is not None
    b.close()


class _Stop(Exception):
    pass


def _run_loop(lg, times, ticks=None):
    """Drive run_forever with a scripted clock; return the sleep arguments."""
    it = iter(times)
    lg.clock = lambda: next(it)
    sleeps = []

    def sleep(d):
        sleeps.append(d)
        if len(sleeps) >= (ticks or len(times)):
            raise _Stop

    lg._sleep = sleep
    if ticks is not None:
        lg.tick = lambda: None
    with pytest.raises(_Stop):
        lg.run_forever()
    return sleeps


def test_run_forever_sleeps_to_next_boundary(lg):
    lg.tick = lambda: None
    sleeps = _run_loop(lg, [1015.0, 1075.5], ticks=2)
    assert sleeps == [pytest.approx(5.0), pytest.approx(4.5)]


def test_long_tick_skips_to_next_future_boundary(lg):
    # tick ended 70 s after it started: sleep to the next future boundary, not a past one
    lg.tick = lambda: None
    assert _run_loop(lg, [1085.0], ticks=1) == [pytest.approx(55.0)]


def test_near_boundary_sleeps_to_following_boundary(lg):
    lg.tick = lambda: None
    assert _run_loop(lg, [1019.6], ticks=1) == [pytest.approx(60.4)]


def test_run_forever_survives_failing_tick(lg, monkeypatch):
    monkeypatch.setattr(probe, "snapshot_processes", lambda: 1 / 0)
    sleeps = []

    def sleep(d):
        sleeps.append(d)
        if len(sleeps) == 3:
            raise _Stop

    lg._sleep = sleep
    with pytest.raises(_Stop):
        lg.run_forever()
    assert len(sleeps) == 3


def test_refreshes_fire_on_due_ticks(lg, monkeypatch):
    calls = {"svc": [], "inv": [], "prune": []}
    n = {"i": 0}
    monkeypatch.setattr(probe, "services_by_pid", lambda: calls["svc"].append(n["i"]) or {})
    monkeypatch.setattr("memwatch.logger.inventory", lambda cfg: calls["inv"].append(n["i"]) or [])
    monkeypatch.setattr("memwatch.logger.prune", lambda *a: calls["prune"].append(n["i"]))
    for i in range(31):
        n["i"] = i
        lg._refresh(lg._n)
        lg._n += 1
    assert calls == {"svc": [0, 10, 20, 30], "inv": [0, 30], "prune": [0]}


def test_failed_tick_does_not_skip_refreshes(lg, monkeypatch):
    seen = []
    monkeypatch.setattr("memwatch.logger.inventory", lambda cfg: seen.append(1) or [])
    monkeypatch.setattr(probe, "snapshot_processes", lambda: 1 / 0)
    lg.tick()  # tick 0 fails in the probe, but its refreshes already ran
    assert seen == [1]


def test_refresh_errors_are_logged_and_swallowed(lg, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("boom-" + "x")

    monkeypatch.setattr(probe, "services_by_pid", boom)
    monkeypatch.setattr("memwatch.logger.inventory", boom)
    monkeypatch.setattr("memwatch.logger.prune", boom)
    lg.tick()
    lg._handler.flush()
    text = (lg.cfg.data_dir / "logger.log").read_text(encoding="utf-8")
    for msg in ("service refresh failed", "startup inventory failed", "prune failed"):
        assert msg in text
    assert latest_system(lg.conn) is not None  # the sample was still written
