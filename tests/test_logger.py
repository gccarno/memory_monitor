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
