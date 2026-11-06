from __future__ import annotations

import pytest

from memwatch.db import connect
from memwatch.models import AppGroup, SystemSnapshot


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "memwatch.db")
    yield c
    c.close()


def mk_group(key: str, priv: int, **overrides) -> AppGroup:
    fields = dict(
        app_key=key,
        label=key.split(":")[-1],
        kind="suite",
        pids=[(1000, 0.0)],
        private_bytes=priv,
        working_set=priv,
        services=[],
        limited=False,
        microsoft=False,
    )
    fields.update(overrides)
    return AppGroup(**fields)


def mk_sys(ts: int, **overrides) -> SystemSnapshot:
    fields = dict(
        ts=ts,
        ram_total=16 * 2**30,
        ram_avail=8 * 2**30,
        commit_used=10 * 2**30,
        commit_limit=24 * 2**30,
        compression_ws=None,
        pool_paged=100 * 2**20,
        pool_nonpaged=50 * 2**20,
        boot_time=0,
        logger_ws=None,
    )
    fields.update(overrides)
    return SystemSnapshot(**fields)


@pytest.fixture
def cfg():
    from pathlib import Path

    from memwatch.config import load_config

    return load_config(Path("nonexistent.toml"))


def tick(conn, ts, key, fg=False, priv=100 << 20, windows=False, pool_nonpaged=None,
         **group_overrides):
    from memwatch.db import write_tick
    from memwatch.models import UsageFlags

    sys_over = {} if pool_nonpaged is None else {"pool_nonpaged": pool_nonpaged}
    write_tick(conn, mk_sys(ts, **sys_over),
               [(mk_group(key, priv, **group_overrides), UsageFlags(fg, fg, windows))])


def seed_ticks(conn, key, n, priv, kind="suite", label=None, microsoft=False,
               services=None, start=0):
    """n ticks, 60 s apart, beginning at tick index `start`; never foreground."""
    over = dict(kind=kind, microsoft=microsoft, services=services or [])
    if label:
        over["label"] = label
    for i in range(start, start + n):
        tick(conn, i * 60, key, priv=priv, **over)


def mkproc(pid: int, ppid: int, name: str, exe: str | None, cmdline=None, **overrides):
    from memwatch.models import ProcInfo

    fields = dict(
        pid=pid, ppid=ppid, name=name, exe=exe, cmdline=cmdline,
        create_time=1.0, private_bytes=10 * 2**20, working_set=8 * 2**20,
        cpu_s=0.0, io_bytes=0, cwd=None, limited=False,
    )
    fields.update(overrides)
    return ProcInfo(**fields)


def svc(name: str, **overrides):
    from memwatch.models import ServiceInfo

    fields = dict(
        name=name, display_name=name, description="", start_type="manual",
        pid=None, binpath="",
    )
    fields.update(overrides)
    return ServiceInfo(**fields)
