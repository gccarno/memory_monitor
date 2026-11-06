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
