from conftest import mk_group, mk_sys

from memwatch.db import (
    all_apps, app_history, get_action, latest_groups, latest_system, list_actions,
    mark_undone, prune, record_action, replace_startup, startup_entries,
    system_ticks_since, write_tick,
)
from memwatch.models import ActionRecord, StartupEntry, UsageFlags

NONE = UsageFlags(False, False, False)


def test_write_tick_tracks_last_used_and_active(conn):
    write_tick(conn, mk_sys(100), [(mk_group("suite:steam", 300), UsageFlags(True, False, True))])
    write_tick(conn, mk_sys(160), [(mk_group("suite:steam", 310), UsageFlags(False, True, False))])
    rec = {a.app_key: a for a in all_apps(conn)}["suite:steam"]
    assert rec.first_seen == 100 and rec.last_seen == 160
    assert rec.last_used == 100 and rec.last_active == 160 and rec.has_windows_ever


def test_prune_removes_old(conn):
    write_tick(conn, mk_sys(0), [(mk_group("a", 1), NONE)])
    write_tick(conn, mk_sys(31 * 86400), [(mk_group("b", 1), NONE)])
    assert prune(conn, now=31 * 86400, retention_days=30) == 1
    assert [a.app_key for a in all_apps(conn)] == ["b"]
    assert system_ticks_since(conn, 0) == [31 * 86400]


def test_actions_roundtrip(conn):
    i = record_action(conn, ActionRecord(None, 5, "suite:discord", "disable_startup", {"source": "run"}, {"approved": None}, False))
    assert list_actions(conn)[0].entry == {"source": "run"}
    mark_undone(conn, i)
    assert list_actions(conn) == [] and get_action(conn, i).undone
    assert len(list_actions(conn, include_undone=True)) == 1
    assert get_action(conn, 999) is None


def test_refresh_fields_and_services(conn):
    write_tick(conn, mk_sys(10), [(mk_group("x", 5, label="Old", services=["svcA"]), NONE)])
    write_tick(conn, mk_sys(20), [(mk_group("x", 6, label="New", services=["svcB", "svcC"], limited=True, microsoft=True), NONE)])
    rec = all_apps(conn)[0]
    assert (rec.label, rec.services, rec.limited, rec.microsoft) == ("New", ["svcB", "svcC"], True, True)
    assert rec.first_seen == 10 and rec.last_used is None and rec.last_active is None
    assert not rec.has_windows_ever


def test_latest_system_and_ticks(conn):
    assert latest_system(conn) is None
    write_tick(conn, mk_sys(1), [])
    write_tick(conn, mk_sys(2, logger_ws=7), [])
    assert latest_system(conn) == mk_sys(2, logger_ws=7)
    assert system_ticks_since(conn, 2) == [2]


def test_history_and_latest_groups(conn):
    write_tick(conn, mk_sys(1), [(mk_group("a", 10), UsageFlags(True, False, False))])
    write_tick(conn, mk_sys(2), [(mk_group("a", 11), NONE), (mk_group("b", 20, working_set=30), NONE)])
    h = app_history(conn, 0)
    assert [s.ts for s in h["a"]] == [1, 2] and h["a"][0].foreground is True and h["a"][1].foreground is False
    assert app_history(conn, 2).keys() == {"a", "b"} and len(app_history(conn, 2)["a"]) == 1
    assert latest_groups(conn) == {"a": (2, 11, 11), "b": (2, 20, 30)}


def test_startup_replace(conn):
    e = StartupEntry("run", "Foo", r"HKCU\Run", "foo.exe", True, False, True, None, "suite:foo")
    f = StartupEntry("task", "Bar", r"\Bar", "bar.exe", False, True, False, "note", None)
    replace_startup(conn, [e, f])
    assert startup_entries(conn) == [e, f]
    replace_startup(conn, [f])
    assert startup_entries(conn) == [f]


def test_hourly_max_typical_and_used_days(conn):
    from memwatch.db import hourly_max, typical_private, used_day_count

    for ts, priv, fg in [(0, 10, True), (60, 30, False), (3600, 20, False), (3 * 86400, 5, True)]:
        write_tick(conn, mk_sys(ts), [(mk_group("a", priv), UsageFlags(fg, fg, False))])
    assert hourly_max(conn, 0)["a"] == [(0, 30), (1, 20), (72, 5)]
    assert hourly_max(conn, 3600)["a"] == [(1, 20), (72, 5)]
    assert typical_private(conn, 0) == {"a": 10}  # only ts=0, 3600, 259200 pass the thinning
    assert used_day_count(conn, "a", 0) == 2 and used_day_count(conn, "b", 0) == 0


def test_latest_groups_follows_latest_system_tick(conn):
    write_tick(conn, mk_sys(1), [(mk_group("a", 10), NONE)])
    write_tick(conn, mk_sys(2), [])  # a tick where no group was written
    assert latest_groups(conn) == {}


def test_markers_written_read_and_pruned(conn):
    from memwatch.db import latest_markers

    write_tick(conn, mk_sys(0), [], markers=["Windows Defender"])
    assert latest_markers(conn) == {"Windows Defender"}
    write_tick(conn, mk_sys(31 * 86400), [])
    assert latest_markers(conn) == set()  # only the latest tick counts
    prune(conn, now=31 * 86400, retention_days=30)
    assert conn.execute("SELECT COUNT(*) FROM markers").fetchone()[0] == 0


def test_set_startup_enabled(conn):
    from memwatch.db import set_startup_enabled

    e = StartupEntry("run", "Foo", r"HKCU\Foo", "foo.exe", True, False, True, None, "suite:foo")
    f = StartupEntry("run", "Bar", r"HKCU\Bar", "bar.exe", True, False, True, None, "suite:bar")
    replace_startup(conn, [e, f])
    set_startup_enabled(conn, "run", r"HKCU\Foo", False)
    assert [x.enabled for x in startup_entries(conn)] == [False, True]
    set_startup_enabled(conn, "run", r"HKCU\Foo", True)
    assert [x.enabled for x in startup_entries(conn)] == [True, True]
