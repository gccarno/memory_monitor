from datetime import datetime

from conftest import mk_group, mk_sys, seed_ticks, tick

from memwatch.db import replace_startup, write_tick
from memwatch.models import StartupEntry, UsageFlags
from memwatch.suggest import (
    build_report, default_dependents, default_service_desc, fmt_dur, fmt_size,
)

DAY = 86400


def test_idle_counts_only_observed_time(conn, cfg):
    tick(conn, 0, "suite:discord", fg=True, priv=200 << 20, windows=True)
    tick(conn, 60, "suite:discord", priv=200 << 20)
    tick(conn, 5 * 86400, "suite:discord", priv=200 << 20)
    s = build_report(conn, cfg, now=5 * 86400)
    assert [a.app_key for a in s.apps] == ["suite:discord"]  # present, but not idle
    assert s.suggestions == []  # only 2 minutes observed
    assert s.apps[0].last_used == 0


def test_large_idle_sentence(conn, cfg):
    seed_ticks(conn, "emulator:31:1", n=3 * 1440, priv=int(4.0 * 2**30), kind="instance")
    sug = build_report(conn, cfg, now=3 * 86400).suggestions[0]
    assert sug.reasons[0] == "Big and idle: 4.0 GB, not used in 3 days of laptop use"
    assert sug.reason_codes[:2] == ["LARGE_IDLE", "LONG_RUNNING"]
    assert sug.reasons[1] == "Running for 3 days"


def test_partial_note_and_no_history(conn, cfg):
    r = build_report(conn, cfg, now=0)
    assert r.suggestions == [] and r.system is None
    tick(conn, 0, "suite:steam", priv=300 << 20)
    assert build_report(conn, cfg, now=0).partial_note.startswith("Based on")


def test_no_partial_note_after_72_hours(conn, cfg):
    seed_ticks(conn, "suite:a", n=72 * 60, priv=1 << 20)
    assert build_report(conn, cfg, now=72 * 3600).partial_note is None


def test_protected_and_excluded_never_suggested(conn, cfg):
    seed_ticks(conn, "protected:windows", n=10, priv=5 << 30, kind="protected")
    seed_ticks(conn, "python:9:1", n=10, priv=5 << 30, kind="instance")
    keys = [s.app_key for s in build_report(conn, cfg, now=600, exclude_keys={"python:9:1"}).suggestions]
    assert keys == []
    r = build_report(conn, cfg, now=600)
    assert {a.app_key for a in r.apps} == {"python:9:1"}  # protected is not an app row
    assert [x.app_key for x in r.suggestions] == ["python:9:1"]  # positive control


def test_duplicate_antivirus_and_ranking(conn, cfg):
    seed_ticks(conn, "suite:reason security", n=10, priv=300 << 20, label="Reason Security")
    seed_ticks(conn, "suite:windows defender", n=10, priv=500 << 20, label="Windows Defender")
    seed_ticks(conn, "suite:zoom", n=10, priv=1900 << 20, label="Zoom")
    r = build_report(conn, cfg, now=600)
    assert r.suggestions[0].app_key == "suite:zoom"
    assert any(c.startswith("Duplicate: 2 antivirus") for c in r.suggestions[-1].reasons)
    assert r.suggestions[-1].reasons[-1] == (
        "Duplicate: 2 antivirus products running (Reason Security, Windows Defender)")


def test_service_modes_drop_disabled_with_dependents(conn, cfg):
    seed_ticks(conn, "service:wsearch", n=10, priv=50 << 20, kind="windows", microsoft=True, services=["WSearch"])
    s = build_report(conn, cfg, now=600, dependents=lambda svc: ["WMPNetworkSvc"]).suggestions[0]
    assert s.service_modes == ["manual"] and s.caution.startswith("Windows Search indexing")
    s = build_report(conn, cfg, now=600, dependents=lambda svc: []).suggestions[0]
    assert s.service_modes == ["manual", "disabled"]
    assert s.reasons == ["Background service with no app you use: " + cfg.notes["service:wsearch"]]


def test_standalone_uses_service_desc_then_fallback(conn, cfg):
    seed_ticks(conn, "service:foo", n=5, priv=10 << 20, kind="windows", services=["Foo"])
    s = build_report(conn, cfg, now=300, service_desc=lambda n: "Does foo things").suggestions[0]
    assert s.reasons == ["Background service with no app you use: Does foo things"]
    assert s.caution is None
    s = build_report(conn, cfg, now=300, service_desc=lambda n: "").suggestions[0]
    assert s.reasons[0].endswith("no description available")


def test_service_modes_empty_without_services(conn, cfg):
    seed_ticks(conn, "suite:x", n=5, priv=900 << 20)
    assert build_report(conn, cfg, now=300).suggestions[0].service_modes == []


def test_kernel_note(conn, cfg):
    tick(conn, 0, "suite:x", priv=1, pool_nonpaged=1545 << 20)
    assert "1.5 GB non-paged" in build_report(conn, cfg, now=0).kernel_note


def test_no_kernel_note_below_threshold(conn, cfg):
    tick(conn, 0, "suite:x", priv=1)
    assert build_report(conn, cfg, now=0).kernel_note is None


def test_never_used_idle_counts_from_first_seen_inclusive(conn, cfg):
    for i in range(3 * 1440):
        tick(conn, i * 60, "suite:win", priv=100 << 20, windows=True)
    s = build_report(conn, cfg, now=3 * DAY).suggestions[0]
    assert s.idle_observed_s == 3 * 1440 * 60
    assert s.reasons == ["Not used in 3 days of laptop use, holding 100 MB"]


def test_used_idle_counts_ticks_after_last_used(conn, cfg):
    tick(conn, 0, "suite:win", fg=True, priv=100 << 20, windows=True)
    for i in range(1, 3 * 1440):
        tick(conn, i * 60, "suite:win", priv=100 << 20)
    s = build_report(conn, cfg, now=3 * DAY).suggestions[0]
    assert s.idle_observed_s == (3 * 1440 - 1) * 60 and s.last_used == 0


def test_large_not_idle(conn, cfg):
    seed_ticks(conn, "suite:big", n=10, priv=600 << 20)
    s = build_report(conn, cfg, now=600).suggestions[0]
    assert s.reasons[0] == "Using a lot of memory: 600 MB" and s.reason_codes[0] == "LARGE"


def test_polling(conn, cfg):
    n = 120
    for i in range(n):
        tick(conn, i * 60, "python:1:1", priv=50 << 20, kind="instance")
    write_tick(conn, mk_sys(n * 60),
               [(mk_group("python:1:1", 50 << 20, kind="instance"), UsageFlags(False, True, False))])
    s = build_report(conn, cfg, now=n * 60).suggestions[0]
    assert s.reason_codes == ["POLLING"]
    assert s.reasons[0] == "Still running and busy, but you haven't looked at it in 2 hours"


def entry(source, enabled=True, key="suite:app", name="App"):
    return StartupEntry(source, name, "loc", "cmd", enabled, False, True, None, key)


def _four_days(conn, key="suite:app", microsoft=False, used_days=1, days=4):
    base = int(datetime(2026, 1, 1, 12).timestamp())
    for d in range(days):
        tick(conn, base + d * DAY, key, fg=d < used_days, priv=50 << 20, windows=True,
             microsoft=microsoft)
    return base + (days - 1) * DAY


def test_autostart_rare(conn, cfg):
    now = _four_days(conn)
    replace_startup(conn, [entry("run", enabled=False), entry("run", name="B")])
    s = build_report(conn, cfg, now=now).suggestions[0]
    assert s.reason_codes == ["AUTOSTART_RARE"]
    assert s.reasons[0] == "Starts with Windows but you used it on only 1 of the last 4 days"
    assert [e.enabled for e in s.startup] == [True, False]
    assert build_report(conn, cfg, now=now).apps[0].autostart is True


def test_autostart_needs_enabled_entry_and_enough_days(conn, cfg):
    now = _four_days(conn)
    replace_startup(conn, [entry("run", enabled=False)])
    assert build_report(conn, cfg, now=now).suggestions == []


def test_autostart_needs_min_observed_days(conn, cfg):
    now = _four_days(conn, days=2)
    replace_startup(conn, [entry("run")])
    assert build_report(conn, cfg, now=now).suggestions == []


def test_autostart_not_rare_when_used_often(conn, cfg):
    now = _four_days(conn, used_days=3)
    replace_startup(conn, [entry("run")])
    assert build_report(conn, cfg, now=now).suggestions == []


def test_microsoft_logon_task_is_not_autostart(conn, cfg):
    now = _four_days(conn, microsoft=True)
    replace_startup(conn, [entry("task")])
    r = build_report(conn, cfg, now=now)
    assert r.apps[0].autostart is False and r.suggestions == []


def test_non_microsoft_task_counts(conn, cfg):
    now = _four_days(conn)
    replace_startup(conn, [entry("task")])
    assert build_report(conn, cfg, now=now).apps[0].autostart is True


def test_report_extras(conn, cfg):
    write_tick(conn, mk_sys(0, boot_time=-3600, logger_ws=60 << 20),
               [(mk_group("suite:a", 1 << 20), UsageFlags(False, False, True))])
    r = build_report(conn, cfg, now=0)
    assert r.uptime_s == 3600 and r.logger_over_cap and r.logger_ws == 60 << 20
    assert r.apps[0].spark == [1 << 20] and r.undo == []
    assert r.system is not None


def test_typical_private_is_median(conn, cfg):
    for i, p in enumerate([100, 900, 700, 700, 800]):  # one tick per hour
        tick(conn, i * 3600, "suite:a", priv=p << 20, windows=True)
    s = build_report(conn, cfg, now=4 * 3600).suggestions[0]
    assert s.typical_private == 700 << 20


def test_formatters():
    assert fmt_size(4 << 30) == "4.0 GB" and fmt_size(600 << 20) == "600 MB"
    assert fmt_dur(60) == "1 minute" and fmt_dur(150) == "2 minutes"
    assert fmt_dur(3600) == "1 hour" and fmt_dur(47 * 3600 + 3599) == "47 hours"
    assert fmt_dur(48 * 3600) == "2 days" and fmt_dur(86400 * 3 + 5) == "3 days"


def test_default_service_desc_never_raises():
    assert default_service_desc("definitely-not-a-service-xyz") == ""


def test_default_dependents_fails_closed(monkeypatch):
    import memwatch.suggest as sg

    def boom(_):
        raise OSError("access denied")

    monkeypatch.setattr(sg, "_scm_dependents", boom)
    monkeypatch.setattr(sg, "_registry_dependents", boom)
    assert default_dependents("RpcSs") == ["<unknown>"]


def test_default_dependents_falls_back_to_registry(monkeypatch):
    import memwatch.suggest as sg

    def denied(_):
        raise OSError("access denied")

    monkeypatch.setattr(sg, "_scm_dependents", denied)
    monkeypatch.setattr(sg, "_registry_dependents", lambda s: ["Dep1"])
    assert default_dependents("X") == ["Dep1"]


def test_unknown_dependents_drop_disabled(conn, cfg):
    seed_ticks(conn, "service:foo", n=5, priv=10 << 20, kind="windows", services=["Foo"])
    s = build_report(conn, cfg, now=300, dependents=lambda svc: ["<unknown>"]).suggestions[0]
    assert s.service_modes == ["manual"]


def test_default_dependents_live_never_raises():
    assert isinstance(default_dependents("definitely-not-a-service-xyz"), list)


def test_build_report_is_fast_on_realistic_history(conn, cfg):
    import time

    n_apps, n_ticks = 130, 7 * 1440
    base = int(datetime(2026, 1, 1, 0, 0).timestamp())
    ts_list = [base + i * 60 for i in range(n_ticks)]
    conn.executemany(
        "INSERT INTO system VALUES(?,?,?,?,?,?,?,?,?,?)",
        [(t, 16 << 30, 8 << 30, 10 << 30, 24 << 30, None, 100 << 20, 50 << 20, 0, None)
         for t in ts_list])
    for a in range(n_apps):
        key = f"suite:app{a}"
        conn.execute(
            "INSERT INTO apps VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (key, f"app{a}", "suite", 0, base, ts_list[-1], base if a % 3 == 0 else None,
             None, 1, 0, "[]"))
        conn.executemany(
            "INSERT INTO samples VALUES(?,?,?,?,?,?,?)",
            [(t, key, (50 + a + i % 7) << 20, 40 << 20, 3, int(a % 3 == 0 and i % 500 == 0), 0)
             for i, t in enumerate(ts_list)])
    conn.commit()
    start = time.perf_counter()
    r = build_report(conn, cfg, now=ts_list[-1])
    elapsed = time.perf_counter() - start
    print(f"build_report took {elapsed:.2f}s")
    assert len(r.apps) == n_apps and r.suggestions
    assert all(len(a.spark) <= 48 for a in r.apps) and r.apps[0].spark
    assert elapsed < 2.0
