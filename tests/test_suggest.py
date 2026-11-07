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
    # Defender is protected: present only as a process-name marker, never as an app row.
    for i in range(10):
        write_tick(conn, mk_sys(i * 60), [
            (mk_group(k, p << 20, label=lbl, kind=kind), UsageFlags(False, False, False))
            for k, p, lbl, kind in [
                ("suite:reason security", 300, "Reason Security", "suite"),
                ("protected:windows", 500, "Windows core", "protected"),
                ("suite:zoom", 1900, "Zoom", "suite")]
        ], markers=["Windows Defender"])
    r = build_report(conn, cfg, now=600)
    assert [s.app_key for s in r.suggestions] == ["suite:zoom", "suite:reason security"]
    assert r.suggestions[-1].reasons[-1] == (
        "Duplicate: 2 antivirus products running (Reason Security, Windows Defender)")


def svc_entry(name, key):
    return StartupEntry("service", name, name, "svchost.exe -k x", True, True, True, None, key)


def test_service_modes_drop_disabled_with_dependents(conn, cfg):
    seed_ticks(conn, "service:wsearch", n=10, priv=50 << 20, kind="windows", microsoft=True, services=["WSearch"])
    replace_startup(conn, [svc_entry("WSearch", "service:wsearch")])
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
    assert s.reasons == ["Background service with no app you use: Foo (no description available)"]


def test_windowless_app_without_services_is_not_called_a_service(conn, cfg):
    seed_ticks(conn, "suite:discord", n=5, priv=10 << 20, label="Discord")
    s = build_report(conn, cfg, now=300, service_desc=lambda n: "unused").suggestions[0]
    assert s.reasons == ["Runs in the background with no window you have opened "
                         "while memwatch was watching"]
    assert s.reason_codes == ["STANDALONE"]


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
    replace_startup(conn, [svc_entry("Foo", "service:foo")])
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


# ---- final-review fixes ---------------------------------------------------

def test_duplicate_antivirus_with_protected_defender(conn, cfg):
    """Defender is protected (never a suggestion); its presence comes from the tick's
    process-name marker, and only the non-protected product carries DUPLICATE."""
    for i in range(10):
        write_tick(conn, mk_sys(i * 60), [
            (mk_group("suite:reason security", 300 << 20, label="Reason Security"),
             UsageFlags(False, False, False)),
            (mk_group("protected:windows", 500 << 20, kind="protected", label="Windows core"),
             UsageFlags(False, False, False)),
        ], markers=["Windows Defender"])
    r = build_report(conn, cfg, now=600)
    assert [s.app_key for s in r.suggestions] == ["suite:reason security"]
    assert r.suggestions[0].reason_codes[-1] == "DUPLICATE"
    assert r.suggestions[0].reasons[-1] == (
        "Duplicate: 2 antivirus products running (Reason Security, Windows Defender)")


def test_no_duplicate_when_defender_marker_absent(conn, cfg):
    write_tick(conn, mk_sys(0), [(mk_group("suite:reason security", 300 << 20,
                                           label="Reason Security"),
                                  UsageFlags(False, False, False))], markers=["Windows Defender"])
    write_tick(conn, mk_sys(60), [(mk_group("suite:reason security", 300 << 20,
                                            label="Reason Security"),
                                   UsageFlags(False, False, False))])
    r = build_report(conn, cfg, now=60)
    assert all("DUPLICATE" not in s.reason_codes for s in r.suggestions)


def test_duplicate_browsers_still_work(conn, cfg):
    seed_ticks(conn, "suite:google chrome", n=10, priv=300 << 20, label="Google Chrome")
    seed_ticks(conn, "suite:firefox", n=10, priv=200 << 20, label="Firefox")
    r = build_report(conn, cfg, now=600)
    dups = [s for s in r.suggestions if "DUPLICATE" in s.reason_codes]
    assert {s.app_key for s in dups} == {"suite:google chrome", "suite:firefox"}
    assert dups[0].reasons[-1] == "Duplicate: 2 browser products running (Google Chrome, Firefox)"


def test_stale_data_flag(conn, cfg):
    tick(conn, 1000, "suite:a", priv=600 << 20)
    r = build_report(conn, cfg, now=1000 + 3 * cfg.sample_interval_s)
    assert r.data_ts == 1000 and r.stale is False
    r = build_report(conn, cfg, now=1000 + 3 * cfg.sample_interval_s + 1)
    assert r.data_ts == 1000 and r.stale is True


def test_no_data_is_not_stale(tmp_path, cfg):
    from memwatch.db import connect

    c = connect(tmp_path / "e.db")
    r = build_report(c, cfg, now=10**9)
    assert r.data_ts is None and r.stale is False
    c.close()


def test_shared_svchost_startup_entry_maps_to_group(conn, cfg):
    """A shared svchost group is keyed service:a+b; its services' startup entries
    (keyed service:a) must attach to that group."""
    now = _four_days(conn, key="service:bits+wuauserv")
    conn.execute("UPDATE apps SET services_json = ?, has_windows_ever = 0",
                 ('["BITS", "wuauserv"]',))
    conn.commit()
    e = StartupEntry("service", "Background Intelligent Transfer", "BITS", "svchost.exe -k x",
                     True, True, True, None, "service:bits")
    replace_startup(conn, [e])
    r = build_report(conn, cfg, now=now, dependents=lambda s: [])
    s = r.suggestions[0]
    assert s.app_key == "service:bits+wuauserv"
    assert [x.location for x in s.startup] == ["BITS"]
    assert r.apps[0].autostart is True
    from memwatch.suggest import startup_by_app
    assert [x.location for x in startup_by_app(conn)["service:bits+wuauserv"]] == ["BITS"]


def test_service_modes_come_from_service_startup_entries(conn, cfg):
    """An Automatic-but-stopped service (not in the running group's services) still
    gets a Manual/Disabled choice, and dependents are checked by its name."""
    seed_ticks(conn, "suite:tobii", n=10, priv=600 << 20, label="Tobii")
    e = StartupEntry("service", "Tobii Service", "TobiiSvc", r"C:\Program Files\Tobii\s.exe",
                     True, True, True, None, "suite:tobii")
    replace_startup(conn, [e])
    asked = []
    s = build_report(conn, cfg, now=600,
                     dependents=lambda n: asked.append(n) or []).suggestions[0]
    assert s.service_modes == ["manual", "disabled"] and asked == ["TobiiSvc"]
    s = build_report(conn, cfg, now=600, dependents=lambda n: ["Dep"]).suggestions[0]
    assert s.service_modes == ["manual"]


def test_running_services_without_service_entries_get_no_modes(conn, cfg):
    seed_ticks(conn, "suite:x", n=5, priv=900 << 20, services=["XSvc"])
    assert build_report(conn, cfg, now=300, dependents=lambda n: []).suggestions[0].service_modes == []


def test_suggestion_parts(conn, cfg):
    seed_ticks(conn, "suite:x", n=5, priv=900 << 20, services=["XSvc"])
    s = build_report(conn, cfg, now=300).suggestions[0]
    assert s.services == ["XSvc"] and s.n_procs == 1
