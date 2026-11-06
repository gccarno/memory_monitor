"""Turn the logged history into plain-English stop suggestions."""
from __future__ import annotations

import statistics
from bisect import bisect_left, bisect_right
from collections import defaultdict
from datetime import datetime
from typing import Callable

from .config import Config
from .db import (
    all_apps, app_history, latest_groups, latest_system, list_actions,
    startup_entries, system_ticks_since,
)
from .models import AppSummary, Report, Suggestion

_HISTORY_DAYS = 30
_AUTOSTART_SOURCES = frozenset({"run", "startup_folder", "packaged", "service"})


def fmt_size(b: int) -> str:
    if b >= 2**30:
        return f"{b / 2**30:.1f} GB"
    return f"{b / 2**20:.0f} MB"


def fmt_dur(s: int) -> str:
    s = int(s)
    if s < 3600:
        n, unit = s // 60, "minute"
    elif s < 48 * 3600:
        n, unit = s // 3600, "hour"
    else:
        n, unit = s // 86400, "day"
    return f"{n} {unit}{'' if n == 1 else 's'}"


def default_service_desc(service: str) -> str:
    try:
        import win32service

        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        try:
            h = win32service.OpenService(scm, service, win32service.SERVICE_QUERY_CONFIG)
            try:
                desc = win32service.QueryServiceConfig2(h, win32service.SERVICE_CONFIG_DESCRIPTION)
            finally:
                win32service.CloseServiceHandle(h)
        finally:
            win32service.CloseServiceHandle(scm)
        return desc or ""
    except Exception:
        return ""


def default_dependents(service: str) -> list[str]:
    try:
        import win32service

        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        try:
            h = win32service.OpenService(scm, service, win32service.SERVICE_ENUMERATE_DEPENDENTS)
            try:
                found = win32service.EnumDependentServices(h, win32service.SERVICE_ACTIVE)
            finally:
                win32service.CloseServiceHandle(h)
        finally:
            win32service.CloseServiceHandle(scm)
        return [str(item[0]) for item in found]
    except Exception:
        return []


def _day(ts: int):
    return datetime.fromtimestamp(ts).date()


def _spark(samples) -> list[int]:
    buckets: dict[int, int] = {}
    for s in samples:
        h = s.ts // 3600
        buckets[h] = max(buckets.get(h, 0), s.private_bytes)
    return [buckets[h] for h in sorted(buckets)[-48:]]


def build_report(
    conn,
    cfg: Config,
    now: int,
    exclude_keys: set[str] = frozenset(),
    dependents: Callable[[str], list[str]] = default_dependents,
    service_desc: Callable[[str], str] = default_service_desc,
) -> Report:
    interval = cfg.sample_interval_s
    since = now - _HISTORY_DAYS * 86400
    ticks = system_ticks_since(conn, since)
    observed_s = len(ticks) * interval
    observed_hours = observed_s / 3600
    partial_note = (f"Based on {fmt_dur(observed_s)} of data"
                    if observed_hours < cfg.partial_hours else None)
    observed_days = len({_day(t) for t in ticks})
    recent = ticks[-10:]

    system = latest_system(conn)
    uptime_s = max(0, now - system.boot_time) if system else 0
    kernel_note = None
    if system and system.pool_nonpaged > cfg.nonpaged_warn_mb * 2**20:
        kernel_note = (
            f"Windows kernel memory is high ({fmt_size(system.pool_nonpaged)} non-paged). "
            f"This is often a driver leak; a reboot clears it. Up {fmt_dur(uptime_s)}."
        )
    logger_ws = system.logger_ws if system else None
    logger_over_cap = logger_ws is not None and logger_ws > cfg.logger_cap_mb * 2**20

    present = latest_groups(conn)
    history = app_history(conn, since)
    apps = {a.app_key: a for a in all_apps(conn)}
    entries_by_app: dict[str, list] = defaultdict(list)
    for e in startup_entries(conn):
        if e.app_key:
            entries_by_app[e.app_key].append(e)

    cands = {k: apps[k] for k in present
             if k in apps and apps[k].kind != "protected" and k not in exclude_keys}

    def autostart(rec) -> bool:
        for e in entries_by_app.get(rec.app_key, []):
            if not e.enabled:
                continue
            if e.source in _AUTOSTART_SOURCES or (e.source == "task" and not rec.microsoft):
                return True
        return False

    # DUPLICATE: category membership by app label (case-insensitive)
    dup: dict[str, tuple[str, list[str]]] = {}
    for cat, members in cfg.categories.items():
        by_label = {r.label.lower(): r for r in cands.values()}
        here = [by_label[m.lower()] for m in members if m.lower() in by_label]
        if len(here) >= 2:
            labels = [r.label for r in here]
            for r in here:
                dup.setdefault(r.app_key, (cat, labels))

    suggestions: list[Suggestion] = []
    summaries: list[AppSummary] = []
    for key, rec in cands.items():
        _, priv, ws = present[key]
        samples = history.get(key, [])
        instance = rec.kind == "instance"
        if rec.last_used is None:
            n_idle = len(ticks) - bisect_left(ticks, rec.first_seen)
        else:
            n_idle = len(ticks) - bisect_right(ticks, rec.last_used)
        idle_s = n_idle * interval
        size, idle = fmt_size(priv), fmt_dur(idle_s)
        large = priv >= cfg.large_mb * 2**20
        is_idle = idle_s >= cfg.idle_days * 86400
        reasons: list[str] = []
        codes: list[str] = []

        def add(code: str, text: str) -> None:
            codes.append(code)
            reasons.append(text)

        if large and is_idle:
            add("LARGE_IDLE", f"Big and idle: {size}, not used in {idle} of laptop use")
        elif is_idle and (rec.has_windows_ever or instance):
            add("IDLE", f"Not used in {idle} of laptop use, holding {size}")
        elif large:
            add("LARGE", f"Using a lot of memory: {size}")
        if (instance and rec.last_active is not None and recent
                and rec.last_active >= recent[0] and idle_s >= 3600):
            add("POLLING", f"Still running and busy, but you haven't looked at it in {idle}")
        age = now - rec.first_seen
        if instance and age >= cfg.long_running_days * 86400:
            add("LONG_RUNNING", f"Running for {fmt_dur(age)}")
        is_auto = autostart(rec)
        if is_auto and observed_days >= cfg.rare_min_observed_days:
            used_days = len({_day(s.ts) for s in samples if s.foreground})
            if used_days <= cfg.rare_max_days_used:
                add("AUTOSTART_RARE",
                    f"Starts with Windows but you used it on only {used_days} of the last "
                    f"{observed_days} days")
        if not rec.has_windows_ever and not instance:
            desc = (cfg.notes.get(key)
                    or next((d for d in (service_desc(s) for s in rec.services) if d), "")
                    or "no description available")
            add("STANDALONE", f"Background service with no app you use: {desc}")
        if key in dup:
            cat, labels = dup[key]
            add("DUPLICATE",
                f"Duplicate: {len(labels)} {cat} products running ({', '.join(labels)})")

        summaries.append(AppSummary(key, rec.label, priv, rec.last_used, is_auto, _spark(samples)))
        if not codes:
            continue
        caution = (cfg.notes.get(key, "Part of Windows; turning it off may affect some features.")
                   if rec.microsoft else None)
        modes: list[str] = []
        if rec.services:
            modes = ["manual", "disabled"]
            if any(dependents(s) for s in rec.services):
                modes.remove("disabled")
        startup = sorted(entries_by_app.get(key, []), key=lambda e: not e.enabled)
        typical = int(statistics.median(s.private_bytes for s in samples)) if samples else priv
        suggestions.append(Suggestion(
            key, rec.label, rec.kind, priv, ws, typical, rec.last_used, idle_s, reasons,
            codes, rec.has_windows_ever, caution, rec.limited, startup, modes))

    suggestions.sort(key=lambda s: (set(s.reason_codes) <= {"DUPLICATE", "STANDALONE"},
                                    -s.private_bytes))
    summaries.sort(key=lambda a: -a.private_bytes)
    return Report(
        now=now, system=system, observed_hours=observed_hours, partial_note=partial_note,
        reclaimable=sum(s.private_bytes for s in suggestions), suggestions=suggestions,
        apps=summaries, kernel_note=kernel_note, uptime_s=uptime_s, logger_ws=logger_ws,
        logger_over_cap=logger_over_cap, undo=list_actions(conn))
