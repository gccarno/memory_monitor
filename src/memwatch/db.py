from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import (
    ActionRecord, AppGroup, AppRecord, SampleRow, StartupEntry, SystemSnapshot, UsageFlags,
)

_SYSTEM_COLS = (
    "ts", "ram_total", "ram_avail", "commit_used", "commit_limit",
    "compression_ws", "pool_paged", "pool_nonpaged", "boot_time", "logger_ws",
)
_STARTUP_COLS = (
    "source", "name", "location", "command", "enabled", "needs_admin",
    "can_disable", "note", "app_key",
)
_ACTION_COLS = "id, ts, app_key, action, entry_json, before_json, undone"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS samples(
    ts INTEGER, app_key TEXT, private_bytes INTEGER, working_set INTEGER,
    n_procs INTEGER, foreground INTEGER, active INTEGER,
    PRIMARY KEY(ts, app_key));
CREATE INDEX IF NOT EXISTS idx_samples_app_ts ON samples(app_key, ts);
CREATE TABLE IF NOT EXISTS system(
    ts INTEGER PRIMARY KEY, ram_total INTEGER, ram_avail INTEGER,
    commit_used INTEGER, commit_limit INTEGER, compression_ws INTEGER,
    pool_paged INTEGER, pool_nonpaged INTEGER, boot_time INTEGER, logger_ws INTEGER);
CREATE TABLE IF NOT EXISTS apps(
    app_key TEXT PRIMARY KEY, label TEXT, kind TEXT, microsoft INTEGER,
    first_seen INTEGER, last_seen INTEGER, last_used INTEGER, last_active INTEGER,
    has_windows_ever INTEGER, limited INTEGER, services_json TEXT);
CREATE TABLE IF NOT EXISTS startup(
    source TEXT, name TEXT, location TEXT, command TEXT, enabled INTEGER,
    needs_admin INTEGER, can_disable INTEGER, note TEXT, app_key TEXT);
CREATE TABLE IF NOT EXISTS actions(
    id INTEGER PRIMARY KEY, ts INTEGER, app_key TEXT, action TEXT,
    entry_json TEXT, before_json TEXT, undone INTEGER DEFAULT 0);
"""


def connect(path: Path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def write_tick(
    conn: sqlite3.Connection,
    system: SystemSnapshot,
    apps: list[tuple[AppGroup, UsageFlags]],
) -> None:
    ts = system.ts
    with conn:
        conn.execute(
            f"INSERT OR REPLACE INTO system({','.join(_SYSTEM_COLS)}) "
            f"VALUES({','.join('?' * len(_SYSTEM_COLS))})",
            [getattr(system, c) for c in _SYSTEM_COLS],
        )
        for g, f in apps:
            conn.execute(
                "INSERT OR REPLACE INTO samples VALUES(?,?,?,?,?,?,?)",
                (ts, g.app_key, g.private_bytes, g.working_set, len(g.pids),
                 int(f.foreground), int(f.active)),
            )
            conn.execute(
                """INSERT INTO apps(app_key, label, kind, microsoft, first_seen, last_seen,
                       last_used, last_active, has_windows_ever, limited, services_json)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(app_key) DO UPDATE SET
                       label=excluded.label, kind=excluded.kind, microsoft=excluded.microsoft,
                       last_seen=excluded.last_seen,
                       last_used=COALESCE(excluded.last_used, apps.last_used),
                       last_active=COALESCE(excluded.last_active, apps.last_active),
                       has_windows_ever=apps.has_windows_ever OR excluded.has_windows_ever,
                       limited=excluded.limited, services_json=excluded.services_json""",
                (g.app_key, g.label, g.kind, int(g.microsoft), ts, ts,
                 ts if f.foreground else None, ts if f.active else None,
                 int(f.has_windows), int(g.limited), json.dumps(g.services)),
            )


def prune(conn: sqlite3.Connection, now: int, retention_days: int) -> int:
    cutoff = now - retention_days * 86400
    with conn:
        n = conn.execute("DELETE FROM samples WHERE ts < ?", (cutoff,)).rowcount
        conn.execute("DELETE FROM system WHERE ts < ?", (cutoff,))
        conn.execute("DELETE FROM apps WHERE last_seen < ?", (cutoff,))
    return n


def latest_system(conn: sqlite3.Connection) -> SystemSnapshot | None:
    row = conn.execute(
        f"SELECT {','.join(_SYSTEM_COLS)} FROM system ORDER BY ts DESC LIMIT 1"
    ).fetchone()
    return SystemSnapshot(*row) if row else None


def system_ticks_since(conn: sqlite3.Connection, since: int) -> list[int]:
    return [r[0] for r in conn.execute(
        "SELECT ts FROM system WHERE ts >= ? ORDER BY ts", (since,))]


def app_history(conn: sqlite3.Connection, since: int) -> dict[str, list[SampleRow]]:
    out: dict[str, list[SampleRow]] = {}
    for key, ts, priv, ws, fg, act in conn.execute(
        "SELECT app_key, ts, private_bytes, working_set, foreground, active "
        "FROM samples WHERE ts >= ? ORDER BY app_key, ts", (since,)
    ):
        out.setdefault(key, []).append(SampleRow(ts, priv, ws, bool(fg), bool(act)))
    return out


def all_apps(conn: sqlite3.Connection) -> list[AppRecord]:
    return [
        AppRecord(k, label, kind, bool(ms), fs, ls, lu, la, bool(hw), bool(lim),
                  json.loads(svc) if svc else [])
        for k, label, kind, ms, fs, ls, lu, la, hw, lim, svc in conn.execute(
            "SELECT app_key, label, kind, microsoft, first_seen, last_seen, last_used, "
            "last_active, has_windows_ever, limited, services_json FROM apps ORDER BY app_key")
    ]


def latest_groups(conn: sqlite3.Connection) -> dict[str, tuple[int, int, int]]:
    return {k: (ts, priv, ws) for k, ts, priv, ws in conn.execute(
        "SELECT app_key, ts, private_bytes, working_set FROM samples "
        "WHERE ts = (SELECT MAX(ts) FROM samples)")}


def replace_startup(conn: sqlite3.Connection, entries: list[StartupEntry]) -> None:
    with conn:
        conn.execute("DELETE FROM startup")
        conn.executemany(
            f"INSERT INTO startup({','.join(_STARTUP_COLS)}) "
            f"VALUES({','.join('?' * len(_STARTUP_COLS))})",
            [(e.source, e.name, e.location, e.command, int(e.enabled),
              int(e.needs_admin), int(e.can_disable), e.note, e.app_key)
             for e in entries],
        )


def startup_entries(conn: sqlite3.Connection) -> list[StartupEntry]:
    return [
        StartupEntry(s, n, loc, cmd, bool(en), bool(na), bool(cd), note, ak)
        for s, n, loc, cmd, en, na, cd, note, ak in conn.execute(
            f"SELECT {','.join(_STARTUP_COLS)} FROM startup ORDER BY rowid")
    ]


def _action(row: tuple) -> ActionRecord:
    i, ts, key, action, entry, before, undone = row
    return ActionRecord(i, ts, key, action, json.loads(entry), json.loads(before), bool(undone))


def record_action(conn: sqlite3.Connection, rec: ActionRecord) -> int:
    with conn:
        cur = conn.execute(
            "INSERT INTO actions(ts, app_key, action, entry_json, before_json, undone) "
            "VALUES(?,?,?,?,?,?)",
            (rec.ts, rec.app_key, rec.action, json.dumps(rec.entry),
             json.dumps(rec.before), int(rec.undone)),
        )
    return cur.lastrowid


def list_actions(conn: sqlite3.Connection, include_undone: bool = False) -> list[ActionRecord]:
    where = "" if include_undone else "WHERE undone = 0"
    return [_action(r) for r in conn.execute(
        f"SELECT {_ACTION_COLS} FROM actions {where} ORDER BY id")]


def get_action(conn: sqlite3.Connection, id: int) -> ActionRecord | None:
    row = conn.execute(f"SELECT {_ACTION_COLS} FROM actions WHERE id = ?", (id,)).fetchone()
    return _action(row) if row else None


def mark_undone(conn: sqlite3.Connection, id: int) -> None:
    with conn:
        conn.execute("UPDATE actions SET undone = 1 WHERE id = ?", (id,))
