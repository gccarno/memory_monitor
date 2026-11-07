"""`memwatch` command line: log | report | install | uninstall | status."""
from __future__ import annotations

import argparse
import logging
import shutil
import sqlite3
import subprocess
import sys
import winreg
from pathlib import Path

import psutil
import win32api
import win32process

from memwatch import db, probe
from memwatch.config import load_config
from memwatch.elevated_runner import is_memwatch_cmdline

RUN_SUBKEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME = "memwatch"
SHORTCUT_NAME = "Memory Report.lnk"
_DETACHED_PROCESS = 0x00000008
_CREATE_NEW_PROCESS_GROUP = 0x00000200


def pythonw_path() -> Path:
    """The venv's pythonw.exe, whether we were started by python.exe or pythonw.exe."""
    return Path(sys.executable).with_name("pythonw.exe")


def _run_key(root: str | None) -> str:
    return root + "\\" + RUN_SUBKEY if root else RUN_SUBKEY


def _desktop_dir() -> Path:
    from win32com.shell import shell, shellcon

    return Path(shell.SHGetFolderPath(0, shellcon.CSIDL_DESKTOPDIRECTORY, 0, 0))


def is_logger_cmdline(cmdline: list[str] | None) -> bool:
    """A `python -m memwatch log` invocation (not report, not the elevated runner)."""
    if not is_memwatch_cmdline(cmdline):
        return False
    args = [str(a).lower() for a in cmdline or []]
    for i, a in enumerate(args):
        if a == "-m" and args[i + 1:i + 2] == ["memwatch"]:
            return args[i + 2:i + 3] == ["log"]
        if a == "-mmemwatch":
            return args[i + 1:i + 2] == ["log"]
    return False


def find_loggers() -> list[psutil.Process]:
    import os

    out = []
    for p in psutil.process_iter():
        if p.pid == os.getpid() or probe.is_terminated(p):
            continue
        try:
            if is_logger_cmdline(p.cmdline()):
                out.append(p)
        except psutil.Error:
            pass
    return out


def start_logger_detached() -> None:
    pyw = str(pythonw_path())
    hp, ht, _pid, _tid = win32process.CreateProcess(
        None, f'"{pyw}" -m memwatch log', None, None, False,
        win32process.DETACHED_PROCESS | win32process.CREATE_NO_WINDOW
        | win32process.CREATE_NEW_PROCESS_GROUP,
        None, None, win32process.STARTUPINFO())
    win32api.CloseHandle(hp)
    win32api.CloseHandle(ht)


def _wait_gone(procs: list[psutil.Process]) -> None:
    _gone, alive = psutil.wait_procs(procs, timeout=5)
    for p in alive:
        try:
            p.kill()
        except psutil.Error:
            pass
    if alive:
        psutil.wait_procs(alive, timeout=5)


def _cmd_log(args) -> int:
    from memwatch.logger import Logger, acquire_single_instance

    cfg = load_config()
    mutex = acquire_single_instance()
    if mutex is None:
        return 0
    conn = db.connect(cfg.data_dir / "memwatch.db")
    Logger(cfg, conn).run_forever()
    del mutex
    return 0


def _cmd_report(args) -> int:
    from memwatch.server import serve_report

    serve_report(load_config())
    return 0


def _cmd_install(args) -> int:
    if args.root and not args.desktop:
        print("--root requires --desktop", file=sys.stderr)
        return 2
    import win32com.client

    pyw = pythonw_path()
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, _run_key(args.root), 0,
                            winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, RUN_NAME, 0, winreg.REG_SZ, f'"{pyw}" -m memwatch log')
    try:
        desktop = Path(args.desktop) if args.desktop else _desktop_dir()
        desktop.mkdir(parents=True, exist_ok=True)
        lnk = win32com.client.Dispatch("WScript.Shell").CreateShortCut(
            str(desktop / SHORTCUT_NAME))
        lnk.TargetPath = str(pyw)
        lnk.Arguments = "-m memwatch report"
        lnk.WorkingDirectory = str(pyw.parent)
        lnk.Description = "memwatch memory report"
        lnk.save()
    except Exception as e:
        print(f"memwatch: startup entry was written but the desktop shortcut failed: {e}",
              file=sys.stderr)
        print("Run `python -m memwatch uninstall` to undo, or create the shortcut by hand.",
              file=sys.stderr)
        return 1
    start_logger_detached()
    print("memwatch installed: logger starts at login; shortcut 'Memory Report' created.")
    return 0


_UNDO_HOW = {
    "run": "Task Manager > Startup apps",
    "startup_folder": "Task Manager > Startup apps",
    "packaged": "Task Manager > Startup apps",
    "task": "Task Scheduler (enable the task)",
    "service": "services.msc (set the startup type back to Automatic)",
}


def _outstanding_changes(data_dir: Path) -> list:
    """memwatch startup changes that were never undone (the purge would lose their record)."""
    path = data_dir / "memwatch.db"
    if not path.is_file():
        return []
    try:
        conn = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
        try:
            return db.list_actions(conn)
        finally:
            conn.close()
    except sqlite3.Error:
        return []


def _cmd_uninstall(args) -> int:
    if args.root and not args.desktop:
        print("--root requires --desktop", file=sys.stderr)
        return 2
    if args.purge and not args.force:
        pending = _outstanding_changes(load_config().data_dir)
        if pending:
            print(f"memwatch: {len(pending)} startup change(s) made by memwatch are still in "
                  "effect, and purging deletes the record needed to undo them:",
                  file=sys.stderr)
            for rec in pending:
                src = rec.entry.get("source", "")
                print(f"  - {rec.entry.get('name', rec.app_key)} ({src}): re-enable in "
                      f"{_UNDO_HOW.get(src, 'Task Manager or services.msc')}", file=sys.stderr)
            print("Undo them in the report's Undo section (or by hand as above), then run "
                  "this again; or pass --force to purge anyway. Nothing was removed.",
                  file=sys.stderr)
            return 1
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _run_key(args.root), 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, RUN_NAME)
    except FileNotFoundError:
        pass
    desktop = Path(args.desktop) if args.desktop else _desktop_dir()
    (desktop / SHORTCUT_NAME).unlink(missing_ok=True)
    procs = find_loggers()
    for p in procs:
        try:
            p.terminate()
        except psutil.Error:
            pass
    _wait_gone(procs)
    if args.purge:
        data_dir = load_config().data_dir
        shutil.rmtree(data_dir, ignore_errors=True)
        left = [str(f) for f in data_dir.rglob("*") if f.is_file()] if data_dir.exists() else []
        if left:
            print("memwatch: could not delete these files:", *left, sep=" | ",
                  file=sys.stderr)
            return 1
    print("memwatch uninstalled.")
    return 0


def _cmd_status(args) -> int:
    cfg = load_config()
    path = cfg.data_dir / "memwatch.db"
    print(f"logger running: {'yes' if find_loggers() else 'no'}")
    if not path.is_file():
        print("db size: 0.0 MB")
        print("observed: 0.0 hours")
        print("logger memory: unknown")
        return 0
    print(f"db size: {path.stat().st_size / 2**20:.1f} MB")
    hours, ws = 0.0, None
    try:
        conn = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
        try:
            hours = len(db.system_ticks_since(conn, 0)) * cfg.sample_interval_s / 3600
            latest = db.latest_system(conn)
            ws = latest.logger_ws if latest else None
        finally:
            conn.close()
    except sqlite3.Error:
        pass
    print(f"observed: {hours:.1f} hours")
    if ws is None:
        print("logger memory: unknown")
    else:
        print(f"logger memory: {ws / 2**20:.0f} MB (cap {cfg.logger_cap_mb} MB)")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="memwatch")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("log", help="run the logger (foreground)").set_defaults(fn=_cmd_log)
    sub.add_parser("report", help="open the memory report").set_defaults(fn=_cmd_report)
    for name, fn in (("install", _cmd_install), ("uninstall", _cmd_uninstall)):
        p = sub.add_parser(name)
        p.add_argument("--root", help=argparse.SUPPRESS)  # tests only
        p.add_argument("--desktop", help=argparse.SUPPRESS)  # tests only
        if name == "uninstall":
            p.add_argument("--purge", action="store_true", help="also delete the data dir")
            p.add_argument("--force", action="store_true",
                           help="purge even while memwatch startup changes are not undone")
        p.set_defaults(fn=fn)
    sub.add_parser("status").set_defaults(fn=_cmd_status)
    args = ap.parse_args(argv)
    if args.cmd not in ("log", "report"):
        return args.fn(args)
    # Windowless entry points: failures must land in logger.log, not vanish.
    from memwatch.logger import setup_logging

    try:
        setup_logging(load_config())
        return args.fn(args)
    except Exception:
        logging.getLogger("memwatch.cli").exception("memwatch %s failed", args.cmd)
        return 1
