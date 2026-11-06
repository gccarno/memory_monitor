"""`memwatch` command line: log | report | install | uninstall | status."""
from __future__ import annotations

import argparse
import shutil
import sqlite3
import subprocess
import sys
import winreg
from pathlib import Path

import psutil

from memwatch import db
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
    for p in psutil.process_iter(["pid", "cmdline"]):
        if p.info["pid"] != os.getpid() and is_logger_cmdline(p.info["cmdline"]):
            out.append(p)
    return out


def start_logger_detached() -> None:
    subprocess.Popen(
        [str(pythonw_path()), "-m", "memwatch", "log"],
        creationflags=_DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        close_fds=True,
    )


def _wait_gone(procs: list[psutil.Process]) -> None:
    psutil.wait_procs(procs, timeout=5)


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
    desktop = Path(args.desktop) if args.desktop else _desktop_dir()
    desktop.mkdir(parents=True, exist_ok=True)
    lnk = win32com.client.Dispatch("WScript.Shell").CreateShortCut(
        str(desktop / SHORTCUT_NAME))
    lnk.TargetPath = str(pyw)
    lnk.Arguments = "-m memwatch report"
    lnk.WorkingDirectory = str(pyw.parent)
    lnk.Description = "memwatch memory report"
    lnk.save()
    start_logger_detached()
    print("memwatch installed: logger starts at login; shortcut 'Memory Report' created.")
    return 0


def _cmd_uninstall(args) -> int:
    if args.root and not args.desktop:
        print("--root requires --desktop", file=sys.stderr)
        return 2
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
        shutil.rmtree(load_config().data_dir, ignore_errors=True)
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
        p.set_defaults(fn=fn)
    sub.add_parser("status").set_defaults(fn=_cmd_status)
    args = ap.parse_args(argv)
    return args.fn(args)
