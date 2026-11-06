from __future__ import annotations

import sqlite3
import sys
import uuid
import winreg
from pathlib import Path

import pytest

from memwatch import cli
from memwatch.cli import main

from conftest import mk_sys

RUN_SUB = r"Software\Microsoft\Windows\CurrentVersion\Run"


def read_hkcu_run(root, name):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"{root}\{RUN_SUB}") as k:
            return winreg.QueryValueEx(k, name)[0]
    except FileNotFoundError:
        return None


def _delete_tree(path):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0,
                            winreg.KEY_ALL_ACCESS) as k:
            while True:
                try:
                    sub = winreg.EnumKey(k, 0)
                except OSError:
                    break
                _delete_tree(f"{path}\{sub}")
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
    except FileNotFoundError:
        pass


@pytest.fixture
def test_root():
    root = rf"Software\memwatch-test-{uuid.uuid4().hex[:8]}"
    yield root
    _delete_tree(root)


def test_install_uninstall_roundtrip(tmp_path, test_root, monkeypatch):
    monkeypatch.setattr(cli, "start_logger_detached", lambda: None)
    monkeypatch.setattr(cli, "find_loggers", lambda: [])
    assert main(["install", "--root", test_root, "--desktop", str(tmp_path)]) == 0
    val = read_hkcu_run(test_root, "memwatch")
    assert 'pythonw.exe" -m memwatch log' in val and val.startswith('"')
    assert (tmp_path / "Memory Report.lnk").exists()
    assert main(["uninstall", "--root", test_root, "--desktop", str(tmp_path)]) == 0
    assert read_hkcu_run(test_root, "memwatch") is None
    assert not (tmp_path / "Memory Report.lnk").exists()


def test_install_without_desktop_under_root_refuses(test_root, monkeypatch):
    monkeypatch.setattr(cli, "start_logger_detached", lambda: pytest.fail("started"))
    assert main(["install", "--root", test_root]) == 2
    assert read_hkcu_run(test_root, "memwatch") is None


def test_pythonw_derived_from_sys_executable(monkeypatch):
    monkeypatch.setattr(sys, "executable", r"C:\v\Scripts\python.exe")
    assert cli.pythonw_path() == Path(r"C:\v\Scripts\pythonw.exe")
    monkeypatch.setattr(sys, "executable", r"C:\v\Scripts\pythonw.exe")
    assert cli.pythonw_path() == Path(r"C:\v\Scripts\pythonw.exe")


def test_logger_cmdline_match_is_specific():
    f = cli.is_logger_cmdline
    assert f(["pythonw.exe", "-m", "memwatch", "log"])
    assert not f(["pythonw.exe", "-m", "memwatch", "report"])
    assert not f(["pythonw.exe", "-I", "-m", "memwatch.elevated_runner", "x", "log"])
    assert not f(["python.exe", "other.py", "log"])
    assert not f(None)


def test_uninstall_stops_only_found_loggers(tmp_path, test_root, monkeypatch):
    stopped = []

    class P:
        pid = 1

        def terminate(self):
            stopped.append(1)

    monkeypatch.setattr(cli, "find_loggers", lambda: [P()])
    monkeypatch.setattr(cli, "_wait_gone", lambda ps: None)
    assert main(["uninstall", "--root", test_root, "--desktop", str(tmp_path)]) == 0
    assert stopped == [1]


def test_uninstall_purge_deletes_data_dir(tmp_path, test_root, monkeypatch):
    local = tmp_path / "local"
    (local / "memwatch").mkdir(parents=True)
    (local / "memwatch" / "memwatch.db").write_bytes(b"x")
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setattr(cli, "find_loggers", lambda: [])
    assert main(["uninstall", "--purge", "--root", test_root,
                 "--desktop", str(tmp_path)]) == 0
    assert not (local / "memwatch").exists()


def test_status_runs_without_db(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(cli, "find_loggers", lambda: [])
    assert main(["status"]) == 0
    out = capsys.readouterr().out
    assert "logger running: no" in out
    assert "logger memory: unknown" in out
    assert not (tmp_path / "memwatch").exists()


def test_status_with_db(tmp_path, capsys, monkeypatch):
    from memwatch import db

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(cli, "find_loggers", lambda: [object()])
    conn = db.connect(tmp_path / "memwatch" / "memwatch.db")
    for i in range(120):
        db.write_tick(conn, mk_sys(i * 60, logger_ws=30 * 2**20), [])
    conn.close()
    assert main(["status"]) == 0
    out = capsys.readouterr().out
    assert "logger running: yes" in out
    assert "observed: 2.0 hours" in out
    assert "logger memory: 30 MB (cap 50 MB)" in out
    assert "db size: " in out and " MB" in out
