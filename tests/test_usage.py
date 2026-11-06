from __future__ import annotations

from conftest import mkproc

from memwatch.grouping import group_processes
from memwatch.usage import mark_usage

CLAUDE = r"C:\u\.local\bin\claude.exe"
STEAM = r"C:\Program Files (x86)\Steam\steam.exe"


def _term_procs():
    return [mkproc(60, 1, "mintty.exe", "x"), mkproc(61, 60, "bash.exe", "x"),
            mkproc(62, 61, "claude.exe", CLAUDE),
            mkproc(70, 1, "mintty.exe", "x"), mkproc(72, 70, "claude.exe", CLAUDE)]


def test_terminal_focus_credits_cli_sessions_inside_it(cfg):
    procs = _term_procs()
    g = group_processes(procs, {}, cfg)
    f = mark_usage(g, procs, {}, fg_pid=60, win_pids={60, 70}, user_away=False, cfg=cfg)
    assert f["claude-cli:62:1"].foreground and not f["claude-cli:72:1"].foreground


def test_user_away_means_no_foreground(cfg):
    procs = _term_procs()
    g = group_processes(procs, {}, cfg)
    f = mark_usage(g, procs, {}, fg_pid=60, win_pids={60, 70}, user_away=True, cfg=cfg)
    assert not any(x.foreground for x in f.values())


def test_foreground_group_containing_pid(cfg):
    p = mkproc(80, 1, "steam.exe", STEAM)
    f = mark_usage(group_processes([p], {}, cfg), [p], {}, 80, {80}, False, cfg)
    assert f["suite:steam"].foreground and f["suite:steam"].has_windows


def test_active_by_cpu_delta(cfg):
    p = mkproc(80, 1, "steam.exe", STEAM, cpu_s=10.6)
    f = mark_usage(group_processes([p], {}, cfg), [p], {(80, 1.0): (10.0, 0)}, None, set(), False, cfg)
    assert f["suite:steam"].active


def test_active_by_io_delta_and_new_process_is_idle(cfg):
    p = mkproc(80, 1, "steam.exe", STEAM, io_bytes=5_000_000)
    g = group_processes([p], {}, cfg)
    assert mark_usage(g, [p], {(80, 1.0): (0.0, 0)}, None, set(), False, cfg)["suite:steam"].active
    assert not mark_usage(g, [p], {}, None, set(), False, cfg)["suite:steam"].active


def test_limited_none_values_are_delta_zero(cfg):
    p = mkproc(80, 1, "steam.exe", STEAM, cpu_s=None, io_bytes=None, limited=True)
    g = group_processes([p], {}, cfg)
    f = mark_usage(g, [p], {(80, 1.0): (0.0, 0)}, None, set(), False, cfg)
    assert not f["suite:steam"].active


def test_ancestor_cycle_and_pid_reuse_are_guarded(cfg):
    procs = [mkproc(60, 61, "mintty.exe", "x"), mkproc(61, 60, "bash.exe", "x"),
             mkproc(62, 61, "claude.exe", CLAUDE),
             # parent created later than child: PID reuse, must not be credited
             mkproc(90, 1, "mintty.exe", "x", create_time=50.0),
             mkproc(92, 90, "claude.exe", CLAUDE, create_time=5.0)]
    g = group_processes(procs, {}, cfg)
    f = mark_usage(g, procs, {}, fg_pid=90, win_pids=set(), user_away=False, cfg=cfg)
    assert not f["claude-cli:92:5"].foreground
    f = mark_usage(g, procs, {}, fg_pid=60, win_pids=set(), user_away=False, cfg=cfg)
    assert f["claude-cli:62:1"].foreground
