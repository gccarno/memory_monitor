"""Send whitelisted ops to `elevated_runner` through a UAC prompt."""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path
from typing import Callable, Literal

from memwatch.config import Config

Elevator = Callable[[list[dict]], "list[dict] | Literal['declined']"]

_TIMEOUT_S = 120
_ERROR_CANCELLED = 1223


def _pythonw() -> Path:
    exe = Path(sys.executable)
    w = exe.with_name("pythonw.exe")
    return w if w.is_file() else exe


def _quote(arg: str) -> str:
    return '"' + arg + '"' if (" " in arg or not arg) else arg


def _run_as_admin(exe: str, args: list[str], timeout_s: int) -> int | Literal["declined"] | None:
    """Launch `exe args` via the `runas` verb and wait. Returns the exit code,
    "declined" when the UAC prompt was cancelled, or None on timeout."""
    import pywintypes
    import win32api
    import win32con
    import win32event
    import win32process
    from win32com.shell import shell, shellcon

    try:
        info = shell.ShellExecuteEx(
            fMask=shellcon.SEE_MASK_NOCLOSEPROCESS, lpVerb="runas", lpFile=exe,
            lpParameters=" ".join(_quote(a) for a in args), nShow=win32con.SW_HIDE)
    except pywintypes.error as e:
        if e.winerror == _ERROR_CANCELLED:
            return "declined"
        raise
    h = info["hProcess"]
    try:
        if win32event.WaitForSingleObject(h, timeout_s * 1000) != win32event.WAIT_OBJECT_0:
            return None
        return win32process.GetExitCodeProcess(h)
    finally:
        win32api.CloseHandle(h)


def _failed(n: int, why: str) -> list[dict]:
    return [{"ok": False, "error": why} for _ in range(n)]


def _read_results(path: Path, n: int) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _failed(n, "elevated runner wrote no result")
    if (not isinstance(data, list) or len(data) != n
            or not all(isinstance(r, dict) and isinstance(r.get("ok"), bool) for r in data)):
        return _failed(n, "elevated runner wrote a malformed result")
    return [{"ok": r["ok"], "error": None if r["ok"] else str(r.get("error") or "failed")}
            for r in data]


def run_elevated(ops: list[dict], cfg: Config) -> list[dict] | Literal["declined"]:
    if not ops:
        return []
    data_dir = Path(cfg.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    uid = uuid.uuid4().hex
    inp = data_dir / f"elev-{uid}-in.json"
    out = data_dir / f"elev-{uid}-out.json"
    try:
        inp.write_text(json.dumps(ops), encoding="utf-8")
        try:
            rc = _run_as_admin(str(_pythonw()),
                               ["-I", "-m", "memwatch.elevated_runner", str(inp), str(out)],
                               _TIMEOUT_S)
        except Exception as e:
            return _failed(len(ops), f"could not start elevated runner: {e}")
        if rc == "declined":
            return "declined"
        if rc is None:
            return _failed(len(ops), f"elevated runner did not finish within {_TIMEOUT_S} s")
        return _read_results(out, len(ops))
    finally:
        inp.unlink(missing_ok=True)
        out.unlink(missing_ok=True)
