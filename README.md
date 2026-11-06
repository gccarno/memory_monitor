# memwatch

A small Windows 11 memory monitor. A background logger samples memory use once a minute (about 30 days kept), and a local report suggests what is safe to stop or keep from starting at login, with the reason for each. Nothing is stopped or changed unless you click it in the report.

## Install

```
python -m venv .venv
.venv\Scripts\python -m pip install -e .[dev]
.venv\Scripts\python -m memwatch install
```

`install` needs no admin rights. It adds a per-user startup entry (HKCU `Run`, value `memwatch`) that starts the logger at login, puts a **Memory Report** shortcut on your desktop, and starts the logger now.

## Open the report

Double-click **Memory Report** on the desktop, or run `.venv\Scripts\python -m memwatch report`. The report opens in your browser from a local server on `127.0.0.1`. Until 72 hours of data exist it says "Based on X hours of data". Check progress with `.venv\Scripts\python -m memwatch status`.

Actions that need administrator rights (stopping some services, changing service start types) show a Windows UAC prompt for Python. Approve it only for an action you clicked.

## Security note

Admin actions run memwatch's own Python code (the editable install in this repo and its `.venv`) under the Windows UAC prompt for Python. Anything that can edit this folder could therefore change what runs as admin the next time you approve a prompt. Keep the folder private to your account, or for daily use install memwatch non-editable (`pip install .` into a venv outside this repo).

## Uninstall

```
.venv\Scripts\python -m memwatch uninstall          # remove startup entry and shortcut, stop the logger
.venv\Scripts\python -m memwatch uninstall --purge  # also delete the collected data
```

`--purge` refuses while startup changes made by memwatch are still in effect (it would delete the record needed to undo them). It lists them and where to re-enable each one (Task Manager > Startup apps, Task Scheduler, or services.msc). Undo them in the report first, or add `--force` to purge anyway.

## Where data lives

`%LOCALAPPDATA%\memwatch\`: `memwatch.db` (samples), optional `config.toml` (overrides), `logger.log`.

## Privacy

Everything stays on this PC. The only network traffic is the report served on `127.0.0.1`, protected by a per-run token.
