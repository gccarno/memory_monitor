from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path


def _default_data_dir() -> Path:
    return Path(os.environ["LOCALAPPDATA"]) / "memwatch"


_PROTECTED_NAMES = frozenset({
    "system", "idle", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "dwm.exe",
    "explorer.exe", "fontdrvhost.exe", "memory compression", "secure system",
    "sihost.exe", "ctfmon.exe", "audiodg.exe", "msmpeng.exe", "nissrv.exe",
    "mpdefendercoreservice.exe", "securityhealthservice.exe",
    "securityhealthsystray.exe", "taskhostw.exe", "runtimebroker.exe",
    "startmenuexperiencehost.exe", "shellexperiencehost.exe", "searchhost.exe",
    "textinputhost.exe", "lockapp.exe", "wudfhost.exe",
})

_PROTECTED_SERVICES = frozenset({
    "rpcss", "dcomlaunch", "rpceptmapper", "lsm", "brokerinfrastructure",
    "power", "plugplay", "eventlog", "schedule", "profsvc", "usermanager",
    "coremessagingregistrar", "systemeventsbroker", "dhcp", "dnscache", "nsi",
    "nlasvc", "netprofm", "winmgmt", "cryptsvc", "audiosrv",
    "audioendpointbuilder", "themes", "gpsvc", "windefend", "mdcoresvc",
    "wdnissvc", "securityhealthservice", "mpssvc", "bfe", "wscsvc",
    "staterepository", "timebrokersvc", "camsvc", "dispbrokerdesktopsvc",
    "appinfo", "tokenbroker", "samss", "keyiso", "vaultsvc", "wlansvc",
    "wcmsvc", "lanmanworkstation", "sens", "fontcache", "shellhwdetection",
    "cdpusersvc", "wpnservice", "wpnusersvc", "tabletinputservice",
    "textinputmanagementservice", "appxsvc", "clipsvc", "msiserver",
    "trustedinstaller",
})

_TERMINAL_NAMES = frozenset({
    "windowsterminal.exe", "mintty.exe", "openconsole.exe", "conhost.exe",
    "wezterm-gui.exe", "alacritty.exe",
})

# Children of these do not inherit their parent's group.
_SHELL_PARENT_NAMES = frozenset({
    "explorer.exe", "services.exe", "svchost.exe", "wininit.exe",
    "userinit.exe", "windowsterminal.exe", "mintty.exe", "openconsole.exe",
    "conhost.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe",
    "taskhostw.exe", "sihost.exe",
})

_SUITE_OVERRIDES = {
    "\\google\\chrome\\": "Google Chrome",
    "\\mozilla firefox\\": "Firefox",
    "\\citrix\\": "Citrix",
    "\\zoom\\": "Zoom",
    "\\steam\\": "Steam",
    "\\discord\\": "Discord",
    "\\nvidia corporation\\": "NVIDIA",
    "\\lenovo\\": "Lenovo Vantage",
    "\\samsung\\": "Samsung",
    "\\tobii\\": "Tobii",
    "\\reasonlabs\\": "Reason Security",
    "\\android\\sdk\\": "Android SDK",
    "\\adobe\\": "Adobe",
    "\\displaylink\\": "DisplayLink",
    "\\tobiiab.": "Tobii",
    "\\google\\drive": "Google Drive",
    "\\driverstore\\filerepository\\lenovo": "Lenovo Vantage",
    "\\driverstore\\filerepository\\nv_": "NVIDIA",
    "\\driverstore\\filerepository\\nvlt.": "NVIDIA",
    "\\elevocinstalldriver\\": "Elevoc",
    "\\common files\\microsoft shared\\": "Microsoft Office",
}

_CATEGORIES = {
    "antivirus": ["Reason Security", "Windows Defender"],
    "browser": ["Google Chrome", "Firefox", "Microsoft Edge"],
}

_NOTES = {
    "service:wsearch": "Windows Search indexing: Start-menu and File Explorer search get slower without it.",
    "service:sysmain": "SysMain preloads apps you use often; turning it off frees memory but apps may open a bit slower.",
    "service:diagtrack": "Telemetry sent to Microsoft; safe to turn off.",
    "suite:microsoft.yourphone": "Phone Link: you lose phone notifications and texts on the PC.",
    "suite:microsoftwindows.client.webexperience": "Widgets board: the taskbar widgets stop working.",
    "service:wslservice": "WSL: Linux distros and Docker Desktop need this.",
    "service:edgeupdate": "Edge updater: Edge will update less promptly.",
    "suite:microsoft onedrive": "OneDrive: files stop syncing until it is started again.",
}


@dataclass
class Config:
    sample_interval_s: int = 60
    retention_days: int = 30
    idle_days: float = 2.0
    large_mb: int = 500
    long_running_days: float = 2.0
    rare_max_days_used: int = 2
    rare_min_observed_days: int = 3
    cpu_active_s: float = 0.5  # per tick
    io_active_bytes: int = 1_048_576  # per tick
    user_away_s: int = 300
    close_timeout_s: int = 10
    logger_cap_mb: int = 50
    nonpaged_warn_mb: int = 500
    partial_hours: int = 72
    heartbeat_timeout_s: int = 180
    server_idle_timeout_s: int = 1800
    data_dir: Path = field(default_factory=_default_data_dir)
    protected_names: frozenset[str] = _PROTECTED_NAMES
    protected_services: frozenset[str] = _PROTECTED_SERVICES
    terminal_names: frozenset[str] = _TERMINAL_NAMES
    shell_parent_names: frozenset[str] = _SHELL_PARENT_NAMES
    suite_overrides: dict[str, str] = field(default_factory=lambda: dict(_SUITE_OVERRIDES))
    categories: dict[str, list[str]] = field(
        default_factory=lambda: {k: list(v) for k, v in _CATEGORIES.items()}
    )
    notes: dict[str, str] = field(default_factory=lambda: dict(_NOTES))


def load_config(path: Path | None = None) -> Config:
    """Load config; scalars override defaults, sets/lists/dicts extend them."""
    cfg = Config()
    if path is None:
        path = cfg.data_dir / "config.toml"
    path = Path(path)
    if not path.is_file():
        return cfg
    with path.open("rb") as f:
        data = tomllib.load(f)
    known = {f.name for f in fields(Config)}
    for key, val in data.items():
        if key not in known:
            continue
        cur = getattr(cfg, key)
        if isinstance(cur, frozenset):
            setattr(cfg, key, cur | frozenset(str(v).lower() for v in val))
        elif key == "categories":
            for k, v in val.items():
                cur[k] = list(dict.fromkeys([*cur.get(k, []), *v]))
        elif isinstance(cur, dict):
            cur.update(val)
        elif isinstance(cur, Path):
            setattr(cfg, key, Path(val))
        else:
            setattr(cfg, key, val)
    return cfg
