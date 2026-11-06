from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProcInfo:
    pid: int
    ppid: int
    name: str
    exe: str | None
    cmdline: list[str] | None
    create_time: float
    private_bytes: int
    working_set: int
    cpu_s: float | None
    io_bytes: int | None
    cwd: str | None
    limited: bool


@dataclass(frozen=True)
class ServiceInfo:
    name: str
    display_name: str
    description: str
    start_type: str  # 'automatic' | 'manual' | 'disabled'
    pid: int | None
    binpath: str


@dataclass(frozen=True)
class SystemSnapshot:
    ts: int
    ram_total: int
    ram_avail: int
    commit_used: int
    commit_limit: int
    compression_ws: int | None
    pool_paged: int
    pool_nonpaged: int
    boot_time: int
    logger_ws: int | None


@dataclass
class AppGroup:
    app_key: str
    label: str
    kind: str  # 'suite' | 'instance' | 'windows' | 'protected'
    pids: list[tuple[int, float]]
    private_bytes: int
    working_set: int
    services: list[str]
    limited: bool
    microsoft: bool  # optional Microsoft component (caution label)


@dataclass(frozen=True)
class UsageFlags:
    foreground: bool
    active: bool
    has_windows: bool


@dataclass(frozen=True)
class SampleRow:
    ts: int
    private_bytes: int
    working_set: int
    foreground: bool
    active: bool


@dataclass(frozen=True)
class AppRecord:
    app_key: str
    label: str
    kind: str
    microsoft: bool
    first_seen: int
    last_seen: int
    last_used: int | None
    last_active: int | None
    has_windows_ever: bool
    limited: bool
    services: list[str]


@dataclass(frozen=True)
class StartupEntry:
    source: str  # 'run' | 'startup_folder' | 'packaged' | 'task' | 'service'
    name: str
    location: str
    command: str
    enabled: bool
    needs_admin: bool
    can_disable: bool
    note: str | None
    app_key: str | None


@dataclass(frozen=True)
class ActionRecord:
    id: int | None
    ts: int
    app_key: str
    action: str
    entry: dict
    before: dict
    undone: bool


@dataclass(frozen=True)
class ActionResult:
    status: str  # 'done'|'still_open'|'already_stopped'|'declined'|'failed'|'partial'
    message: str
    remaining_pids: list[int] = field(default_factory=list)


@dataclass
class Suggestion:
    app_key: str
    label: str
    kind: str
    private_bytes: int
    working_set: int
    typical_private: int
    last_used: int | None
    idle_observed_s: int
    reasons: list[str]
    reason_codes: list[str]
    has_windows: bool
    caution: str | None
    limited: bool
    startup: list[StartupEntry]
    service_modes: list[str]
    services: list[str] = field(default_factory=list)  # read-only parts list
    n_procs: int = 0


@dataclass
class AppSummary:
    app_key: str
    label: str
    private_bytes: int
    last_used: int | None
    autostart: bool
    spark: list[int]


@dataclass
class Report:
    now: int
    system: SystemSnapshot | None
    observed_hours: float
    partial_note: str | None
    reclaimable: int
    suggestions: list[Suggestion]
    apps: list[AppSummary]
    kernel_note: str | None
    uptime_s: int
    logger_ws: int | None
    logger_over_cap: bool
    undo: list[ActionRecord]
    data_ts: int | None = None  # ts of the latest logged tick
    stale: bool = False  # the logger has not written for > 3 sample intervals
