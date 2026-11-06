# memwatch — Memory Usage Monitor & Cleanup Advisor (Design)

Date: 2026-11-05
Platform: Windows 11 Home laptop, 16 GB RAM, Python 3.11.9

## Why

The laptop regularly runs out of memory. Triggers the owner named:

- Kaggle model training on the laptop
- Claude Code sessions that monitor cloud jobs (they pile up and stay open)
- many browser tabs and apps open at once

The owner believes 16 GB should comfortably run a browser plus their apps, and that a lot of
memory goes to unneeded background processes, **including many small ones that add up**.

A read-only snapshot taken on 2026-11-05 (6 days uptime) confirmed it:

- Commit charge was ~51 GB against 16 GB RAM, 0.6 GB free, and Memory Compression held 2.5 GB.
  The machine was paging and compressing heavily.
- Big items: an Android emulator (`qemu-system-x86_64`, ~4 GB, running 3 days, forgotten),
  two stale Claude Code CLI sessions from Oct 30 and Nov 1 (~1.5 GB), three browsers at once
  (Chrome ~4.5 GB committed with tabs from Oct 30, Firefox ~1.6 GB, Edge WebView2), and Zoom
  plus `aomhost64` (~1.9 GB).
- Small items: 726 processes, 706 of them under 100 MB working set, ~3.6 GB in total.
  Many came from auto-start apps: two security suites (Defender plus Reason Security/RAV with
  VPN and DNS services), Steam, Discord, Citrix, Teams, Adobe sync, Samsung connectivity, Tobii,
  Lenovo Vantage, NVIDIA, DisplayLink, OneDrive, Google Drive, Ollama, and Chrome and Edge
  auto-launch.
- Kernel nonpaged pool was ~1.5 GB, which is high and suggests a driver leak.

Already done by hand during design: the Xbox services (`XboxService`, `XblAuthManager`) were
disabled. Gaming Services was stopped but cannot be disabled as a service: it is a packaged
service and returns "Access denied" even for admin. Only uninstalling the
`Microsoft.GamingServices` app package removes it permanently.

## What it is

Two parts:

1. **Logger**: a lightweight background process that starts at logon, samples every ~60 s, and
   records per-app memory and whether the owner actually used each app. It builds a usage
   pattern over several days.
2. **Report**: opened on demand (desktop shortcut or `memwatch report`) when memory feels tight.
   It is a local browser page listing ranked suggestions of what to stop, each with a plain
   reason, and buttons that **actually perform the action**.

## Goals

- Find big memory hogs **and** the long tail of small, never-used processes that add up.
- Base suggestions on observed usage over days, not a single snapshot.
- Give every suggestion a human-readable reason, for example:
  - "Not used in 5 days, holding 600 MB"
  - "Big and idle: 4.0 GB, no activity for 3 days"
  - "Starts with Windows but you opened it twice in 2 weeks"
  - "Duplicate: two antivirus products running"
- Make acting easy: one click to **stop now**, and one click to **stop it starting with Windows**.
- Let the owner validate the tool's judgment before any nudges are added.

## Non-goals (for this version)

- Nudges, notifications, or alerts. These come later, after the owner trusts the report.
- Automatic killing of anything. Every action requires a click.
- GPU/VRAM tracking, and monitoring of the cloud VMs themselves.
- Fixing the kernel/driver leak. The report surfaces it but cannot act on it.

## Anti-goals (failure even if it "works")

- **The logger becomes a memory hog itself.** Target: under ~50 MB working set and negligible CPU.
- **Killing or suggesting Windows core processes.** These must never appear as suggestions or
  carry action buttons.
- **Acting without an explicit click.**
- **Silently losing unsaved work.** Stopping a windowed app should try a graceful close first.
  The suggestion should warn when an app has open windows, since unsaved work may be lost.
- **Any website being able to trigger kills through the local helper** (see Security).

## Decisions made with the owner

- Watch over several days and build a usage pattern.
- Every suggestion carries a reason: unused for N days, consuming a lot, or both.
- Claude Code sessions and Kaggle/Python jobs **are** tracked and **can** be suggested for
  stopping.
- Windows core processes are never suggested.
- Output is a report opened on demand, not nudges, for now.
- Report buttons really perform the actions. A small local helper runs only while the report is
  open.

## Decisions made by Claude (owner can override)

- **Language/runtime:** Python 3.11 with `psutil` and `pywin32` (or `ctypes`) for the
  foreground window and the registry. The owner already uses Python for Kaggle. The owner confirmed Python
  after weighing Rust: Rust would save roughly 20–30 MB on the logger, but adds toolchain setup
  and slower iteration during validation.
- **Rust fallback for the logger (owner's decision).** If the Python logger cannot stay under the
  ~50 MB cap in real use, rewrite **only the logger** in Rust. Keep the logger and the report
  decoupled through the SQLite database (the logger writes and the report reads; no shared
  in-process code), so this swap stays clean. Measure the logger's working set as part of
  validation.
- **Storage:** a SQLite file under `%LOCALAPPDATA%\memwatch\`. Keep 30 days of samples, then
  prune automatically.
- **Logger startup:** a per-user Task Scheduler task at logon running `pythonw`, so no console
  window appears. No admin is needed for the logger.
- **Sampling interval:** 60 s, configurable.
- **Data stays local.** No network calls except the report's localhost page.
- **Vendor suites are one row.** Group processes, services, tray apps and startup entries by
  publisher/install folder, so "Reason Security/RAV" or "Citrix" is a single row. "Stop all" and
  "Disable all at startup" act on the whole suite, with one UAC prompt per batch. The row can be
  expanded to show and act on individual parts. This matches the owner's "small things add up"
  framing and makes the duplicate-antivirus reason possible.
- **Graceful close is two-step.** "Stop now" sends WM_CLOSE. If the app is still running after
  the timeout, memwatch does **not** force-kill. It reports "still open; it may be waiting for
  you (unsaved work?)" and offers a separate **Force kill** button. Windowless processes are
  terminated directly.
- **Disabling startup uses Windows' own switches where they exist:**
  - Run keys and Startup-folder entries: the `StartupApproved` keys, as Task Manager does. Apps
    like Discord and Steam rewrite deleted Run entries, and this keeps Settings and Task Manager
    in agreement.
  - Packaged-app startup tasks: their StartupApproved/startup-task state.
  - Logon scheduled tasks: disable the task.
  - Services: a choice of Manual or Disabled.
  - Anything memwatch cannot switch off is shown read-only, with the reason.
- **The logger runs without admin (v1).** Accept that some elevated/SYSTEM processes hide
  command lines and I/O counters. The report marks such rows "limited data" rather than guessing.
  An elevated logger can be revisited after validation.

## How it behaves

### Grouping into "apps"

Raw processes are grouped into apps the owner recognises, so Chrome's 25 processes count as one
"Chrome". Grouping uses the executable plus the parent/child tree.

Exceptions where each instance is its own row, because they are independent units of work the
owner may want to stop individually:

- **Each Claude Code CLI session** (`claude.exe` under `.local\bin`). Label it with its start
  time and, if obtainable, its working directory.
- **Each Python process.** Label it with its script or command line, so a Kaggle training run is
  identifiable.
- **The Android emulator / qemu.** Label it with the AVD name.

Windows services are shown under their display name. `svchost` instances are mapped to the
service(s) they host where possible.

### What counts as "used"

An app counts as used in a sample if either:

- one of its windows is the foreground window, or
- it is doing meaningful work (CPU time or I/O delta above a small threshold).

Caveats the builder must handle:

- **CLI tools inside terminals.** A Claude Code session lives in a terminal (Windows Terminal,
  mintty). The foreground window belongs to the terminal, not to `claude.exe`. Attribute
  foreground use of a terminal to the process tree running inside the focused terminal tab/window
  where feasible; otherwise fall back to the activity signal.
- **Monitoring sessions that poll forever.** A Claude session watching cloud jobs may show
  steady low CPU or network activity without the owner touching it. "Last foreground/interaction
  time" must therefore be tracked separately from "last activity". A suggestion can say "running
  and polling, but you haven't looked at it in 2 days".

**Windowless components (owner's decision).** Services, tray agents and helpers with no window
of their own do not get "used" credit from their own background activity. Instead:

- A component **counts as used when the owner uses the app it belongs to**. For example, the
  Samsung connectivity service counts as used when the Samsung/Phone app is in the foreground.
  The link comes from the suite grouping (publisher/install folder) and the parent/child tree.
- A component with **no owning app** (a standalone service) is judged on size, not usage.
  Its suggestion includes a short plain-English description of what it does, taken from the
  service description plus a small hand-maintained notes file, so the owner can decide whether
  they need it.

Thresholds are left to the builder. They must be in config so they can be tuned during
validation.

### Startup inventory

The logger (or report) records each app's auto-start sources:

- HKCU/HKLM `Run` keys
- the Startup folders
- services with an Automatic start type
- scheduled tasks at logon, where cheap to detect

This lets the report say "starts with Windows" and offer a disable action.

### Suggestions and ranking

Rank by estimated memory reclaimable. Use **private bytes / commit** as the primary measure,
because that is what drove the 51 GB commit. Show working set alongside. Each suggestion shows:

- app name
- memory now and typical memory
- last used
- the reason sentence(s)
- the available actions

Reasons the tool should generate:

- **Idle for a long time:** not used in N days.
- **Large:** above a size threshold.
- **Large and idle:** the strongest case.
- **Auto-start but rarely used:** opened rarely in the observation window.
- **Long-running:** for example, a Claude session open for 5 days.
- **Duplicate category:** two antivirus products, or several browsers running. Lower priority.
  The builder can choose a simple hand-maintained category list.

Before several days of history exist, the report must still be useful. Show current memory use
and mark the suggestions as "based on X hours of data".

### Protection list

Never suggest and never act on:

- Windows core processes: System, Registry, smss, csrss, wininit, winlogon, services, lsass,
  svchost hosting core services, dwm, explorer, fontdrvhost, Memory Compression, Secure System,
  and similar.
- Defender (MsMpEng, WinDefend, MDCoreSvc).
- memwatch itself.
- The process tree that launched the report.

Third-party services (for example Reason Security, Citrix, Samsung, Tobii, Lenovo Vantage) **are**
eligible.

**Optional Microsoft services are eligible too (owner chose the bolder option).** Examples:
Windows Search, SysMain, DiagTrack/telemetry, Phone Link, Widgets, WSL, Edge update, OneDrive.
The rule is:

- Protect only an explicit core denylist.
- Suggest all other Microsoft components, with a **caution label** saying what may stop working
  (for example "Windows Search: Start-menu and File Explorer search get slower").
- Never offer Disabled for a service that other running services depend on. Offer Manual only
  and explain why.

The protection list and the caution notes live in config so they can be extended.

### Report page

Sections, top to bottom:

1. **Pressure now:** RAM used/free, commit used/limit, Memory Compression size, and the total
   reclaimable if all suggestions were taken.
2. **Suggestions:** the ranked list with action buttons.
3. **All apps:** a per-app table with memory over time (simple sparkline or chart), last used,
   and startup status. This is for validating the tool's judgment.
4. **Not fixable here:** kernel paged/nonpaged pool size with a note when it is abnormally high
   (for example, nonpaged above ~500 MB: "possible driver leak; a reboot clears it"), plus
   uptime.
5. **Undo:** a list of startup changes memwatch made, each with a re-enable button.

### Actions

- **Stop now.** For windowed apps, try a graceful close first (WM_CLOSE), then terminate the
  process tree after a short timeout. Background processes are terminated directly. For
  services, stop the service.
- **Stop it starting with Windows.**
  - Run-key entries: back up, then remove.
  - Startup-folder shortcuts: move them to a memwatch backup folder.
  - Services: set the start type to Manual or Disabled.
  - Each change is recorded so Undo can restore it.
- **Elevation.** HKLM keys and services need admin. Trigger a UAC prompt per action, the same
  way this design session did. Report clearly when an action fails: packaged services such as
  Gaming Services return Access Denied. In that case show the explanation instead of pretending
  it worked.
- After an action, re-read the state and show the actual outcome.

### Security of the local helper

The helper binds to `127.0.0.1` only, and requires a random per-launch token embedded in the
page URL on every action request. This stops other web pages in the browser from triggering
kills via localhost. It exits when the report page is closed or after an idle timeout.

## Left to the builder

- Package/CLI structure, the web framework for the helper (stdlib `http.server` is fine), and
  the charting approach.
- Exact thresholds and defaults, kept in config.
- Database schema and how samples are aggregated for 30-day retention.
- How to test kill and startup actions safely, for example with dummy processes and a dummy Run
  key.
