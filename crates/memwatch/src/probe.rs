//! Live probes: processes, system memory, windows, input idle and services.
//!
//! Processes come from one `NtQuerySystemInformation(SystemProcessInformation)` call,
//! which reports memory, CPU and I/O for every process (even SYSTEM and elevated ones)
//! without opening a handle. Only the slow-changing exe / command line / cwd need a handle,
//! and those are cached per (pid, create_time).

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{LazyLock, Mutex};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, ERROR_MORE_DATA, HANDLE, HWND, LPARAM, BOOL};
use windows::Win32::Graphics::Dwm::DwmGetWindowAttribute;
use windows::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::ProcessStatus::{
    GetPerformanceInfo, GetProcessMemoryInfo, PERFORMANCE_INFORMATION, PROCESS_MEMORY_COUNTERS,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, QueryServiceConfig2W,
    QueryServiceConfigW, ENUM_SERVICE_STATUS_PROCESSW, QUERY_SERVICE_CONFIGW, SC_ENUM_PROCESS_INFO,
    SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_DESCRIPTIONW, SERVICE_QUERY_CONFIG, SERVICE_STATE_ALL, SERVICE_WIN32,
};
use windows::Win32::System::SystemInformation::{GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows::Win32::UI::Shell::CommandLineToArgvW;
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetForegroundWindow, GetWindowTextLengthW, GetWindowThreadProcessId, IsWindowVisible,
};

use crate::models::{ProcInfo, ServiceInfo, SystemSnapshot};
use crate::usage::{pkey, ProcKey};

#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(class: u32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
    fn NtQueryInformationProcess(h: HANDLE, class: u32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
}

const SYSTEM_PROCESS_INFORMATION: u32 = 5;
const PROCESS_BASIC_INFORMATION: u32 = 0;
const PROCESS_WOW64_INFORMATION: u32 = 26;
const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
const STATUS_BUFFER_OVERFLOW_LIKE: [i32; 2] = [STATUS_INFO_LENGTH_MISMATCH, 0xC000_0023_u32 as i32];

// ---- raw process table -----------------------------------------------------

/// One entry of the system process table (`SYSTEM_PROCESS_INFORMATION`, x64 layout).
#[derive(Debug, Clone, PartialEq)]
pub struct RawProc {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub create_time: f64,
    pub private_bytes: i64,
    pub working_set: i64,
    pub cpu_s: f64,
    pub io_bytes: i64,
    pub threads: u32,
}

const OFF_NEXT: usize = 0;
const OFF_THREADS: usize = 4;
const OFF_CREATE: usize = 32;
const OFF_USER: usize = 40;
const OFF_KERNEL: usize = 48;
const OFF_NAME_LEN: usize = 56;
const OFF_NAME_PTR: usize = 64;
const OFF_PID: usize = 80;
const OFF_PPID: usize = 88;
const OFF_WSET: usize = 144;
const OFF_PRIVATE: usize = 200;
const OFF_READ_XFER: usize = 232;
const OFF_WRITE_XFER: usize = 240;
const SPI_MIN_SIZE: usize = 256;
const FILETIME_EPOCH: f64 = 11_644_473_600.0;

fn rd_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn rd_u64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn rd_u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}

fn utf16le(bytes: &[u8]) -> String {
    let wide: Vec<u16> = bytes.iter().step_by(2).zip(bytes.iter().skip(1).step_by(2))
        .map(|(a, b)| u16::from_le_bytes([*a, *b])).collect();
    String::from_utf16_lossy(&wide)
}

fn ft_to_unix(ft: u64) -> f64 {
    if ft == 0 {
        0.0
    } else {
        ft as f64 / 1e7 - FILETIME_EPOCH
    }
}

/// Walk the `SystemProcessInformation` records. Image-name pointers are absolute
/// addresses inside `buf`, so they are resolved against `buf`'s own base address.
pub fn parse_process_buffer(buf: &[u8]) -> Vec<RawProc> {
    let base = buf.as_ptr() as usize;
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + SPI_MIN_SIZE <= buf.len() {
        let rec = &buf[off..];
        let pid = rd_u64(rec, OFF_PID) as u32;
        let ppid = rd_u64(rec, OFF_PPID) as u32;
        let name_len = rd_u16(rec, OFF_NAME_LEN) as usize;
        let name_ptr = rd_u64(rec, OFF_NAME_PTR) as usize;
        let mut name = String::new();
        if name_len > 0 && name_ptr >= base && name_ptr - base + name_len <= buf.len() {
            let bytes = &buf[name_ptr - base..name_ptr - base + name_len];
            name = utf16le(bytes);
        }
        if name.is_empty() {
            name = match pid {
                0 => "System Idle Process".to_string(),
                4 => "System".to_string(),
                _ => String::new(),
            };
        }
        let cpu_100ns = rd_u64(rec, OFF_USER) + rd_u64(rec, OFF_KERNEL);
        out.push(RawProc {
            pid,
            ppid,
            name,
            create_time: ft_to_unix(rd_u64(rec, OFF_CREATE)),
            private_bytes: rd_u64(rec, OFF_PRIVATE) as i64,
            working_set: rd_u64(rec, OFF_WSET) as i64,
            cpu_s: cpu_100ns as f64 / 1e7,
            io_bytes: (rd_u64(rec, OFF_READ_XFER) + rd_u64(rec, OFF_WRITE_XFER)) as i64,
            threads: rd_u32(rec, OFF_THREADS),
        });
        let next = rd_u32(rec, OFF_NEXT) as usize;
        if next == 0 {
            break;
        }
        off += next;
    }
    out
}

fn query_raw() -> Vec<RawProc> {
    let mut size = 1usize << 20;
    loop {
        let mut buf = vec![0u8; size];
        let mut ret = 0u32;
        let st = unsafe {
            NtQuerySystemInformation(SYSTEM_PROCESS_INFORMATION, buf.as_mut_ptr().cast(), size as u32, &mut ret)
        };
        if st == STATUS_INFO_LENGTH_MISMATCH {
            size = (ret as usize).max(size) + (256 << 10);
            continue;
        }
        if st < 0 {
            log::warn!("NtQuerySystemInformation failed: {st:#x}");
            return Vec::new();
        }
        buf.truncate(ret as usize);
        return parse_process_buffer(&buf);
    }
}

// ---- per-process static fields ----------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct StaticFields {
    pub exe: Option<String>,
    pub cmdline: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub limited: bool,
}

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn open(pid: u32, access: windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS) -> Option<OwnedHandle> {
    unsafe { OpenProcess(access, false, pid).ok().map(OwnedHandle) }
}

fn exe_of(h: &OwnedHandle) -> Option<String> {
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len).ok()?;
    }
    Some(String::from_utf16_lossy(&buf[..len as usize]))
}

fn split_args(line: &str) -> Vec<String> {
    let wide: Vec<u16> = line.encode_utf16().chain(std::iter::once(0)).collect();
    let mut argc = 0i32;
    unsafe {
        let argv = CommandLineToArgvW(PCWSTR(wide.as_ptr()), &mut argc);
        if argv.is_null() {
            return vec![line.to_string()];
        }
        let out = (0..argc as usize)
            .map(|i| (*argv.add(i)).to_string().unwrap_or_default())
            .collect();
        let _ = windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(argv.cast()));
        out
    }
}

fn cmdline_of(h: &OwnedHandle) -> Option<Vec<String>> {
    let mut size = 4096usize;
    for _ in 0..4 {
        let mut buf = vec![0u8; size];
        let mut ret = 0u32;
        let st = unsafe {
            NtQueryInformationProcess(h.0, PROCESS_COMMAND_LINE_INFORMATION, buf.as_mut_ptr().cast(), size as u32, &mut ret)
        };
        if STATUS_BUFFER_OVERFLOW_LIKE.contains(&st) {
            size = (ret as usize).max(size * 2);
            continue;
        }
        if st < 0 {
            return None;
        }
        let len = rd_u16(&buf, 0) as usize;
        let ptr = rd_u64(&buf, 8) as usize;
        let base = buf.as_ptr() as usize;
        if ptr < base || ptr - base + len > buf.len() {
            return None;
        }
        return Some(split_args(&utf16le(&buf[ptr - base..ptr - base + len])));
    }
    None
}

fn read_mem(h: HANDLE, addr: usize, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut got = 0usize;
    unsafe {
        ReadProcessMemory(h, addr as *const c_void, buf.as_mut_ptr().cast(), len, Some(&mut got)).ok()?;
    }
    (got == len).then_some(buf)
}

/// Current directory via the target's PEB (64-bit targets only; WOW64 returns None).
fn cwd_of(pid: u32) -> Option<String> {
    let h = open(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)?;
    let mut wow: usize = 0;
    let mut ret = 0u32;
    let st = unsafe {
        NtQueryInformationProcess(h.0, PROCESS_WOW64_INFORMATION, (&mut wow as *mut usize).cast(), 8, &mut ret)
    };
    if st < 0 || wow != 0 {
        return None;
    }
    let mut pbi = [0u8; 48];
    let st = unsafe {
        NtQueryInformationProcess(h.0, PROCESS_BASIC_INFORMATION, pbi.as_mut_ptr().cast(), 48, &mut ret)
    };
    if st < 0 {
        return None;
    }
    let peb = rd_u64(&pbi, 8) as usize;
    if peb == 0 {
        return None;
    }
    let params = rd_u64(&read_mem(h.0, peb + 0x20, 8)?, 0) as usize;
    let us = read_mem(h.0, params + 0x38, 16)?;
    let (len, ptr) = (rd_u16(&us, 0) as usize, rd_u64(&us, 8) as usize);
    if len == 0 || ptr == 0 || len > 65_536 {
        return None;
    }
    let raw = read_mem(h.0, ptr, len)?;
    let mut s = utf16le(&raw);
    if s.len() > 3 && s.ends_with('\\') {
        s.pop();
    }
    Some(s)
}

const SYSTEM_PROCESS_ID_INFORMATION: u32 = 88;

/// (NT device path, drive letter) pairs, e.g. (`\Device\HarddiskVolume3`, `C:`).
fn dos_devices() -> Vec<(String, String)> {
    use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
    let mut out = Vec::new();
    for letter in 'A'..='Z' {
        let drive = format!("{letter}:");
        let w: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
        let mut buf = [0u16; 1024];
        let n = unsafe { QueryDosDeviceW(PCWSTR(w.as_ptr()), Some(&mut buf)) } as usize;
        if n > 0 {
            let end = buf.iter().position(|&c| c == 0).unwrap_or(n);
            out.push((String::from_utf16_lossy(&buf[..end]), drive));
        }
    }
    out
}

static DOS_DEVICES: LazyLock<Mutex<Vec<(String, String)>>> = LazyLock::new(|| Mutex::new(dos_devices()));

fn nt_to_dos(nt: &str, devices: &[(String, String)]) -> Option<String> {
    devices.iter().find_map(|(dev, drive)| {
        let rest = nt.strip_prefix(dev.as_str())?;
        (rest.starts_with('\\') || rest.is_empty()).then(|| format!("{drive}{rest}"))
    })
}

/// Image path without opening the process (works for protected and elevated ones),
/// like psutil's fallback: `SystemProcessIdInformation` returns an NT path.
fn exe_via_system_info(pid: u32) -> Option<String> {
    let mut cap = 1024usize; // bytes for the name
    for _ in 0..3 {
        let mut name = vec![0u8; cap];
        let mut info = [0u8; 24]; // pid (8) + UNICODE_STRING { len u16, max u16, pad u32, buffer ptr }
        info[0..8].copy_from_slice(&(pid as u64).to_le_bytes());
        info[10..12].copy_from_slice(&(cap as u16).to_le_bytes());
        info[16..24].copy_from_slice(&(name.as_mut_ptr() as u64).to_le_bytes());
        let mut ret = 0u32;
        let st = unsafe {
            NtQuerySystemInformation(SYSTEM_PROCESS_ID_INFORMATION, info.as_mut_ptr().cast(), 24, &mut ret)
        };
        if st == STATUS_INFO_LENGTH_MISMATCH {
            let need = rd_u16(&info, 10) as usize;
            if need <= cap || need > 60_000 {
                return None;
            }
            cap = need;
            continue;
        }
        if st < 0 {
            return None;
        }
        let len = rd_u16(&info, 8) as usize;
        if len == 0 || len > cap {
            return None;
        }
        let nt = utf16le(&name[..len]);
        let mut devices = DOS_DEVICES.lock().unwrap();
        if let Some(p) = nt_to_dos(&nt, &devices) {
            return Some(p);
        }
        *devices = dos_devices(); // a volume may have been mounted since the first lookup
        return nt_to_dos(&nt, &devices);
    }
    None
}

fn read_static(r: &RawProc) -> StaticFields {
    let h = open(r.pid, PROCESS_QUERY_LIMITED_INFORMATION);
    let exe = h.as_ref().and_then(exe_of).or_else(|| exe_via_system_info(r.pid));
    let cmdline = h.as_ref().and_then(cmdline_of);
    let limited = exe.is_none() || cmdline.is_none();
    drop(h);
    let cwd = if cmdline.is_some() { cwd_of(r.pid) } else { None };
    StaticFields { exe, cmdline, cwd, limited }
}

// (pid, create_time) -> static fields; pruned on every snapshot.
static STATIC_CACHE: LazyLock<Mutex<HashMap<ProcKey, StaticFields>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Number of cached entries (for tests).
pub fn static_cache_len() -> usize {
    STATIC_CACHE.lock().unwrap().len()
}

pub fn static_cache_contains(pid: u32, create_time: f64) -> bool {
    STATIC_CACHE.lock().unwrap().contains_key(&pkey(pid, create_time))
}

/// A process that has exited but is still listed (zero threads). Reading its
/// exe/cmdline/cwd is slow and it holds no user memory, so callers skip it.
pub fn is_terminated(r: &RawProc) -> bool {
    r.threads == 0 && r.pid > 4
}

/// Turn the raw table into `ProcInfo`s using `fetch` for the (cached) static fields.
pub fn snapshot_from(raw: Vec<RawProc>, fetch: &dyn Fn(&RawProc) -> StaticFields) -> Vec<ProcInfo> {
    let mut out = Vec::with_capacity(raw.len());
    let mut seen: Vec<ProcKey> = Vec::with_capacity(raw.len());
    for r in raw {
        if is_terminated(&r) {
            continue;
        }
        let key = pkey(r.pid, r.create_time);
        let cached = STATIC_CACHE.lock().unwrap().get(&key).cloned();
        let sf = match cached {
            Some(sf) => sf,
            None => {
                let sf = if r.pid <= 4 {
                    StaticFields { limited: true, ..Default::default() }
                } else {
                    fetch(&r)
                };
                STATIC_CACHE.lock().unwrap().insert(key, sf.clone());
                sf
            }
        };
        seen.push(key);
        out.push(ProcInfo {
            pid: r.pid,
            ppid: r.ppid,
            name: r.name,
            exe: sf.exe,
            cmdline: sf.cmdline,
            create_time: r.create_time,
            private_bytes: r.private_bytes,
            working_set: r.working_set,
            cpu_s: Some(r.cpu_s),
            io_bytes: Some(r.io_bytes),
            cwd: sf.cwd,
            limited: sf.limited,
        });
    }
    let keep: std::collections::HashSet<ProcKey> = seen.into_iter().collect();
    STATIC_CACHE.lock().unwrap().retain(|k, _| keep.contains(k));
    out
}

pub fn snapshot_processes() -> Vec<ProcInfo> {
    snapshot_from(query_raw(), &read_static)
}

// ---- system ----------------------------------------------------------------

fn compression_from_procs(procs: &[ProcInfo]) -> Option<i64> {
    procs
        .iter()
        .find(|p| p.name == "Memory Compression")
        .and_then(|p| (p.working_set > 0).then_some(p.working_set))
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn system_snapshot(ts: i64, procs: &[ProcInfo]) -> windows::core::Result<SystemSnapshot> {
    let mut pi = PERFORMANCE_INFORMATION { cb: std::mem::size_of::<PERFORMANCE_INFORMATION>() as u32, ..Default::default() };
    unsafe { GetPerformanceInfo(&mut pi, pi.cb)? };
    let mut ms = MEMORYSTATUSEX { dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32, ..Default::default() };
    unsafe { GlobalMemoryStatusEx(&mut ms)? };
    let page = pi.PageSize as i64;
    let uptime_s = (unsafe { GetTickCount64() } / 1000) as i64;
    Ok(SystemSnapshot {
        ts,
        ram_total: ms.ullTotalPhys as i64,
        ram_avail: ms.ullAvailPhys as i64,
        commit_used: pi.CommitTotal as i64 * page,
        commit_limit: pi.CommitLimit as i64 * page,
        compression_ws: compression_from_procs(procs),
        pool_paged: pi.KernelPaged as i64 * page,
        pool_nonpaged: pi.KernelNonpaged as i64 * page,
        boot_time: now_unix() - uptime_s,
        logger_ws: None,
    })
}

/// This process's working set, in bytes.
pub fn own_working_set() -> Option<i64> {
    let mut c = PROCESS_MEMORY_COUNTERS { cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32, ..Default::default() };
    unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb).ok()? };
    Some(c.WorkingSetSize as i64)
}

// ---- windows / input -------------------------------------------------------

pub fn foreground_pid() -> Option<u32> {
    unsafe {
        let hwnd = GetForegroundWindow();
        if hwnd.0.is_null() {
            return None;
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        (pid != 0).then_some(pid)
    }
}

const DWMWA_CLOAKED: u32 = 14;

unsafe extern "system" fn enum_cb(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let pids = &mut *(lparam.0 as *mut std::collections::HashSet<u32>);
    if !IsWindowVisible(hwnd).as_bool() || GetWindowTextLengthW(hwnd) <= 0 {
        return BOOL(1);
    }
    let mut cloaked = 0u32;
    let hr = DwmGetWindowAttribute(
        hwnd,
        windows::Win32::Graphics::Dwm::DWMWINDOWATTRIBUTE(DWMWA_CLOAKED as i32),
        (&mut cloaked as *mut u32).cast(),
        4,
    );
    if hr.is_ok() && cloaked != 0 {
        return BOOL(1);
    }
    let mut pid = 0u32;
    GetWindowThreadProcessId(hwnd, Some(&mut pid));
    if pid != 0 {
        pids.insert(pid);
    }
    BOOL(1)
}

/// PIDs owning a visible, titled, non-cloaked top-level window.
pub fn window_pids() -> std::collections::HashSet<u32> {
    let mut pids = std::collections::HashSet::new();
    unsafe {
        let _ = EnumWindows(Some(enum_cb), LPARAM((&mut pids as *mut std::collections::HashSet<u32>) as isize));
    }
    pids
}

pub fn seconds_since_input() -> f64 {
    let mut lii = LASTINPUTINFO { cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32, dwTime: 0 };
    unsafe {
        if !GetLastInputInfo(&mut lii).as_bool() {
            return 0.0;
        }
        // dwTime is a 32-bit tick count: compare with the low 32 bits of the 64-bit clock.
        let now32 = (GetTickCount64() & 0xFFFF_FFFF) as u32;
        now32.wrapping_sub(lii.dwTime) as f64 / 1000.0
    }
}

// ---- version info -----------------------------------------------------------

/// A `len`-element slice of `T` at `p`, only if it lies entirely inside `data`
/// (the version-info block that `VerQueryValueW` points into).
fn slice_within<T>(data: &[u8], p: *mut c_void, len: usize) -> Option<&[T]> {
    let start = p as usize;
    let base = data.as_ptr() as usize;
    let bytes = len.checked_mul(std::mem::size_of::<T>())?;
    let end = start.checked_add(bytes)?;
    if start < base || end > base + data.len() || !start.is_multiple_of(std::mem::align_of::<T>()) {
        return None;
    }
    // SAFETY: [start, end) is inside `data`, which outlives the returned slice, and is aligned for T.
    Some(unsafe { std::slice::from_raw_parts(start as *const T, len) })
}

/// CompanyName from the exe's version info, or None when unreadable.
pub fn file_company(path: &str) -> Option<String> {
    let wpath: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let size = GetFileVersionInfoSizeW(PCWSTR(wpath.as_ptr()), None);
        if size == 0 {
            return None;
        }
        let mut data = vec![0u8; size as usize];
        GetFileVersionInfoW(PCWSTR(wpath.as_ptr()), 0, size, data.as_mut_ptr().cast()).ok()?;
        let mut p: *mut c_void = std::ptr::null_mut();
        let mut len = 0u32;
        let tr: Vec<u16> = "\\VarFileInfo\\Translation\0".encode_utf16().collect();
        if !VerQueryValueW(data.as_ptr().cast(), PCWSTR(tr.as_ptr()), &mut p, &mut len).as_bool() || len < 4 {
            return None;
        }
        // len is in bytes for the translation table; we read its first (lang, codepage) pair.
        let pair: &[u16] = slice_within(&data, p, 2)?;
        let sub = format!("\\StringFileInfo\\{:04x}{:04x}\\CompanyName\0", pair[0], pair[1]);
        let wsub: Vec<u16> = sub.encode_utf16().collect();
        if !VerQueryValueW(data.as_ptr().cast(), PCWSTR(wsub.as_ptr()), &mut p, &mut len).as_bool() || len == 0 {
            return None;
        }
        // len is in characters for string values.
        let chars: &[u16] = slice_within(&data, p, len as usize)?;
        let end = chars.iter().position(|&c| c == 0).unwrap_or(chars.len());
        let s = String::from_utf16_lossy(&chars[..end]);
        (!s.is_empty()).then_some(s)
    }
}

// ---- services --------------------------------------------------------------

struct ScHandle(SC_HANDLE);
impl Drop for ScHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

fn wstr(p: PWSTR) -> String {
    if p.is_null() {
        String::new()
    } else {
        unsafe { p.to_string().unwrap_or_default() }
    }
}

fn start_type_name(code: u32) -> &'static str {
    match code {
        0..=2 => "automatic", // boot, system, auto
        4 => "disabled",
        _ => "manual",
    }
}

fn service_details(scm: &ScHandle, name: &PWSTR) -> (String, String, String) {
    unsafe {
        let Ok(h) = OpenServiceW(scm.0, PCWSTR(name.0), SERVICE_QUERY_CONFIG) else {
            return ("manual".into(), String::new(), String::new());
        };
        let h = ScHandle(h);
        let mut buf = vec![0u8; 8192];
        let mut needed = 0u32;
        let mut cfg = QueryServiceConfigW(h.0, Some(buf.as_mut_ptr().cast()), buf.len() as u32, &mut needed);
        if cfg.is_err() && needed as usize > buf.len() {
            buf = vec![0u8; needed as usize];
            cfg = QueryServiceConfigW(h.0, Some(buf.as_mut_ptr().cast()), buf.len() as u32, &mut needed);
        }
        let (start, bin) = if cfg.is_ok() {
            let q = &*(buf.as_ptr() as *const QUERY_SERVICE_CONFIGW);
            (start_type_name(q.dwStartType.0).to_string(), wstr(q.lpBinaryPathName))
        } else {
            ("manual".to_string(), String::new())
        };
        let mut dbuf = vec![0u8; 8192];
        let mut dneeded = 0u32;
        let mut d = QueryServiceConfig2W(h.0, SERVICE_CONFIG_DESCRIPTION, Some(&mut dbuf), &mut dneeded);
        if d.is_err() && dneeded as usize > dbuf.len() {
            dbuf = vec![0u8; dneeded as usize];
            d = QueryServiceConfig2W(h.0, SERVICE_CONFIG_DESCRIPTION, Some(&mut dbuf), &mut dneeded);
        }
        let desc = if d.is_ok() {
            wstr((*(dbuf.as_ptr() as *const SERVICE_DESCRIPTIONW)).lpDescription)
        } else {
            String::new()
        };
        (start, bin, desc)
    }
}

/// All Win32 services (not drivers) with config; empty (and logged) when the SCM fails.
pub fn all_services() -> Vec<ServiceInfo> {
    unsafe {
        let scm = match OpenSCManagerW(None, None, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE) {
            Ok(h) => ScHandle(h),
            Err(e) => {
                log::warn!("service enumeration failed: {e}");
                return Vec::new();
            }
        };
        let mut buf = vec![0u8; 256 << 10];
        let mut resume = 0u32;
        let mut out = Vec::new();
        loop {
            let (mut needed, mut count) = (0u32, 0u32);
            let r = EnumServicesStatusExW(
                scm.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                Some(&mut buf),
                &mut needed,
                &mut count,
                Some(&mut resume),
                None,
            );
            let more = matches!(&r, Err(e) if e.code() == ERROR_MORE_DATA.to_hresult());
            if r.is_err() && !more {
                log::warn!("service enumeration failed: {:?}", r.err());
                return out;
            }
            let entries = std::slice::from_raw_parts(buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW, count as usize);
            for e in entries {
                let (start, binpath, description) = service_details(&scm, &e.lpServiceName);
                let pid = e.ServiceStatusProcess.dwProcessId;
                out.push(ServiceInfo {
                    name: wstr(e.lpServiceName),
                    display_name: wstr(e.lpDisplayName),
                    description,
                    start_type: start,
                    pid: (pid != 0).then_some(pid),
                    binpath,
                });
            }
            if !more {
                break;
            }
        }
        out
    }
}

pub fn services_by_pid() -> HashMap<u32, Vec<ServiceInfo>> {
    let mut by_pid: HashMap<u32, Vec<ServiceInfo>> = HashMap::new();
    for s in all_services() {
        if let Some(pid) = s.pid {
            by_pid.entry(pid).or_default().push(s);
        }
    }
    by_pid
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a two-record SYSTEM_PROCESS_INFORMATION buffer with the given names.
    fn synth(recs: &[(u32, u32, &str, u32)]) -> Vec<u8> {
        let rec_size = 256 + 64; // header + room for the name
        let mut buf = vec![0u8; rec_size * recs.len()];
        let base = buf.as_ptr() as usize;
        for (i, (pid, ppid, name, threads)) in recs.iter().enumerate() {
            let o = i * rec_size;
            let next = if i + 1 < recs.len() { rec_size as u32 } else { 0 };
            buf[o..o + 4].copy_from_slice(&next.to_le_bytes());
            buf[o + OFF_THREADS..o + OFF_THREADS + 4].copy_from_slice(&threads.to_le_bytes());
            let ft: u64 = ((1_700_000_000.0 + FILETIME_EPOCH) * 1e7) as u64;
            buf[o + OFF_CREATE..o + OFF_CREATE + 8].copy_from_slice(&ft.to_le_bytes());
            buf[o + OFF_USER..o + OFF_USER + 8].copy_from_slice(&15_000_000u64.to_le_bytes());
            buf[o + OFF_KERNEL..o + OFF_KERNEL + 8].copy_from_slice(&5_000_000u64.to_le_bytes());
            let wide: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
            let name_off = o + 256;
            buf[name_off..name_off + wide.len()].copy_from_slice(&wide);
            buf[o + OFF_NAME_LEN..o + OFF_NAME_LEN + 2].copy_from_slice(&(wide.len() as u16).to_le_bytes());
            buf[o + OFF_NAME_PTR..o + OFF_NAME_PTR + 8].copy_from_slice(&((base + name_off) as u64).to_le_bytes());
            buf[o + OFF_PID..o + OFF_PID + 8].copy_from_slice(&(*pid as u64).to_le_bytes());
            buf[o + OFF_PPID..o + OFF_PPID + 8].copy_from_slice(&(*ppid as u64).to_le_bytes());
            buf[o + OFF_WSET..o + OFF_WSET + 8].copy_from_slice(&200u64.to_le_bytes());
            buf[o + OFF_PRIVATE..o + OFF_PRIVATE + 8].copy_from_slice(&100u64.to_le_bytes());
            buf[o + OFF_READ_XFER..o + OFF_READ_XFER + 8].copy_from_slice(&3u64.to_le_bytes());
            buf[o + OFF_WRITE_XFER..o + OFF_WRITE_XFER + 8].copy_from_slice(&4u64.to_le_bytes());
        }
        buf
    }

    #[test]
    fn parses_process_records() {
        let buf = synth(&[(10, 1, "alpha.exe", 3), (0, 0, "", 2)]);
        let procs = parse_process_buffer(&buf);
        assert_eq!(procs.len(), 2);
        assert_eq!((procs[0].pid, procs[0].ppid, procs[0].name.as_str()), (10, 1, "alpha.exe"));
        assert_eq!((procs[0].private_bytes, procs[0].working_set, procs[0].io_bytes), (100, 200, 7));
        assert_eq!(procs[0].cpu_s, 2.0);
        assert!((procs[0].create_time - 1_700_000_000.0).abs() < 1.0);
        assert_eq!(procs[1].name, "System Idle Process");
    }

    fn raw(pid: u32, threads: u32) -> RawProc {
        RawProc {
            pid, ppid: 1, name: format!("p{pid}"), create_time: 777_000.0 + pid as f64,
            private_bytes: 100, working_set: 200, cpu_s: 2.0, io_bytes: 7, threads,
        }
    }

    fn fetch_ok(_: &RawProc) -> StaticFields {
        StaticFields { exe: Some(r"C:\x\p.exe".into()), cmdline: Some(vec!["p.exe".into(), "-a".into()]), cwd: Some(r"C:\x".into()), limited: false }
    }

    #[test]
    fn snapshot_skips_terminated_without_slow_reads_and_prunes_cache() {
        let fetch_boom = |r: &RawProc| -> StaticFields {
            assert_ne!(r.pid, 8811, "static read on a terminated process");
            fetch_ok(r)
        };
        let procs = snapshot_from(vec![raw(8810, 1), raw(8811, 0), raw(8812, 1)], &fetch_boom);
        assert_eq!(procs.iter().map(|p| p.pid).collect::<Vec<_>>(), [8810, 8812]);
        assert!(!static_cache_contains(8811, 777_000.0 + 8811.0));
        assert!(static_cache_contains(8810, 777_000.0 + 8810.0));
        // next snapshot without 8810 prunes it
        snapshot_from(vec![raw(8812, 1)], &fetch_ok);
        assert!(!static_cache_contains(8810, 777_000.0 + 8810.0));
        assert!(static_cache_contains(8812, 777_000.0 + 8812.0));
    }

    #[test]
    fn real_snapshot_contains_self() {
        let me = std::process::id();
        let procs = snapshot_processes();
        let p = procs.iter().find(|p| p.pid == me).expect("self in snapshot");
        assert!(p.private_bytes > 0 && p.create_time > 0.0 && !p.limited);
        assert!(p.exe.as_deref().is_some_and(|e| e.to_lowercase().ends_with(".exe")));
        assert!(p.cmdline.as_ref().is_some_and(|c| !c.is_empty()));
        assert!(p.cwd.is_some());
    }

    #[test]
    fn system_snapshot_sane() {
        let procs = snapshot_processes();
        let s = system_snapshot(1, &procs).unwrap();
        assert!(s.ram_total > 4 << 30 && s.commit_used > 0 && s.commit_used <= s.commit_limit && s.pool_nonpaged > 0);
        assert!(s.boot_time > 0 && s.logger_ws.is_none());
    }

    #[test]
    fn compression_from_procs_found_absent() {
        let mk = |name: &str, ws: i64| {
            let mut p = crate::testutil::mkproc(4, 0, name, None);
            p.working_set = ws;
            p
        };
        assert_eq!(compression_from_procs(&[mk("Memory Compression", 123)]), Some(123));
        assert_eq!(compression_from_procs(&[mk("Memory Compression", 0)]), None);
        assert_eq!(compression_from_procs(&[mk("other", 5)]), None);
    }

    #[test]
    fn input_and_window_probes_are_sane() {
        assert!(seconds_since_input() >= 0.0);
        let _ = window_pids();
        assert!(foreground_pid().is_none_or(|p| p > 0));
        assert!(own_working_set().is_some_and(|w| w > 0));
    }

    #[test]
    fn services() {
        let svcs = all_services();
        assert!(!svcs.is_empty());
        assert!(svcs.iter().all(|s| ["automatic", "manual", "disabled"].contains(&s.start_type.as_str())));
        assert!(svcs.iter().any(|s| s.start_type == "automatic"));
        let by_pid = services_by_pid();
        assert!(by_pid.iter().all(|(pid, l)| *pid > 0 && !l.is_empty()));
    }

    #[test]
    fn exe_without_a_handle_resolves_to_a_dos_path() {
        // this process's own image, found through the no-handle path
        let exe = exe_via_system_info(std::process::id()).expect("image name");
        assert!(exe.len() > 3 && exe.as_bytes()[1] == b':', "{exe}");
        assert!(std::path::Path::new(&exe).exists(), "{exe}");
        let devs = [(r"\Device\HarddiskVolume3".to_string(), "C:".to_string())];
        assert_eq!(nt_to_dos(r"\Device\HarddiskVolume3\Windows\x.exe", &devs), Some(r"C:\Windows\x.exe".to_string()));
        assert_eq!(nt_to_dos(r"\Device\HarddiskVolume33\x", &devs), None);
    }

    #[test]
    fn company_of_a_system_exe() {
        let c = file_company(r"C:\Windows\System32\notepad.exe");
        assert!(c.is_some_and(|c| c.to_lowercase().contains("microsoft")));
    }
}
