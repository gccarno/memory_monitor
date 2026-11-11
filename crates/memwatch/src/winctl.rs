//! Thin Win32 controls used by the actions and the elevated runner: terminate a process,
//! close windows, stop a service, change a service's start type.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_SERVICE_NOT_ACTIVE, BOOL, HWND, LPARAM, WPARAM,
};
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW,
    QueryServiceConfigW, QueryServiceStatus, ENUM_SERVICE_TYPE, QUERY_SERVICE_CONFIGW, SERVICE_QUERY_CONFIG, SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG,
    SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_CONTROL_STOP, SERVICE_DELAYED_AUTO_START_INFO,
    SERVICE_DEMAND_START, SERVICE_DISABLED, SERVICE_ERROR, SERVICE_QUERY_STATUS, SERVICE_START_TYPE, SERVICE_STATUS,
    SERVICE_STOP, SERVICE_STOPPED,
};
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowThreadProcessId, IsWindowVisible, PostMessageW, WM_CLOSE,
};

/// Outcome of asking Windows to end one process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    Done,
    /// No such process (already gone).
    Gone,
    /// The caller may not terminate it: needs elevation.
    Denied,
    Failed(String),
}

pub fn terminate(pid: u32) -> Term {
    unsafe {
        let h = match OpenProcess(PROCESS_TERMINATE, false, pid) {
            Ok(h) => h,
            Err(e) if e.code() == ERROR_INVALID_PARAMETER.to_hresult() => return Term::Gone,
            Err(e) if e.code() == ERROR_ACCESS_DENIED.to_hresult() => return Term::Denied,
            Err(e) => return Term::Failed(e.message()),
        };
        let r = TerminateProcess(h, 1);
        let _ = CloseHandle(h);
        match r {
            Ok(()) => Term::Done,
            Err(e) if e.code() == ERROR_ACCESS_DENIED.to_hresult() => Term::Denied,
            Err(e) => Term::Failed(e.message()),
        }
    }
}

unsafe extern "system" fn win_cb(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let out = &mut *(lparam.0 as *mut HashMap<u32, Vec<isize>>);
    if IsWindowVisible(hwnd).as_bool() {
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        if pid != 0 {
            out.entry(pid).or_default().push(hwnd.0 as isize);
        }
    }
    BOOL(1)
}

/// Visible top-level windows per pid (cloaked ones too, e.g. on other desktops).
pub fn windows_by_pid() -> HashMap<u32, Vec<isize>> {
    let mut out: HashMap<u32, Vec<isize>> = HashMap::new();
    unsafe {
        let _ = EnumWindows(Some(win_cb), LPARAM((&mut out as *mut HashMap<u32, Vec<isize>>) as isize));
    }
    out
}

/// Ask each window to close (WM_CLOSE); never fails.
pub fn post_close(hwnds: &[isize]) {
    for &h in hwnds {
        unsafe {
            let _ = PostMessageW(HWND(h as *mut _), WM_CLOSE, WPARAM(0), LPARAM(0));
        }
    }
}

struct Sc(SC_HANDLE);
impl Drop for Sc {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

fn open_service(name: &str, access: u32) -> Result<(Sc, Sc), String> {
    unsafe {
        let scm = Sc(OpenSCManagerW(None, None, SC_MANAGER_CONNECT).map_err(|e| e.message())?);
        let w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let h = Sc(OpenServiceW(scm.0, PCWSTR(w.as_ptr()), access).map_err(|e| e.message())?);
        Ok((scm, h))
    }
}

/// Only ordinary Win32 services that start at auto, demand or disabled may be changed:
/// never kernel or file-system drivers, nor boot/system-start services.
fn ensure_ordinary(h: &Sc) -> Result<(), String> {
    unsafe {
        let mut buf = vec![0u8; 8192];
        let mut needed = 0u32;
        let mut r = QueryServiceConfigW(h.0, Some(buf.as_mut_ptr().cast()), buf.len() as u32, &mut needed);
        if r.is_err() && needed as usize > buf.len() {
            buf = vec![0u8; needed as usize];
            r = QueryServiceConfigW(h.0, Some(buf.as_mut_ptr().cast()), buf.len() as u32, &mut needed);
        }
        r.map_err(|e| e.message())?;
        let q = &*(buf.as_ptr() as *const QUERY_SERVICE_CONFIGW);
        if q.dwServiceType.0 & 0x30 == 0 {
            return Err("not a Win32 service (driver); left alone".into());
        }
        if q.dwStartType.0 < 2 {
            return Err("boot/system-start service; left alone".into());
        }
        Ok(())
    }
}

/// Stop a service and wait until it reports stopped, for at most `wait`.
pub fn stop_service(name: &str, wait: Duration) -> Result<(), String> {
    let (_scm, h) = open_service(name, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG)?;
    ensure_ordinary(&h)?;
    unsafe {
        let mut st = SERVICE_STATUS::default();
        if let Err(e) = ControlService(h.0, SERVICE_CONTROL_STOP, &mut st) {
            if e.code() != ERROR_SERVICE_NOT_ACTIVE.to_hresult() {
                return Err(e.message());
            }
        }
        let until = Instant::now() + wait;
        loop {
            QueryServiceStatus(h.0, &mut st).map_err(|e| e.message())?;
            if st.dwCurrentState == SERVICE_STOPPED {
                return Ok(());
            }
            if Instant::now() >= until {
                return Err(format!("{name} did not stop in time"));
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

/// Set a service's start type: auto, delayed-auto, demand or disabled.
pub fn set_service_start(name: &str, start: &str) -> Result<(), String> {
    let code: SERVICE_START_TYPE = match start {
        "auto" | "delayed-auto" => SERVICE_AUTO_START,
        "demand" => SERVICE_DEMAND_START,
        "disabled" => SERVICE_DISABLED,
        other => return Err(format!("unknown start type {other}")),
    };
    let (_scm, h) = open_service(name, SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG)?;
    ensure_ordinary(&h)?;
    unsafe {
        ChangeServiceConfigW(
            h.0,
            ENUM_SERVICE_TYPE(0xFFFF_FFFF), // SERVICE_NO_CHANGE
            code,
            SERVICE_ERROR(0xFFFF_FFFF),
            PCWSTR::null(),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
        .map_err(|e| e.message())?;
        if code == SERVICE_AUTO_START {
            // auto and delayed-auto differ only in this flag
            let mut info = SERVICE_DELAYED_AUTO_START_INFO { fDelayedAutostart: BOOL((start == "delayed-auto") as i32) };
            ChangeServiceConfig2W(h.0, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, Some((&mut info as *mut _) as *const _))
                .map_err(|e| e.message())?;
        }
    }
    Ok(())
}

const CT_TOLERANCE: f64 = 1e-3;

/// The process with this pid, if it still exists with the recorded create time
/// (a reused pid does not match).
pub fn find_live(pid: u32, create_time: f64) -> Option<crate::models::ProcInfo> {
    crate::probe::snapshot_processes()
        .into_iter()
        .find(|p| p.pid == pid && (p.create_time - create_time).abs() <= CT_TOLERANCE)
}

/// Wait until the given processes are gone or `timeout` passes; returns the survivors.
pub fn wait_gone(items: &[(u32, f64)], timeout: Duration) -> Vec<(u32, f64)> {
    let until = Instant::now() + timeout;
    let mut left: Vec<(u32, f64)> = items.to_vec();
    loop {
        let snap = crate::probe::snapshot_processes();
        left.retain(|&(pid, ct)| snap.iter().any(|p| p.pid == pid && (p.create_time - ct).abs() <= CT_TOLERANCE));
        if left.is_empty() || Instant::now() >= until {
            return left;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
