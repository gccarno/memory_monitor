//! A small window that exits on WM_CLOSE; with `--stubborn` it ignores WM_CLOSE. Exits on
//! its own after 120 s so a failed test leaks nothing.
use std::sync::atomic::{AtomicBool, Ordering};

use windows::core::w;
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::*;

static STUBBORN: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_CLOSE if STUBBORN.load(Ordering::SeqCst) => LRESULT(0),
        WM_CLOSE | WM_TIMER => {
            let _ = DestroyWindow(hwnd);
            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wp, lp),
    }
}

fn main() {
    STUBBORN.store(std::env::args().any(|a| a == "--stubborn"), Ordering::SeqCst);
    unsafe {
        let hi = GetModuleHandleW(None).expect("module").into();
        let class = w!("MemwatchTestWindow");
        let wc = WNDCLASSW { lpfnWndProc: Some(proc), hInstance: hi, lpszClassName: class, ..Default::default() };
        RegisterClassW(&wc);
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0), class, w!("memwatch test window"), WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            40, 40, 260, 100, None, None, hi, None,
        )
        .expect("window");
        SetTimer(hwnd, 1, 120_000, None);
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}
