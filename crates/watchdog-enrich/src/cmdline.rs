//! Best-effort command line resolution for a live PID.
//!
//! `Microsoft-Windows-Kernel-Process` event 1 does not carry the command
//! line, so we fish it out ourselves via the documented (since Win 8.1)
//! `NtQueryInformationProcess(ProcessCommandLineInformation)` class 60.
//! The kernel hands back a `UNICODE_STRING` whose `Buffer` already
//! points into our buffer past the header — no PEB walk required.
//!
//! Races are accepted: a brand-new process may not have its command line
//! materialized yet when we query right after `ProcessStart`. In that
//! case we return `None`; the caller leaves the field empty.

use std::ffi::c_void;
use std::sync::LazyLock;

use windows::core::{s, w, PCSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, NTSTATUS, UNICODE_STRING};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;

type NtQueryInformationProcessFn = unsafe extern "system" fn(
    handle: HANDLE,
    info_class: u32,
    info: *mut c_void,
    info_len: u32,
    ret_len: *mut u32,
) -> NTSTATUS;

static NTQUERY: LazyLock<Option<NtQueryInformationProcessFn>> = LazyLock::new(|| unsafe {
    let ntdll = GetModuleHandleW(w!("ntdll.dll")).ok()?;
    // GetProcAddress takes a PCSTR (ANSI). The `s!` macro gives us a
    // null-terminated ANSI literal at compile time.
    let proc_name: PCSTR = s!("NtQueryInformationProcess");
    let addr = GetProcAddress(ntdll, proc_name)?;
    Some(std::mem::transmute::<_, NtQueryInformationProcessFn>(addr))
});

/// Read the command line of an arbitrary PID. Requires
/// `PROCESS_QUERY_LIMITED_INFORMATION` which an elevated process has
/// against virtually anything except a few protected processes.
pub fn query(pid: u32) -> Option<String> {
    let nt_query = *NTQUERY.as_ref()?;

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()? };

    // 8 KB is well over the documented Windows command-line cap (32 KB on
    // recent versions, but 99% of real cmdlines are < 1 KB). If a real
    // cmdline exceeds this we'll just see it truncated.
    let mut buf = vec![0u8; 8192];
    let mut ret_len = 0u32;

    let status = unsafe {
        nt_query(
            handle,
            PROCESS_COMMAND_LINE_INFORMATION,
            buf.as_mut_ptr().cast::<c_void>(),
            buf.len() as u32,
            &mut ret_len,
        )
    };

    let result = if status.is_ok() {
        // Layout: UNICODE_STRING header followed by the wide-char data
        // that its Buffer pointer addresses (the kernel writes both
        // inside our buffer).
        let us = unsafe { &*(buf.as_ptr() as *const UNICODE_STRING) };
        if us.Length == 0 || us.Buffer.is_null() {
            None
        } else {
            let chars = (us.Length / 2) as usize;
            let slice = unsafe { std::slice::from_raw_parts(us.Buffer.0, chars) };
            Some(String::from_utf16_lossy(slice))
        }
    } else {
        None
    };

    unsafe {
        let _ = CloseHandle(handle);
    }
    result
}
