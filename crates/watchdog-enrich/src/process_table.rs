//! Live, concurrent table of known processes.
//!
//! Bootstrap path: an initial snapshot via `CreateToolhelp32Snapshot`
//! captures every process running at startup.
//!
//! Steady-state path: ETW `ProcessStart`/`ProcessStop` events keep the
//! table in sync.
//!
//! Lookups are cheap and lock-free for readers most of the time
//! (RwLock with reader-biased contention). Process records are wrapped
//! in `Arc` so events that travel downstream can keep them alive
//! independently of the table itself.

use std::collections::HashMap;
use std::mem::size_of;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use watchdog_core::ProcessInfo;

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::{cmdline, device_map};

pub struct ProcessTable {
    inner: RwLock<HashMap<u32, Arc<ProcessInfo>>>,
}

impl ProcessTable {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::with_capacity(512)),
        }
    }

    /// Walk every currently-running process and fill the table. Best-effort:
    /// individual failures (process exited mid-walk, access denied on a
    /// protected process, etc.) are silently skipped — they'll get picked
    /// up by ETW the next time they do anything observable.
    pub fn populate_from_snapshot(&self) -> usize {
        let mut count = 0;
        let now = SystemTime::now();

        unsafe {
            let snapshot: HANDLE = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return 0,
            };

            let mut entry = PROCESSENTRY32W {
                dwSize: size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let pid = entry.th32ProcessID;
                    let ppid = entry.th32ParentProcessID;

                    // szExeFile is the basename only. Try to upgrade it to the full
                    // DOS path by querying the process directly.
                    let (image_path, image_name) = upgrade_to_full_path(pid)
                        .unwrap_or_else(|| (PathBuf::from(read_wide(&entry.szExeFile)), read_wide(&entry.szExeFile)));

                    let cmdline = cmdline::query(pid).unwrap_or_default();

                    let info = Arc::new(ProcessInfo {
                        pid,
                        ppid,
                        session_id: 0, // not exposed by Toolhelp; ETW fills it later
                        image_path,
                        image_name: image_name.to_ascii_lowercase(),
                        cmdline,
                        started_at: now, // we don't know the real start; "before us" suffices
                    });

                    self.inner.write().unwrap().insert(pid, info);
                    count += 1;

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }

            let _ = CloseHandle(snapshot);
        }
        count
    }

    /// Add (or replace) a process entry from a `ProcessStart` event.
    pub fn on_process_start(
        &self,
        pid: u32,
        ppid: u32,
        session_id: u32,
        image_nt: &str,
        cmdline_from_event: &str,
        ts: SystemTime,
    ) -> Arc<ProcessInfo> {
        let image_path = device_map::canonicalize(image_nt);
        let image_name = device_map::basename_lower(&image_path);

        // The Kernel-Process manifest doesn't populate CommandLine on event 1,
        // so this is almost always empty. Try to fish it out ourselves; if we
        // also fail (race: process is still initializing) we accept "".
        let cmdline = if cmdline_from_event.is_empty() {
            cmdline::query(pid).unwrap_or_default()
        } else {
            cmdline_from_event.to_string()
        };

        let info = Arc::new(ProcessInfo {
            pid,
            ppid,
            session_id,
            image_path,
            image_name,
            cmdline,
            started_at: ts,
        });

        self.inner.write().unwrap().insert(pid, Arc::clone(&info));
        info
    }

    /// Mark the PID gone. We currently evict immediately; once we have a
    /// detection stage that benefits from short retention we'll add a TTL.
    pub fn on_process_stop(&self, pid: u32) -> Option<Arc<ProcessInfo>> {
        self.inner.write().unwrap().remove(&pid)
    }

    pub fn lookup(&self, pid: u32) -> Option<Arc<ProcessInfo>> {
        self.inner.read().unwrap().get(&pid).cloned()
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    /// `true` if any live process has this image basename (case-
    /// insensitive). Used by the Summary view to spot well-known
    /// security services like `msmpeng.exe`.
    pub fn contains_image(&self, name: &str) -> bool {
        let needle = name.to_ascii_lowercase();
        self.inner
            .read()
            .unwrap()
            .values()
            .any(|p| p.image_name == needle)
    }
}

/// Open the process and ask Windows for the canonical DOS path. Returns
/// `None` if we can't open it (gone, protected) — caller falls back to
/// the basename Toolhelp gave us.
fn upgrade_to_full_path(pid: u32) -> Option<(PathBuf, String)> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = vec![0u16; 1024];
        let mut size = buf.len() as u32;
        let res = QueryFullProcessImageNameW(
            h,
            PROCESS_NAME_FORMAT(0), // 0 = Win32/DOS form
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        );
        let _ = CloseHandle(h);
        if res.is_err() || size == 0 {
            return None;
        }
        let path_str = String::from_utf16_lossy(&buf[..size as usize]);
        let path = PathBuf::from(&path_str);
        let basename = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        Some((path, basename))
    }
}

fn read_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}
