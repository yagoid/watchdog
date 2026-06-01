use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use crossbeam_channel::Sender;
use ferrisetw::native::EvntraceNativeError;
use ferrisetw::trace::{stop_trace_by_name, TraceError, TraceTrait, UserTrace};
use watchdog_core::RawEvent;

// Both raw forms of ERROR_ACCESS_DENIED that we've observed coming back through
// ferrisetw -> std::io::Error: the bare Win32 code and the HRESULT-wrapped form.
const WIN32_ERROR_ACCESS_DENIED: i32 = 5;
const HRESULT_E_ACCESSDENIED: i32 = -2147024891; // 0x80070005

/// A live ETW real-time session. Dropping it stops the session.
pub struct Session {
    _trace: UserTrace,
}

impl Session {
    /// Start a real-time session named `name`, enabling the providers
    /// we care about, and spawn a background thread to process events.
    ///
    /// `dropped` is incremented whenever an ETW callback fails to push an
    /// event downstream (channel full) — used by the UI to display
    /// backpressure pressure.
    ///
    /// ETW sessions outlive the process that started them: if a previous
    /// run crashed or was Ctrl-C'd, an orphan session with the same name
    /// is still alive in the kernel and a fresh `start()` returns
    /// `AlreadyExist`. We detect that, evict the orphan, and retry once.
    pub fn start(name: &str, tx: Sender<RawEvent>, dropped: Arc<AtomicU64>) -> Result<Self> {
        match Self::try_start(name, tx.clone(), Arc::clone(&dropped)) {
            Ok(s) => Ok(s),
            Err(TraceError::EtwNativeError(EvntraceNativeError::AlreadyExist)) => {
                eprintln!(
                    "watchdog-etw: session {name:?} already exists (orphan from a prior run); stopping it and retrying"
                );
                stop_trace_by_name(name)
                    .map_err(|e| friendly_err("failed to stop orphan session", name, &e))?;
                Self::try_start(name, tx, dropped)
                    .map_err(|e| friendly_err("retry after orphan cleanup failed", name, &e))
            }
            Err(e) => Err(friendly_err("failed to start ETW session", name, &e)),
        }
    }

    fn try_start(
        name: &str,
        tx: Sender<RawEvent>,
        dropped: Arc<AtomicU64>,
    ) -> std::result::Result<Self, TraceError> {
        let process_provider  = crate::providers::kernel_process::build(tx.clone(),  Arc::clone(&dropped));
        let file_provider     = crate::providers::kernel_file::build(tx.clone(),     Arc::clone(&dropped));
        let registry_provider = crate::providers::kernel_registry::build(tx.clone(), Arc::clone(&dropped));
        let network_provider  = crate::providers::kernel_network::build(tx.clone(),  Arc::clone(&dropped));
        let dns_provider      = crate::providers::dns_client::build(tx,              dropped);

        let (trace, handle) = UserTrace::new()
            .named(name.to_string())
            .enable(process_provider)
            .enable(file_provider)
            .enable(registry_provider)
            .enable(network_provider)
            .enable(dns_provider)
            .start()?;

        std::thread::Builder::new()
            .name("watchdog-etw".to_string())
            .spawn(move || {
                let status = UserTrace::process_from_handle(handle);
                eprintln!("watchdog-etw: trace processing ended: {status:?}");
            })
            .expect("failed to spawn ETW processing thread");

        Ok(Self { _trace: trace })
    }
}

/// Wrap a ferrisetw `TraceError` into an `anyhow::Error` with a hint about
/// the most common cause when we recognize it.
fn friendly_err(ctx: &str, name: &str, err: &TraceError) -> anyhow::Error {
    if let TraceError::EtwNativeError(EvntraceNativeError::IoError(io_err)) = err {
        if matches!(io_err.raw_os_error(), Some(WIN32_ERROR_ACCESS_DENIED) | Some(HRESULT_E_ACCESSDENIED)) {
            return anyhow!(
                "{ctx} {name:?}: Access Denied.\n  \
                 Creating ETW real-time sessions requires running elevated. \
                 Re-open Windows Terminal / PowerShell with \"Run as administrator\" \
                 and try again. (Original error: {err:?})"
            );
        }
    }
    anyhow!("{ctx} {name:?}: {err:?}")
}
