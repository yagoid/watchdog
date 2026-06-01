//! The `run-service` entry point: the code the SCM actually launches. Sets up
//! the service control dispatcher, builds the pipeline, and drains scored
//! events into the incident sinks until the SCM asks us to stop.

use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use crossbeam_channel::RecvTimeoutError;
use watchdog_core::Severity;
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

use super::sink::IncidentSink;
use super::{service_log, SERVICE_NAME, SERVICE_SESSION_NAME};

/// How often the drain loop wakes to check the stop flag.
const POLL: Duration = Duration::from_millis(500);

define_windows_service!(ffi_service_main, service_main);

/// Hand control to the SCM dispatcher. Blocks until the service stops. Called
/// from `main` for the `run-service` subcommand; must only run when launched
/// by the SCM.
pub fn dispatch() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        service_log(&format!("service exited with error: {e:#}"));
    }
}

fn run_service() -> Result<()> {
    let shutdown = Arc::new(AtomicBool::new(false));

    let handler_flag = Arc::clone(&shutdown);
    let event_handler = move |control| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                handler_flag.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // Give the SCM a wait hint: bootstrapping the process table and enabling
    // five ETW providers takes a beat, and a 0 hint can read as hung.
    status_handle.set_service_status(status_hint(
        ServiceState::StartPending,
        false,
        Duration::from_secs(10),
    ))?;
    service_log("service starting");

    let (pipeline, rx_scored) = crate::pipeline::start(SERVICE_SESSION_NAME, false)?;
    let baseline = Arc::clone(&pipeline.baseline);
    let mut sink = IncidentSink::open()?;

    status_handle.set_service_status(status(ServiceState::Running, true))?;
    service_log("service running");

    while !shutdown.load(Ordering::SeqCst) {
        match rx_scored.recv_timeout(POLL) {
            Ok(ev) => {
                if ev.severity >= Severity::Warn {
                    sink.record(&ev);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            // The drive-watcher keeps a sender alive, so this only fires if
            // the pipeline genuinely tore down — treat as stop.
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    status_handle.set_service_status(status_hint(
        ServiceState::StopPending,
        false,
        Duration::from_secs(5),
    ))?;
    service_log("service stopping");

    // Stop ETW ingestion, then persist the baseline explicitly: the worker
    // threads are detached and won't run their own final save on a clean
    // stop (the drive-watcher never releases the raw channel).
    drop(pipeline);
    if let Err(e) = baseline.save_to_disk() {
        service_log(&format!("baseline save on shutdown failed: {e}"));
    }
    sink.flush();

    status_handle.set_service_status(status(ServiceState::Stopped, false))?;
    service_log("service stopped");
    Ok(())
}

fn status(state: ServiceState, accept_stop: bool) -> ServiceStatus {
    status_hint(state, accept_stop, Duration::default())
}

fn status_hint(state: ServiceState, accept_stop: bool, wait_hint: Duration) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if accept_stop {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint,
        process_id: None,
    }
}
