// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//! Windows Service Control Manager (SCM) adapter for dd-procmgr-service.
//!
//! Implements the SCM protocol using `windows-sys` directly:
//! - `StartServiceCtrlDispatcherW` registers with SCM (blocks the calling thread).
//! - `RegisterServiceCtrlHandlerExW` installs our control-event callback.
//! - `SetServiceStatus` reports lifecycle transitions.
//!
//! The control handler bridges SCM stop events into the tokio runtime via
//! [`crate::platform::shutdown_notify()`], so `ProcessManager::run()` shuts
//! down without any API changes.

use std::ffi::c_void;
use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use log::{error, info, warn};
use windows_sys::Win32::Foundation::{
    ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, GetLastError, NO_ERROR,
};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOP_PENDING, SERVICE_STOPPED,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
};

use crate::config::YamlConfigLoader;
use crate::manager::ProcessManager;
use crate::platform;
use crate::uuid_gen::V4UuidGenerator;

const SERVICE_NAME: &str = "dd-procmgr-service";
/// Must exceed `DEFAULT_STOP_TIMEOUT_SECS` (90s) + `EXIT_GATE` so that
/// `ProcessManager::shutdown` can finish gracefully and force-kill any
/// stubborn children before we hard-exit.
const HARD_STOP_TIMEOUT: Duration = Duration::from_secs(100);
const EXIT_GATE: Duration = Duration::from_secs(5);

/// Global status handle set by `service_main` before use in the control handler.
/// On the GNU ABI `SERVICE_STATUS_HANDLE` is `*mut c_void`, not `isize`.
static STATUS_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

/// Encode `SERVICE_NAME` as a null-terminated UTF-16 slice at compile time.
/// `StartServiceCtrlDispatcherW` and `RegisterServiceCtrlHandlerExW` require
/// LPCWSTR pointers.
fn service_name_wide() -> Vec<u16> {
    SERVICE_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}

fn set_service_status(state: u32, controls: u32, exit_code: u32, wait_hint_ms: u32) {
    let handle = STATUS_HANDLE.load(Ordering::SeqCst);
    if handle.is_null() {
        return;
    }
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: controls,
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: wait_hint_ms,
    };
    unsafe {
        SetServiceStatus(handle, &status);
    }
}

/// SCM control-event callback. Runs on an OS thread managed by SCM, not
/// inside the tokio runtime.
unsafe extern "system" fn ctrl_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            set_service_status(
                SERVICE_STOP_PENDING,
                0,
                NO_ERROR,
                HARD_STOP_TIMEOUT.as_millis() as u32,
            );
            platform::shutdown_notify().notify_one();

            std::thread::spawn(|| {
                std::thread::sleep(HARD_STOP_TIMEOUT);
                eprintln!("hard-stop timeout reached, forcing exit");
                std::process::exit(1);
            });

            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => NO_ERROR,
    }
}

/// Entry point called by SCM on a new thread via `StartServiceCtrlDispatcherW`.
unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let name = service_name_wide();

    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(ctrl_handler), std::ptr::null_mut())
    };
    if handle.is_null() {
        error!(
            "RegisterServiceCtrlHandlerExW failed: {}",
            unsafe { GetLastError() }
        );
        return;
    }
    STATUS_HANDLE.store(handle, Ordering::SeqCst);

    set_service_status(SERVICE_START_PENDING, 0, NO_ERROR, 10_000);

    if let Err(e) = run_service_inner() {
        error!("service failed: {e:#}");
        set_service_status(SERVICE_STOPPED, 0, 1, 0);
        return;
    }

    set_service_status(SERVICE_STOPPED, 0, NO_ERROR, 0);
}

/// Core service logic: creates the tokio runtime, runs ProcessManager, then
/// waits for the exit gate before reporting stopped.
fn run_service_inner() -> Result<()> {
    dd_agent_log::init(dd_agent_log::LogConfig {
        logger_name: "PROCMGR",
        level: log::Level::Info,
        log_file: None,
    })
    .context("failed to initialize logging")?;

    info!("dd-procmgr-service starting (SCM mode)");

    let runtime = tokio::runtime::Runtime::new().context("failed to create tokio runtime")?;

    set_service_status(
        SERVICE_RUNNING,
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        NO_ERROR,
        0,
    );

    let result = runtime.block_on(async {
        let loader = Arc::new(YamlConfigLoader::from_env());
        let mgr = ProcessManager::new(loader, Arc::new(V4UuidGenerator));
        mgr.run().await
    });

    if let Err(ref e) = result {
        warn!("ProcessManager exited with error: {e:#}");
    }

    // Keep the service alive briefly so SCM treats a quick clean exit as
    // success rather than a crash (mirrors Go's runTimeExitGate).
    std::thread::sleep(EXIT_GATE);

    result
}

/// Run as a Windows service. If launched interactively (not by SCM), falls
/// back to console mode so the binary remains debuggable.
pub fn run_as_service() -> Result<()> {
    let name = service_name_wide();

    let table: [SERVICE_TABLE_ENTRYW; 2] = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_ptr() as *mut u16,
            lpServiceProc: Some(service_main),
        },
        // Null-terminated sentinel entry.
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];

    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if ok != 0 {
        return Ok(());
    }

    let err = unsafe { GetLastError() };
    if err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
        info!("not launched by SCM, falling back to console mode");
        return run_console_fallback();
    }

    bail!("StartServiceCtrlDispatcherW failed: error {err}");
}

/// Fallback console mode: identical to dd-procmgrd but under the
/// dd-procmgr-service binary name, useful for interactive debugging.
fn run_console_fallback() -> Result<()> {
    dd_agent_log::init(dd_agent_log::LogConfig {
        logger_name: "PROCMGR",
        level: log::Level::Info,
        log_file: None,
    })
    .context("failed to initialize logging")?;

    info!("dd-procmgr-service starting (console mode)");

    let runtime = tokio::runtime::Runtime::new().context("failed to create tokio runtime")?;
    runtime.block_on(async {
        let loader = Arc::new(YamlConfigLoader::from_env());
        let mgr = ProcessManager::new(loader, Arc::new(V4UuidGenerator));
        mgr.run().await
    })
}
