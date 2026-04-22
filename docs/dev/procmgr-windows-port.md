# dd-procmgrd Windows Port — Step-by-Step Plan

## Overview

Port the `dd-procmgrd` process manager daemon and its `dd-procmgr` CLI client
from Linux-only to full Windows support with identical functionality. The work
follows an incremental TDD approach where every commit keeps CI green.

## Principles

- **Every commit compiles on Linux/macOS and cross-compiles for Windows.**
- **Every commit passes all existing tests** — no regressions.
- `#[cfg(windows)]` code compiles but does not execute on the Linux CI.
  `unimplemented!()` stubs are acceptable for initial compilation.
- Small, independently committable steps. Each step is one PR.

## Platform Abstraction Strategy

| Concern | Unix | Windows |
|---|---|---|
| Process groups | `cmd.process_group(0)` + `kill(-pgid, sig)` | Job Objects |
| Graceful stop | `SIGTERM` to process group | `GenerateConsoleCtrlEvent` (CTRL_BREAK) |
| Force kill | `SIGKILL` to process group | `TerminateJobObject` / `TerminateProcess` |
| Exit signal | `ExitStatus::signal()` | Always `None` |
| Daemon shutdown | `SIGTERM` / `SIGINT` | `tokio::signal::ctrl_c()` + service events |
| IPC transport | Unix Domain Sockets (UDS) | Named Pipes |
| Default paths | `/etc/dd-procmgr/`, `/run/dd-procmgr.sock` | `%ProgramData%\Datadog\dd-procmgr\` |

## Steps

### Phase 1: Foundation (S01–S02) ✅

| Step | Description | Status |
|---|---|---|
| **S01** | `Cargo.toml`: make `nix` unix-only, add `windows-sys` under `cfg(windows)`. Verify `cargo check`. | ✅ Merged |
| **S02** | Create `platform/{mod,unix,windows}.rs` with Unix real impl + Windows `unimplemented!()` stubs. Add to `lib.rs`. Verify compile. | ✅ Merged |

### Phase 2: Test Porting (S03–S09)

| Step | Description | Status |
|---|---|---|
| **S03** | Add `test_helpers` module (`sleep_cmd`, `true_cmd`, `false_cmd`, `shell_cmd`, `exit_status`, `sleep_config_yaml`, etc.). Verify `cargo check --tests`. | ✅ Merged |
| **S04** | Refactor `process.rs` production code: replace `nix::` calls with `platform::` calls. All tests pass unchanged. | ✅ Merged |
| **S05** | Port `process.rs` tests: replace hardcoded commands with `test_helpers`, cfg-gate Unix-only tests. All tests still pass. | ✅ Merged |
| **S06** | Add `shutdown_signal()` to `platform/{unix,windows}.rs`. Refactor `manager.rs`: replace `tokio::signal::unix`. Tests pass. | ✅ Merged |
| **S07** | Port `manager.rs` tests: replace commands + `nix` cleanup with `test_helpers` + `platform::`. Tests pass. | ✅ Merged |
| **S08** | Port `shutdown.rs` tests: replace commands with `test_helpers`. Tests pass. | ✅ Merged |
| **S09** | Port `grpc/service.rs` tests: replace commands + `nix` cleanup. Tests pass. | ✅ Merged |

### Phase 3: Transport Abstraction (S10–S14)

| Step | Description | Status |
|---|---|---|
| **S10** | Create `transport/{mod,uds,named_pipe}.rs`. Extract UDS logic from `server.rs` into `transport/uds.rs`. Verify compile. | ✅ Merged |
| **S11** | Refactor `grpc/server.rs`: delegate to `transport::serve()`. All server tests pass. | ✅ Merged |
| **S12** | Remove duplicate transport tests from `grpc/server.rs`. Tests pass. | ✅ Merged |
| **S13** | Port `grpc/mod.rs` tests: cfg-gate with `#[cfg(unix)]`, use `test_helpers`. Tests pass. | ✅ Merged |
| **S14** | Refactor `bins/dd-procmgr.rs`: use `transport::connect()`. E2E tests still pass. | ✅ Merged |

### Phase 4: Config & Build (S15–S16)

| Step | Description | Status |
|---|---|---|
| **S15** | Port `config.rs` tests + implement platform-conditional default paths. Tests pass. | ✅ Merged |
| **S16** | Update `BUILD.bazel`: add `select()` for platform deps (`nix` on Linux, `tokio-stream` shared, `windows-sys` on Windows). Constraint widening deferred to S22 when Windows toolchain is available. | PR open, rebased on main |

### Phase 5: Integration Test Port (S17–S18)

| Step | Description | Status |
|---|---|---|
| **S17** | Port `tests/helpers/mod.rs`: cross-platform `DaemonHandle`, `pid_is_alive`, `TestEnv`. Verify compile both targets. | PR open, based on S16 |
| **S18** | Port `tests/e2e.rs`: replace commands with helpers, cfg-gate Unix-only tests, DRY-consolidate config builders into `src/test_helpers.rs`. All E2E tests pass on Unix. | PR open, based on S17 |

### Phase 6: Windows Implementation (S19–S20)

| Step | Description | Status |
|---|---|---|
| **S19** | Implement `platform/windows.rs`: `CREATE_NEW_PROCESS_GROUP`, `GenerateConsoleCtrlEvent`, `TerminateProcess`. Make `cpp_stdlib` and e2e deps platform-aware in BUILD.bazel. Keep `e2e_test` and all Bazel Rust targets Linux-only (proto dep requires prost toolchain not yet available for Windows). | PR open, based on S18 |
| **S20** | Implement `transport/named_pipe.rs`: Named Pipe server + client for tonic. Cargo cross-compile verified (`cargo check/clippy --target x86_64-pc-windows-msvc`). Bazel Windows build tracked in S22. | PR open, based on S19 |

### Phase 7: Build & Packaging (S21–S23)

| Step | Description | Status |
|---|---|---|
| **S21** | Rename Windows daemon binary from `dd-procmgrd` to `dd-procmgr-service`. Platform-conditional `[[bin]]` in Cargo.toml, separate `rust_binary` in BUILD.bazel, update test helpers and docs. | PR open, based on S20 |
| **S22** | Bazel Windows build enablement. Upgraded `rules_rust` via `git_override` to commit `82506df` (GNU ABI support), registered `x86_64-pc-windows-gnu` toolchain in `MODULE.bazel`, added `--extra_toolchains` to `.bazelrc`. Fixed sandbox `PATH` for Windows CI in `.gitlab/build/bazel/test.yml` (adds MinGW, PowerShell, system32 dirs via `--action_env`/`--host_action_env`). Library compiles, `dd-procmgrd_test` passes, `dd-procmgr-service` and `dd-procmgr` build on Windows. | ✅ Merged |
| **S23** | Installer integration: add `dd-procmgr-service.exe` and `dd-procmgr.exe` to the Windows MSI package. Windows `pkg_files` in `BUILD.bazel`, Omnibus build+copy via `bazelisk run :install_windows`, WiX# service registration (`GenerateDependentServiceInstaller` as LocalSystem), service lifecycle in `ServiceCustomAction.cs`, symbol stripping and code signing in `agent.rb`. CLI binary (`dd-procmgr.exe`) included as a plain file (no service). | PR open |

### Phase 8: End-to-End Validation (S24–S25)

| Step | Description | Status |
|---|---|---|
| **S24** | Write new-e2e `helpers_windows.go` + `windows_test.go`. Go compiles, tests skipped unless Windows VM provisioned. | Pending |
| **S25** | Run new-e2e on Windows EC2, iterate until all pass. | Pending |

## Key Files

| File | Purpose |
|---|---|
| `pkg/procmgr/rust/src/platform/mod.rs` | Re-exports active platform module |
| `pkg/procmgr/rust/src/platform/unix.rs` | Unix process ops (nix wrappers) |
| `pkg/procmgr/rust/src/platform/windows.rs` | Windows process ops (Job Objects, Win32 API) |
| `pkg/procmgr/rust/src/test_helpers.rs` | Cross-platform test command helpers |
| `pkg/procmgr/rust/src/transport/mod.rs` | Re-exports active transport module |
| `pkg/procmgr/rust/src/transport/uds.rs` | Unix Domain Socket transport + serve() |
| `pkg/procmgr/rust/src/transport/named_pipe.rs` | Named Pipe transport (server + client for tonic) |

## Dependencies

| Crate | Scope | Purpose |
|---|---|---|
| `nix` | `cfg(unix)` | POSIX signals, process groups |
| `windows-sys` | `cfg(windows)` | Win32 API: Job Objects, Console, Threading |
| `tempfile` | dev | Temp dirs for test configs |

## Future Improvements

- **`Abandoned` process state**: When `force_kill` fails (e.g. permissions, race
  conditions), `wait_for_stop` currently marks the process as `Stopped` even
  though it may still be running. A new `Abandoned` (or `Unknown`) state would
  more honestly represent this situation. This affects both Unix and Windows and
  requires deciding what the manager should do with abandoned processes (retry,
  alert, ignore). Tracked as a follow-up outside the Windows port scope.

- **Named Pipe ACL hardening**: `ServerOptions::new().create()` uses the default
  Windows security descriptor. Apply an explicit DACL restricting pipe access to
  `SYSTEM` and `Administrators` to prevent unprivileged users from holding
  connections open and exhausting pipe instances (local DoS). Requires
  `InitializeSecurityDescriptor` / `SetSecurityDescriptorDacl` from
  `windows_sys::Win32::Security` or a helper crate.

- **`ProcessConfig` builder pattern**: Add `ProcessConfig::new(cmd, args)` and
  chainable `.with_*()` methods (`.with_restart()`, `.with_env()`,
  `.with_stop_timeout()`, etc.) to replace verbose `mut cfg` + field assignment
  patterns in tests and production code. Deferred to a standalone PR after the
  Windows port is complete.

## CI Notes

- PR #48450 introduced a bug where non-Go files (like `Cargo.toml`) caused
  `go test` to run on Rust-only directories. Fixed in
  `jose/fix-gotest-non-go-files` (pending merge).
- E2E tests (`TestMultiFakeintakeSuite`, etc.) only run on `main` and RC
  branches, not PR branches. Failures in those tests on PR CI are typically
  AWS infrastructure issues (subnet exhaustion), not code problems.
- The Windows Bazel CI uses MinGW (GNU) as its C++ toolchain.
  `rules_rust` was upgraded via `git_override` to a commit (`82506df`) that
  adds `x86_64-pc-windows-gnu` toolchain support. The GNU toolchain is
  registered in `MODULE.bazel` and selected via `--extra_toolchains` in
  `.bazelrc`. This resolved the original MSVC/MinGW ABI mismatch.
- The Windows CI sandbox `PATH` must include MinGW, PowerShell, and system32
  directories. These are set via `--action_env=PATH` / `--host_action_env=PATH`
  in `.gitlab/build/bazel/test.yml` (not in `.bazelrc`, to avoid poisoning
  remote cache keys).
- `timeout.exe` is not available on Windows Server Core CI runners. Tests use
  `ping -n <secs+1> 127.0.0.1 >nul` as a portable delay alternative.
