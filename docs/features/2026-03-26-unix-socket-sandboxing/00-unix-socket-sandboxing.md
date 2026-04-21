# Unix Socket Sandboxing

## Context

nono's Landlock sandbox grants `/run` read access (via `system_read_linux` group) for basic system
functionality, but this exposes unix domain sockets that allow sandbox escape:

- `/run/user/1000/wezterm/agent.*` -- SSH agent (sign anything)
- `/run/docker.sock` -- Docker API (arbitrary container execution)
- `/run/dbus/system_bus_socket` -- D-Bus (system service control)

Landlock filesystem rules don't intercept `connect()` on filesystem-based unix sockets -- the
`connect()` syscall goes through `security_unix_stream_connect` / `security_unix_may_send` LSM
hooks, not the filesystem `security_path_*` hooks that Landlock uses. Future Landlock ABIs (~v7+)
may add `LANDLOCK_ACCESS_FS_CONNECT_UNIX`, but that's not available today.

nono already intercepts `openat()`/`openat2()` via seccomp user notification with a supervisor
process. Adding `connect()` and `sendmsg()` interception for AF_UNIX sockets follows the same
proven pattern: trap the syscall, read the `sockaddr_un` from the child's memory, validate the
path, and either emulate the syscall or deny with EPERM.

Scope: **Linux only**. macOS Seatbelt already handles unix socket deny via `(deny network-outbound
(path ...))` rules added in v0.23.1.

## Checkpoint

All implementation and manual verification complete. Phase 2 Steps 1-8 done: policy model
(`deny.sockets`), default deny entries (Docker, D-Bus), supervisor wiring, UX (dry-run output),
proxy filter consolidation (Step 5), sendmsg deadlock fix (Step 6, pipe+pidfd), profile
`add_deny_sockets` field (Step 7), and symlink-aware path matching (Step 8). Manual tests pass:
Docker socket blocked by default, custom wezterm agent socket blocked via external profile with
`add_deny_sockets`. All automated tests pass. Pending: user acceptance of both phases.
Future: diagnostic footer for socket denials (deferred), unified `deny.access` approach (option 2).

## Requirements

* R1: 🔄 `connect()` on AF_UNIX sockets to denied paths is blocked with EPERM (Phase: Interception) — implemented + tested
* R2: 🔄 `sendmsg()`/`sendto()` on AF_UNIX SOCK_DGRAM to denied paths is blocked with EPERM (Phase: Interception) — implemented + tested
* R3: 🔄 Allowed unix socket connections proceed without observable overhead or behavior change (Phase: Interception) — tested
* R4: 🔄 The supervisor reads `sockaddr_un.sun_path` from the child's memory and validates against a deny list (Phase: Interception) — tested
* R5: 🔄 TOCTOU is mitigated -- the supervisor emulates the syscall using its own copy of the address, not the child's memory (Phase: Interception) — verified structurally safe
* R6: 🔄 Denied socket paths are configurable via profiles or policy (Phase: Policy) — `deny.sockets` key + `add_deny_sockets` in external profiles. Manually verified with custom profile.
* R7: 🔄 Default policy blocks known-dangerous sockets (SSH agent, Docker, D-Bus) when sandbox is active (Phase: Policy) — Docker + D-Bus in defaults. SSH agent configurable via external profile `add_deny_sockets`.

#### Out of Scope
* macOS Seatbelt changes (already handled via network-outbound deny)
* Abstract unix sockets (Landlock `SCOPE_ABSTRACT_UNIX_SOCKET` covers these)
* BPF-based approaches (require elevated privileges)

## Phases

### 🔄 01 Phase: Interception
[01-interception](01-interception.md)

Add `connect()` and `sendmsg()` syscall interception to the seccomp supervisor. Read
`sockaddr_un.sun_path` from child memory, validate against deny list, emulate allowed calls
via fd injection.

### 🔄 02 Phase: Policy
[02-policy](02-policy.md)

Policy model, default deny rules, supervisor wiring, proxy filter consolidation (PR #503
integration), sendmsg deadlock fix, external profile `add_deny_sockets`, symlink-aware matching.

## Files

- **crates/nono/src/sandbox/linux.rs**: BPF filter, seccomp primitives. Socket syscall interception, sockaddr reading, pidfd wrappers, connect emulation. Step 5: shrunk notify filter to openat/openat2 only. (Phase: Interception, Policy)
- **crates/nono/src/sandbox/mod.rs**: Re-exports. (Phase: Interception)
- **crates/nono-cli/src/exec_strategy/supervisor_linux.rs**: Notification handlers. AF_UNIX deny in `handle_network_notification`. Step 8: symlink-aware path matching. (Phase: Interception, Policy)
- **crates/nono-cli/src/exec_strategy.rs**: SupervisorConfig, ExecConfig. Step 5: simplified dumpable guard. Step 6: pipe+pidfd proxy fd transfer, child_keep_fds fix. (Phase: Interception, Policy)
- **crates/nono-cli/src/main.rs**: Strategy selection, proxy_fallback computation, denied_socket_paths wiring. (Phase: Policy)
- **crates/nono-cli/src/policy.rs**: deny.sockets in DenyOps, resolve_socket_paths_for_groups(). (Phase: Policy)
- **crates/nono-cli/data/policy.json**: deny_socket_paths_linux group (Docker, D-Bus). (Phase: Policy)
- **crates/nono-cli/src/output.rs**: Denied socket paths in dry-run output. (Phase: Policy)
- **crates/nono-cli/src/profile/mod.rs**: `add_deny_sockets` in PolicyPatchConfig. (Phase: Policy)
- **crates/nono-cli/src/profile/builtin.rs**: Updated test snapshot. (Phase: Policy)
- **crates/nono-cli/src/policy_cmd.rs**: `add_deny_sockets` display in policy show. (Phase: Policy)
