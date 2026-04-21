# Phase: Interception

## Context

See [00-unix-socket-sandboxing](00-unix-socket-sandboxing.md).

Add `connect()`, `sendmsg()`, and `sendto()` syscall interception to the existing seccomp user
notification supervisor. The supervisor already intercepts `openat()`/`openat2()` via
`SECCOMP_RET_USER_NOTIF`, reads paths from child memory, and injects fds via
`SECCOMP_ADDFD_FLAG_SEND`. This phase extends that pattern to AF_UNIX socket operations.

**Key architectural difference from openat():** `openat()` returns a new fd (emulated via ADDFD
injection). `connect()` modifies an existing socket's state — emulation requires `pidfd_getfd()`
to get a supervisor-side dup of the child's socket fd, call `connect()` on it (modifying the shared
kernel socket object), then respond with the result. For `sendmsg()`/`sendto()`, denied paths get
EPERM; allowed paths use `continue_notif()` (consistent with existing openat fast-path TOCTOU
posture).

## Questions

- [x] Can connect() be emulated via ADDFD like openat()? **No** — connect() modifies socket state,
  doesn't return a new fd. Use pidfd_getfd() (kernel 5.6+, already covered by 5.14+ requirement).
- [x] Should sendmsg() be fully emulated? **No** — copying iovec buffers through supervisor is
  impractical. Validate path + continue_notif() for allowed paths. Denied paths get EPERM
  immediately (no TOCTOU concern for denials).
- [x] How to determine if a socket is AF_UNIX without reading sockaddr? **Read the first 2 bytes**
  of the sockaddr struct (sa_family field) from child memory. If not AF_UNIX, continue_notif().
- [x] Is sendto/sendmsg TOCTOU for allowed paths acceptable? **Yes** — consistent with existing
  openat fast-path. Full emulation impractical (iovec buffer copying). Documented in code comment.
  Deny-list check is the security boundary.
- [x] Should non-UTF-8 sun_path be supported? **No for now** — fail-closed (deny). Non-UTF-8
  socket paths are extremely rare. Can revisit with OsString if needed.

## Tasks

### Step 1: Library primitives (linux.rs)

- [x] Add arch-specific syscall number constants: `SYS_CONNECT` (x86_64: 42, aarch64: 203), `SYS_SENDTO` (x86_64: 44, aarch64: 206), `SYS_SENDMSG` (x86_64: 46, aarch64: 211) (R1, R2)
- [x] Extend BPF filter in `install_seccomp_notify()` with JEQ instructions for the three new syscalls routing to SECCOMP_RET_USER_NOTIF (R1, R2)
- [x] Add `read_sockaddr_un()`: read `struct sockaddr_un` from child memory via `/proc/PID/mem` — reads sa_family + sun_path, returns `SockaddrUn { family, path, is_abstract }` (R4)
- [x] Add `read_msghdr_dest()`: for sendmsg, read `struct msghdr` from child memory to extract `msg_name` pointer + `msg_namelen`, then read sockaddr_un from msg_name — double indirection (R4)
- [x] Add `pidfd_open()` wrapper: `libc::syscall(SYS_pidfd_open, pid, 0)` → OwnedFd
- [x] Add `pidfd_getfd()` wrapper: `libc::syscall(SYS_pidfd_getfd, pidfd, targetfd, 0)` → OwnedFd
- [x] Add `emulate_connect()`: pidfd_open + pidfd_getfd(child_sockfd) → connect(dup_fd, &validated_addr) → respond with result (R5)
- [x] Add `respond_notif_success()`: respond with val=return_value, error=0 (connect returns 0, sendto returns bytes sent)
- [x] Unit test: BPF filter jump targets verified for all 5 syscalls (test_bpf_filter_jump_targets)
- [x] Unit tests: sockaddr_un struct, reject too-small addrlen, pidfd syscall numbers, UNIX_PATH_MAX constant

### Step 2: Handler dispatch (supervisor_linux.rs)

- [x] Add early dispatch in `handle_seccomp_notification()` for SYS_CONNECT, SYS_SENDMSG, SYS_SENDTO → routes to `handle_socket_notification()` (R1, R2)
- [x] Implement `handle_socket_notification()`:
  1. Extract sockaddr per syscall type (connect/sendto use args directly, sendmsg uses read_msghdr_dest)
  2. Non-AF_UNIX → continue_notif() (R3); abstract sockets → continue_notif()
  3. Canonicalize sun_path, TOCTOU check
  4. Check against denied_socket_paths list (exact + prefix match)
  5. Denied → deny_notif() with EPERM (R1, R2)
  6. Allowed connect() → emulate_connect() via pidfd_getfd (R5)
  7. Allowed sendto/sendmsg → continue_notif() (R3)
- [x] Wire denied socket paths into SupervisorConfig (new field: `denied_socket_paths: &[PathBuf]`, cfg(linux))
- [x] Integration test: create test unix socket listener, spawn sandboxed child, verify connect to denied path returns EPERM (requires out-of-sandbox execution)
- [x] Integration test: verify connect to non-denied unix socket succeeds (requires out-of-sandbox execution)
- [x] Integration test: verify AF_INET connect passes through without interception (R3) (requires out-of-sandbox execution)

### Step 3: Verify and harden

- [x] Test sendmsg to denied SOCK_DGRAM unix socket returns EPERM
- [x] Test sendto to denied SOCK_DGRAM unix socket returns EPERM
- [x] Verify TOCTOU: connect emulation uses supervisor's copy of address, not child memory (code-review verified + comment in supervisor_linux.rs)
- [x] Verify error propagation: if connect() fails (ECONNREFUSED etc), child sees correct errno
- [x] Verify non-blocking behavior: if child socket is non-blocking, connect emulation preserves semantics

## Files

- **crates/nono/src/sandbox/linux.rs**: +515 lines. BPF filter extended (5→8 instructions), new: SockaddrUn, MsghdrPrefix, read_sockaddr_un(), read_msghdr_dest(), pidfd_open(), pidfd_getfd(), emulate_connect(), respond_notif_success(), SYS_CONNECT/SENDTO/SENDMSG constants. Tests updated. Phase 1 tests: added read_sockaddr_un unit tests using self-memory reads (5 new tests).
- **crates/nono/src/sandbox/mod.rs**: Re-exports for all new symbols.
- **crates/nono-cli/src/exec_strategy/supervisor_linux.rs**: +165 lines (Phase 1). Phase 1 tests: added integration tests using fork+seccomp+socketpair (8 new tests covering Steps 2 and 3).
- **crates/nono-cli/src/exec_strategy.rs**: Added `denied_socket_paths` field to SupervisorConfig (cfg(linux)).
- **crates/nono-cli/src/main.rs**: Wire denied_socket_paths: &[] (TODO for Phase 2).
