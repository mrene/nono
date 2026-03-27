# Phase: Policy

## Context

See [00-unix-socket-sandboxing](00-unix-socket-sandboxing.md).

Define how denied unix socket paths are configured and provide secure defaults. The interception
mechanism from Phase 1 needs a deny list to check against — this phase determines where that list
comes from and what it contains by default.

## Questions

- [x] Should denied sockets reuse `deny.access` paths, get a new `deny.sockets` key, or both?
  → New `deny.sockets` key. `deny.access` paths cannot overlap allowed paths on Linux (Landlock
  constraint), but socket paths like `/run/docker.sock` are under the broadly-allowed `/run`.
  `deny.sockets` bypasses Landlock overlap validation since enforcement is via seccomp, not Landlock.
- [x] Should the deny list support glob/prefix patterns (e.g., `/run/user/*/wezterm/`) or exact paths only?
  → Exact + prefix matching (already implemented in supervisor handler via `starts_with`). No globs.
- [x] How should `$SSH_AUTH_SOCK` be resolved at sandbox setup time?
  → Not resolved. Profile authors write actual known paths. No env var resolution.

## Tasks

### Step 1: Policy model decision

- [x] Research existing deny.access implementation in policy.rs to understand current deny path handling
- [x] Decide: extend deny.access vs new deny.sockets key — present options to user with trade-offs (R6)
- [x] Decide: exact paths vs prefix/glob matching — present options to user

### Step 2: Default deny entries

- [x] Add default deny entries to policy.json for known-dangerous sockets (R7):
  - Docker: `/run/docker.sock`, `/var/run/docker.sock`
  - D-Bus system bus: `/run/dbus/system_bus_socket`
  - SSH agent: omitted (no env vars; common paths are in /tmp which is broadly allowed)
- [x] New `deny.sockets` key added to DenyOps in policy.rs — bypasses Landlock overlap validation
- [x] Test: default profile includes socket deny entries (test_default_profile_group_set_is_explicit updated)

### Step 3: Wire into supervisor

- [x] Add `socket_paths: Vec<PathBuf>` to `ResolvedGroups` in policy.rs
- [x] Add `resolve_socket_paths_for_groups()` function in policy.rs
- [x] Add `denied_socket_paths` field to `PreparedSandbox` and `ExecutionFlags` in main.rs
- [x] Pass resolved socket paths to `SupervisorConfig.denied_socket_paths` (replaced `&[]`)
- [x] Tests pass: policy loads, socket paths flow to supervisor

### Step 4: UX

- [x] Updated `print_capabilities()` signature to accept `denied_socket_paths: &[PathBuf]`
- [x] Denied socket paths shown in capability summary with `sock` badge
- [ ] Update diagnostic footer to mention socket denial when relevant
  (deferred: DenialRecord is file-access oriented; socket denials use a separate seccomp path
  that doesn't feed into the denials vec — non-trivial API change)

### Step 5: Consolidate socket interception into proxy filter

After PR #503 (seccomp proxy-only network fallback) merged, there are two seccomp-notify filters
that can both intercept `connect()`. The notify filter (openat + socket syscalls) and the proxy
filter (connect/bind + optionally sendto/sendmsg) conflict due to LIFO stacking — proxy wins.
Refactor: all socket/network interception lives in the proxy filter; notify filter returns to
openat/openat2 only.

- [x] Expand `seccomp_proxy_fallback` in main.rs to also be true when `!denied_socket_paths.is_empty()` (R6)
- [x] Remove `denied_socket_paths` param from `select_exec_strategy` — socket deny folds into `proxy_active_or_socket_deny` (R6)
- [x] Update all `select_exec_strategy` tests (remove 5th param, remove dedicated test)
- [x] Shrink `install_seccomp_notify` BPF filter to openat/openat2 only (5 instructions) — remove connect/sendto/sendmsg
- [x] Revert seccomp-notify install condition to just `capability_elevation`
- [x] Update `test_bpf_filter_jump_targets` for 5-instruction filter
- [x] Simplify dumpable guard: remove `!denied_socket_paths.is_empty()` — covered by `seccomp_proxy_fallback`
- [x] Remove `handle_socket_notification` and its dispatch from `handle_seccomp_notification` — dead code
- [x] Migrate `run_socket_interception_test` helper to use `install_seccomp_proxy_filter` + `handle_network_notification`
  - Used `pidfd_open`+`pidfd_getfd` instead of `send_fd`/`recv_fd` to avoid sendmsg deadlock when `has_denied_sockets=true`
- [x] Verify all 7 integration tests pass with proxy filter path
- [x] `make ci` passes (build + clippy + fmt + tests; cargo-audit not installed)
- [x] Manual test: `nono run -- curl --unix-socket /run/docker.sock ...` → EPERM (Docker denied)

### Step 6: Fix proxy fd sendmsg deadlock

When `has_denied_sockets=true`, the proxy filter intercepts `sendmsg`. But `execute_supervised()`
uses `sendmsg(SCM_RIGHTS)` to transfer the proxy notify fd from child to parent — deadlock.
Fix: use pipe + `pidfd_getfd` (same pattern as `run_socket_interception_test` helper).

- [x] Before fork: create `proxy_fd_pipe` via `pipe2(O_CLOEXEC)`, conditional on `seccomp_proxy_fallback`
- [x] Child: after `install_seccomp_proxy_filter()`, write `proxy_notify_fd.as_raw_fd()` as i32 to pipe. Remove `send_fd` call.
- [x] Parent: read i32 from pipe, `pidfd_open(child_pid)` + `pidfd_getfd(pidfd, child_fd)` → OwnedFd. Remove `recv_fd` call.
- [x] `make ci` passes
- [x] Manual test: `nono run -- curl --unix-socket /run/docker.sock ...` → EPERM (Docker denied)

### Step 7: Add `add_deny_sockets` to ProfilePatchConfig

External profiles cannot define custom groups — they can only reference built-in ones. Add
`add_deny_sockets` field to `PolicyPatchConfig` (same pattern as `add_deny_access`) so external
profiles can deny additional socket paths via `"policy": { "add_deny_sockets": [...] }`.

- [x] Add `add_deny_sockets: Vec<String>` to `PolicyPatchConfig` in `profile/mod.rs`
- [x] Add merge logic in `merge_profiles()` (extend vec)
- [x] Process in `main.rs` `prepare_sandbox()`: after `resolve_socket_paths_for_groups`, expand vars + append to socket_paths
- [x] Add display in `policy_cmd.rs` (same pattern as `add_deny_access`)
- [x] Update `test-deny-sockets.json` to use `policy.add_deny_sockets`
- [x] `make ci` passes
- [x] Manual test: `nono run --profile ./test-deny-sockets.json -- ssh-add -L` → EPERM (wezterm agent denied)

### Step 8: Fix symlink-aware socket path matching

Socket files can be symlinks (e.g. wezterm `agent.4825` → `/run/user/1000/gcr/ssh`).
`canonicalize()` follows symlinks, so the resolved path no longer matches the deny prefix.
Fix: check both raw (pre-symlink) and canonical (post-symlink) paths against the deny list.

- [x] Check both raw and canonical socket paths in `handle_network_notification` deny matching
- [x] `make ci` passes
- [x] Manual test: `nono run --profile ./test-deny-sockets.json -- ssh-add -L` → "Error connecting to agent: Operation not permitted"

## Files

- **crates/nono-cli/src/policy.rs**: Added `deny.sockets` to DenyOps, `socket_paths` to ResolvedGroups, `add_deny_socket_rules()`, `resolve_socket_paths_for_groups()`.
- **crates/nono-cli/data/policy.json**: Added `deny_socket_paths_linux` group with Docker and D-Bus socket paths; added to default profile.
- **crates/nono-cli/src/output.rs**: Updated `print_capabilities()` to show denied socket paths.
- **crates/nono-cli/src/main.rs**: Wired `socket_paths` through `PreparedSandbox`, `ExecutionFlags`, into `SupervisorConfig.denied_socket_paths`. Step 5: expanded `seccomp_proxy_fallback` to also be true when denied_socket_paths non-empty; removed `denied_socket_paths` param from `select_exec_strategy`; added `proxy_active_or_socket_deny` for Supervised strategy trigger.
- **crates/nono-cli/src/profile/builtin.rs**: Updated `test_default_profile_group_set_is_explicit` snapshot.
- **crates/nono/src/sandbox/linux.rs**: Step 5: shrunk `install_seccomp_notify` BPF filter to 5 instructions (openat/openat2 only); updated `test_bpf_filter_jump_targets`.
- **crates/nono-cli/src/exec_strategy.rs**: Step 5: reverted notify install condition to `capability_elevation` only; simplified dumpable guard. Step 6: replaced sendmsg(SCM_RIGHTS) proxy fd transfer with pipe+pidfd_getfd; added child_keep_fds.push for proxy notify fd.
- **crates/nono-cli/src/exec_strategy/supervisor_linux.rs**: Step 5: removed `handle_socket_notification`, migrated tests to proxy filter path. Step 8: symlink-aware socket path matching (check both raw and canonical paths against deny list).
- **crates/nono-cli/src/profile/mod.rs**: Step 7: added `add_deny_sockets` to `PolicyPatchConfig`, merge logic in `merge_profiles()`.
- **crates/nono-cli/src/policy_cmd.rs**: Step 7: added `add_deny_sockets` display in policy show output.
