//! Linux seccomp-notify supervisor boundary.
//!
//! Threat model:
//! - The child process is sandboxed but untrusted.
//! - All seccomp notifications must be fail-closed on parse/validation errors.
//! - Path opens performed by the supervisor must re-validate policy boundaries.
//! - Security boundary: the supervisor's `open_path_for_access()` + `inject_fd()`
//!   is authoritative. `notif_id_valid()` only proves notification liveness.
//! - Instruction files undergo trust verification with TOCTOU protection via
//!   digest re-check at fd open time.

use super::*;
use crate::trust_intercept::TrustInterceptor;
use nono::AccessMode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InitialCapability {
    pub(super) path: std::path::PathBuf,
    pub(super) access: AccessMode,
    pub(super) is_file: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitialCapabilityMatch<'a> {
    Sufficient(&'a InitialCapability),
    Insufficient(&'a InitialCapability),
    None,
}

/// Token-bucket rate limiter for supervisor expansion requests.
///
/// Prevents a compromised agent from flooding the terminal with approval prompts.
/// Defaults to 10 requests/second with a burst of 5.
pub(super) struct RateLimiter {
    /// Maximum tokens (burst capacity)
    capacity: u32,
    /// Current available tokens
    tokens: u32,
    /// Tokens added per second
    rate: u32,
    /// Last token refill time
    last_refill: std::time::Instant,
}

impl RateLimiter {
    pub(super) fn new(rate: u32, burst: u32) -> Self {
        Self {
            capacity: burst,
            tokens: burst,
            rate,
            last_refill: std::time::Instant::now(),
        }
    }

    /// Try to consume one token. Returns true if allowed, false if rate limited.
    pub(super) fn try_acquire(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill);

        // Refill tokens based on elapsed time
        let new_tokens = (elapsed.as_millis() as u64)
            .saturating_mul(self.rate as u64)
            .saturating_div(1000);
        if new_tokens > 0 {
            self.tokens = self.capacity.min(
                self.tokens
                    .saturating_add(u32::try_from(new_tokens).unwrap_or(u32::MAX)),
            );
            self.last_refill = now;
        }

        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// Read the TGID (thread group ID / process ID) of a thread from /proc/<tid>/status.
///
/// `seccomp_data.pid` is the TID of the requesting thread, not the TGID. `/proc/self`
/// is a symlink to `/proc/<tgid>`, so for correct procfs self-resolution we need the TGID.
/// This matters when a grandchild process (e.g. nono→sh→bun) makes an openat syscall:
/// `notif.pid` is bun's TID, not sh's PID, so we must look up bun's TGID to resolve
/// `/proc/self/maps` to `/proc/<bun_tgid>/maps` instead of `/proc/<sh_pid>/maps`.
///
/// Runs in the unsandboxed supervisor context. Falls back to `tid` if the status file
/// cannot be read (process already exited; the subsequent TOCTOU check will reject it).
fn read_tgid(tid: u32) -> u32 {
    std::fs::read_to_string(format!("/proc/{}/status", tid))
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Tgid:\t"))
                .and_then(|l| l["Tgid:\t".len()..].trim().parse::<u32>().ok())
        })
        .unwrap_or(tid)
}

/// Handle a seccomp notification on Linux.
///
/// Flow:
/// 1. Receive notification (blocking recv from kernel)
/// 2. Read path from child's /proc/PID/mem
/// 3. TOCTOU check: verify notification still valid
/// 4. Check protected nono state roots -> deny (BEFORE initial-set fast-path)
/// 5. Fast-path: if path is in initial set, open + inject fd immediately
/// 6. Rate limit check -> deny if exceeded
/// 7. Trust verification for instruction files (if trust_interceptor present)
/// 8. Delegate to approval backend
/// 9. Second TOCTOU check before inject/deny
/// 10. If approved: open path + inject fd (with TOCTOU digest re-check for
///     instruction files). If denied: deny notification.
///
/// TOCTOU boundary note:
/// - The child controls userspace pointers until syscall completion.
/// - We treat notification ID validation as a liveness guard only.
/// - Authorization is bound to the file descriptor opened by the supervisor.
/// - Instruction files undergo additional TOCTOU protection: the verified
///   digest is re-checked against the opened fd to detect races between
///   trust verification and file open.
///
/// The initial_caps parameter contains the static capabilities applied to the
/// sandbox, allowing the supervisor to distinguish "path not granted" from
/// "path granted, but only with a narrower access mode".
pub(super) fn handle_seccomp_notification(
    notify_fd: std::os::fd::RawFd,
    child: Pid,
    config: &SupervisorConfig<'_>,
    initial_caps: &[InitialCapability],
    rate_limiter: &mut RateLimiter,
    denials: &mut Vec<DenialRecord>,
    mut trust_interceptor: Option<&mut TrustInterceptor>,
) -> Result<()> {
    use nono::sandbox::{
        classify_access_from_flags, continue_notif, deny_notif, inject_fd, notif_id_valid,
        read_notif_path, read_open_how, recv_notif, resolve_notif_path, respond_notif_errno,
        validate_openat2_size, SYS_OPENAT, SYS_OPENAT2,
    };

    // 1. Receive the notification
    let notif = recv_notif(notify_fd)?;

    // 2. Read the path from the child's memory (args[1] = pathname for openat/openat2)
    //    Then resolve dirfd-relative paths using /proc/PID/fd/DIRFD or /proc/PID/cwd.
    let path = match read_notif_path(notif.pid, notif.data.args[1]) {
        Ok(raw_path) => {
            // args[0] is dirfd for both openat and openat2
            match resolve_notif_path(notif.pid, notif.data.args[0], &raw_path) {
                Ok(resolved) => resolved,
                Err(e) => {
                    debug!(
                        "Failed to resolve dirfd-relative path '{}': {}",
                        raw_path.display(),
                        e
                    );
                    let _ = deny_notif(notify_fd, notif.id);
                    return Ok(());
                }
            }
        }
        Err(e) => {
            debug!("Failed to read path from seccomp notification: {}", e);
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }
    };

    // 3. First TOCTOU check: verify notification still valid
    if !notif_id_valid(notify_fd, notif.id)? {
        debug!("Seccomp notification expired (first TOCTOU check)");
        return Ok(());
    }

    // Determine access mode from open flags. The two syscalls have different layouts:
    //   - openat(dirfd, pathname, flags, mode): args[2] is the flags integer
    //   - openat2(dirfd, pathname, how, size): args[2] is a pointer to struct open_how
    let access = match notif.data.nr {
        SYS_OPENAT => {
            // openat: args[2] is the flags integer directly
            classify_access_from_flags(notif.data.args[2] as i32)
        }
        SYS_OPENAT2 => {
            // openat2: args[2] is a pointer to struct open_how, args[3] is the size
            let how_size = notif.data.args[3] as usize;
            if !validate_openat2_size(how_size) {
                debug!(
                    "openat2 size {} outside accepted range, denying malformed request",
                    how_size
                );
                let _ = deny_notif(notify_fd, notif.id);
                return Ok(());
            }

            match read_open_how(notif.pid, notif.data.args[2]) {
                Ok(open_how) => classify_access_from_flags(open_how.flags as i32),
                Err(e) => {
                    // Fail closed: deny when flags cannot be determined
                    warn!("Failed to read open_how struct for openat2, denying: {}", e);
                    let _ = deny_notif(notify_fd, notif.id);
                    return Ok(());
                }
            }
        }
        other => {
            // Unexpected syscall (shouldn't happen with our BPF filter)
            warn!("Unexpected syscall {} in seccomp handler, denying", other);
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }
    };

    // Use the requesting process's TGID (not TID) as process_pid so that /proc/self
    // resolves to /proc/<tgid>/... for grandchild processes (e.g. nono→sh→bun).
    // notif.pid is the TID; for single-threaded processes TID==TGID, but for
    // multithreaded or grandchild processes we need the actual process leader PID.
    let child_pid = child.as_raw() as u32;
    let notifying_tgid = if notif.pid == child_pid {
        child_pid
    } else {
        read_tgid(notif.pid)
    };
    let procfs_context = ProcfsAccessContext::new(notifying_tgid, Some(notif.pid));
    let resolved_path = match resolve_procfs_path_for_child(&path, Some(procfs_context)) {
        Ok(resolved) => resolved,
        Err(e) => {
            debug!("Failed to resolve procfs path '{}': {}", path.display(), e);
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }
    };
    let canonicalized =
        std::fs::canonicalize(&resolved_path).unwrap_or_else(|_| resolved_path.clone());

    // For the initial capability match, map a grandchild's /proc/<tgid> path back to the
    // direct child's /proc/<child_pid>, because initial_caps are built from the direct
    // child's /proc/self remapping (remap_procfs_self_references uses child.as_raw()).
    // Any descendant process should benefit from the same proc-self read policy.
    //
    // Security note: this substitution only affects the policy LOOKUP KEY. The actual file
    // opened by open_path_for_access continues to use `procfs_context` with notifying_tgid,
    // so the correct /proc/<notifying_tgid>/... file is opened. validate_procfs_access also
    // uses notifying_tgid as allowed_pid, blocking cross-process procfs reads.
    let cap_check_path: std::borrow::Cow<std::path::Path> = if notifying_tgid != child_pid {
        let notifying_prefix = format!("/proc/{}", notifying_tgid);
        if let Ok(rel) = canonicalized.strip_prefix(&notifying_prefix) {
            let mut p = std::path::PathBuf::from(format!("/proc/{}", child_pid));
            p.push(rel);
            std::borrow::Cow::Owned(p)
        } else {
            std::borrow::Cow::Borrowed(canonicalized.as_path())
        }
    } else {
        std::borrow::Cow::Borrowed(canonicalized.as_path())
    };

    // 4. Check protected roots BEFORE initial-set fast-path.
    let protected_root = crate::protected_paths::overlapping_protected_root(
        &canonicalized,
        false,
        config.protected_roots,
    )
    .or_else(|| {
        crate::protected_paths::overlapping_protected_root(
            &resolved_path,
            false,
            config.protected_roots,
        )
    });
    if let Some(protected_root) = protected_root {
        debug!(
            "Seccomp: path {} blocked by protected root {}",
            canonicalized.display(),
            protected_root.display()
        );
        record_denial(
            denials,
            DenialRecord {
                path: canonicalized.clone(),
                access,
                reason: DenialReason::PolicyBlocked,
            },
        );
        let _ = deny_notif(notify_fd, notif.id);
        return Ok(());
    }

    // 5. Fast-path: if the path is covered by the initial capability set and
    // the requested access mode is already granted, proceed immediately. If the
    // path matches but only with narrower access, record the denial here so the
    // footer can explain the near-miss precisely.
    match match_initial_capability(&cap_check_path, access, initial_caps) {
        InitialCapabilityMatch::Insufficient(cap) => {
            debug!(
                "Seccomp: path {} matched initial capability {} but {} access was requested",
                canonicalized.display(),
                cap.path.display(),
                access,
            );
            record_denial(
                denials,
                DenialRecord {
                    path: canonicalized.clone(),
                    access,
                    reason: DenialReason::InsufficientAccess,
                },
            );
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }
        InitialCapabilityMatch::Sufficient(_) => {
            if canonicalized.starts_with("/proc") {
                match open_path_for_access(
                    &path,
                    &access,
                    config.protected_roots,
                    None,
                    Some(procfs_context),
                ) {
                    Ok(file) => {
                        if notif_id_valid(notify_fd, notif.id)? {
                            if let Err(e) = inject_fd(notify_fd, notif.id, file.as_raw_fd()) {
                                debug!(
                                    "inject_fd failed for initial-set proc path {}: {}",
                                    path.display(),
                                    e
                                );
                                let _ = deny_notif(notify_fd, notif.id);
                            }
                        }
                    }
                    Err(e) => {
                        debug!(
                            "Failed to open initial-set proc path {}: {}",
                            path.display(),
                            e
                        );
                        if e.is_policy_blocked() {
                            record_denial(
                                denials,
                                DenialRecord {
                                    path: canonicalized.clone(),
                                    access,
                                    reason: DenialReason::PolicyBlocked,
                                },
                            );
                            let _ = deny_notif(notify_fd, notif.id);
                        } else {
                            let _ = respond_notif_errno(notify_fd, notif.id, e.errno());
                        }
                    }
                }
            } else if notif_id_valid(notify_fd, notif.id)? {
                if let Err(e) = continue_notif(notify_fd, notif.id) {
                    debug!(
                        "continue_notif failed for initial-set path {}: {}",
                        path.display(),
                        e
                    );
                    let _ = deny_notif(notify_fd, notif.id);
                }
            }
            return Ok(());
        }
        InitialCapabilityMatch::None => {}
    }

    // Preserve native ENOENT/ENOTDIR behavior for nonexistent paths. Runtimes
    // frequently probe optional locations (e.g. Bun's /$bunfs assets) and
    // expect a normal "not found" result rather than a policy denial. This is
    // safe because Landlock will still block any path that appears after the
    // check but remains outside the initial allow-list.
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                || e.raw_os_error() == Some(libc::ENOTDIR) =>
        {
            if notif_id_valid(notify_fd, notif.id)? {
                if let Err(send_err) = continue_notif(notify_fd, notif.id) {
                    debug!(
                        "continue_notif failed for missing path {}: {}",
                        path.display(),
                        send_err
                    );
                    let _ = deny_notif(notify_fd, notif.id);
                }
            }
            return Ok(());
        }
        Err(_) => {}
    }

    // 6. Rate limit check
    if !rate_limiter.try_acquire() {
        debug!("Rate limited seccomp notification for {}", path.display());
        record_denial(
            denials,
            DenialRecord {
                path: path.clone(),
                access,
                reason: DenialReason::RateLimited,
            },
        );
        let _ = deny_notif(notify_fd, notif.id);
        return Ok(());
    }

    // 7. Trust verification for instruction files (TOCTOU protection)
    // If the path is an instruction file, verify it and stash the digest
    // for re-verification at open time. Failed verification results in early denial.
    let verified_digest: Option<String> = if let Some(trust_result) = trust_interceptor
        .as_mut()
        .and_then(|ti| ti.check_path(&path))
    {
        match trust_result {
            Ok(verified) => {
                debug!(
                    "Seccomp: instruction file {} verified (publisher: {})",
                    path.display(),
                    verified.publisher,
                );
                Some(verified.digest)
            }
            Err(reason) => {
                // Instruction file failed trust verification — auto-deny
                debug!(
                    "Seccomp: instruction file {} failed trust verification: {}",
                    path.display(),
                    reason
                );
                record_denial(
                    denials,
                    DenialRecord {
                        path: path.clone(),
                        access,
                        reason: DenialReason::PolicyBlocked,
                    },
                );
                let _ = deny_notif(notify_fd, notif.id);
                return Ok(());
            }
        }
    } else {
        None
    };

    // 8. Delegate to approval backend (for both instruction and non-instruction files)
    let request = nono::supervisor::CapabilityRequest {
        request_id: format!("seccomp-{}", unique_request_id()),
        path: path.clone(),
        access,
        reason: Some("Sandbox intercepted file operation (seccomp-notify)".to_string()),
        child_pid: child.as_raw() as u32,
        session_id: config.session_id.to_string(),
    };

    let decision = match config.approval_backend.request_capability(&request) {
        Ok(d) => {
            if d.is_denied() {
                record_denial(
                    denials,
                    DenialRecord {
                        path: path.clone(),
                        access,
                        reason: DenialReason::UserDenied,
                    },
                );
            }
            d
        }
        Err(e) => {
            warn!("Approval backend error for seccomp notification: {}", e);
            record_denial(
                denials,
                DenialRecord {
                    path: path.clone(),
                    access,
                    reason: DenialReason::BackendError,
                },
            );
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }
    };

    // 9. Second TOCTOU check before acting on the decision
    if !notif_id_valid(notify_fd, notif.id)? {
        debug!("Seccomp notification expired (second TOCTOU check)");
        return Ok(());
    }

    // 10. Act on the decision
    // Pass verified_digest to enable TOCTOU re-verification for instruction files
    if decision.is_granted() {
        match open_path_for_access(
            &path,
            &access,
            config.protected_roots,
            verified_digest.as_deref(),
            Some(procfs_context),
        ) {
            Ok(file) => {
                if let Err(e) = inject_fd(notify_fd, notif.id, file.as_raw_fd()) {
                    debug!(
                        "inject_fd failed for approved path {}: {}",
                        canonicalized.display(),
                        e
                    );
                    let _ = deny_notif(notify_fd, notif.id);
                }
            }
            Err(e) => {
                warn!(
                    "Failed to open approved path {}: {}",
                    canonicalized.display(),
                    e
                );
                if e.is_policy_blocked() {
                    let _ = deny_notif(notify_fd, notif.id);
                } else {
                    let _ = respond_notif_errno(notify_fd, notif.id, e.errno());
                }
            }
        }
    } else {
        let _ = deny_notif(notify_fd, notif.id);
    }

    Ok(())
}

/// Handle a seccomp notification for connect(), bind(), sendto(), or sendmsg() syscalls.
///
/// This is the proxy-only fallback handler, used when the proxy filter is the top-most
/// seccomp filter (LIFO). Because `continue_notif()` does not cascade to lower filters,
/// this function must also enforce unix socket path deny rules when `denied_socket_paths`
/// is non-empty.
///
/// For AF_UNIX connect/sendto/sendmsg: check against denied_socket_paths.
///   - Denied → EPERM
///   - Allowed connect → emulate_connect (TOCTOU-safe)
///   - Allowed sendto/sendmsg → continue_notif
///   - Empty denied_socket_paths → continue_notif (unix sockets are local-only)
///
/// For AF_INET/AF_INET6 connect: allow only loopback + proxy port.
/// For bind: allow only ports in the bind_ports list.
/// For AF_INET/AF_INET6 sendto/sendmsg: continue_notif.
///
/// Uses SECCOMP_USER_NOTIF_FLAG_CONTINUE on approval for IPv4/IPv6 (safe because
/// the kernel has already copied sockaddr into kernel memory).
pub(super) fn handle_network_notification(
    notify_fd: std::os::fd::RawFd,
    config: &SupervisorConfig<'_>,
    rate_limiter: &mut RateLimiter,
) -> nono::error::Result<()> {
    use nono::sandbox::{
        continue_notif, deny_notif, emulate_connect, notif_id_valid, read_msghdr_dest,
        read_notif_sockaddr, read_sockaddr_un, recv_notif, respond_notif_errno, SYS_BIND,
        SYS_CONNECT, SYS_SENDMSG, SYS_SENDTO,
    };

    let notif = recv_notif(notify_fd)?;

    // Rate limit to prevent flooding
    if !rate_limiter.try_acquire() {
        debug!("Rate limited network seccomp notification, denying");
        let _ = deny_notif(notify_fd, notif.id);
        return Ok(());
    }

    // Read sockaddr from child's memory: args[1] = sockaddr*, args[2] = addrlen.
    // For sendmsg the sockaddr pointer is inside msghdr; read_notif_sockaddr handles
    // the common AF_INET/AF_INET6 case. AF_UNIX is handled separately below.
    let (addr_ptr, addrlen) = match notif.data.nr {
        SYS_CONNECT | SYS_BIND => (notif.data.args[1], notif.data.args[2]),
        SYS_SENDTO => (notif.data.args[4], notif.data.args[5]),
        SYS_SENDMSG => {
            // For sendmsg: family is read via msghdr. Use 0 as sentinel to skip
            // the generic sockaddr read and fall through to AF_UNIX handling below.
            (0, 0)
        }
        _ => (notif.data.args[1], notif.data.args[2]),
    };

    // For sendmsg, resolve the destination address via msghdr
    let family = if notif.data.nr == SYS_SENDMSG {
        match read_msghdr_dest(notif.pid, notif.data.args[1]) {
            Ok(Some(ref sa)) => sa.family,
            Ok(None) => {
                // No destination — connected socket, let through
                if notif_id_valid(notify_fd, notif.id)? {
                    let _ = continue_notif(notify_fd, notif.id);
                }
                return Ok(());
            }
            Err(e) => {
                debug!(
                    "Failed to read msghdr dest for sendmsg in proxy handler: {}",
                    e
                );
                let _ = deny_notif(notify_fd, notif.id);
                return Ok(());
            }
        }
    } else if addr_ptr != 0 {
        match read_notif_sockaddr(notif.pid, addr_ptr, addrlen) {
            Ok(info) => info.family,
            Err(e) => {
                debug!(
                    "Failed to read sockaddr from proxy seccomp notification: {}",
                    e
                );
                let _ = deny_notif(notify_fd, notif.id);
                return Ok(());
            }
        }
    } else {
        // sendto with NULL dest_addr → connected socket, let through
        if notif_id_valid(notify_fd, notif.id)? {
            let _ = continue_notif(notify_fd, notif.id);
        }
        return Ok(());
    };

    // AF_UNIX: enforce denied_socket_paths if configured; otherwise pass through.
    // The proxy filter is LIFO-first, so it must enforce socket deny here rather
    // than deferring to the seccomp_notify filter below.
    if family == libc::AF_UNIX as u16 {
        if config.denied_socket_paths.is_empty() {
            // No unix socket deny rules — let it through
            if notif_id_valid(notify_fd, notif.id)? {
                let _ = continue_notif(notify_fd, notif.id);
            }
            return Ok(());
        }

        // Read the AF_UNIX path from child memory
        let sockaddr_un = match notif.data.nr {
            SYS_CONNECT => {
                read_sockaddr_un(notif.pid, notif.data.args[1], notif.data.args[2] as u32)
            }
            SYS_SENDMSG => {
                match read_msghdr_dest(notif.pid, notif.data.args[1]) {
                    Ok(Some(sa)) => Ok(sa),
                    Ok(None) => {
                        // Connected socket, no path to check — let through
                        if notif_id_valid(notify_fd, notif.id)? {
                            let _ = continue_notif(notify_fd, notif.id);
                        }
                        return Ok(());
                    }
                    Err(e) => Err(e),
                }
            }
            _ => {
                // SYS_SENDTO: args[4]=dest_addr, args[5]=addrlen
                if notif.data.args[4] == 0 {
                    if notif_id_valid(notify_fd, notif.id)? {
                        let _ = continue_notif(notify_fd, notif.id);
                    }
                    return Ok(());
                }
                read_sockaddr_un(notif.pid, notif.data.args[4], notif.data.args[5] as u32)
            }
        };

        let sa = match sockaddr_un {
            Ok(sa) => sa,
            Err(e) => {
                debug!("Failed to read AF_UNIX sockaddr in proxy handler: {}", e);
                let _ = deny_notif(notify_fd, notif.id);
                return Ok(());
            }
        };

        // Abstract sockets are handled by Landlock SCOPE_ABSTRACT_UNIX_SOCKET
        if sa.is_abstract {
            if notif_id_valid(notify_fd, notif.id)? {
                let _ = continue_notif(notify_fd, notif.id);
            }
            return Ok(());
        }

        let raw_path = sa.path.clone();
        let canonical_path = std::fs::canonicalize(&raw_path).ok();

        // TOCTOU check
        if !notif_id_valid(notify_fd, notif.id)? {
            debug!("Network seccomp AF_UNIX notification expired (TOCTOU check)");
            return Ok(());
        }

        // Check both raw and canonical forms against the deny list.
        // Socket paths may be symlinks (e.g. wezterm agent.* -> /run/user/UID/gcr/ssh),
        // so the raw path matches the deny prefix while the canonical path differs.
        let is_denied = config.denied_socket_paths.iter().any(|denied| {
            let denied_canonical = std::fs::canonicalize(denied).unwrap_or_else(|_| denied.clone());
            // Check raw (pre-symlink) path
            raw_path == denied_canonical
                || raw_path.starts_with(&denied_canonical)
                || raw_path == *denied
                || raw_path.starts_with(denied)
                // Check canonical (post-symlink) path
                || canonical_path
                    .as_ref()
                    .is_some_and(|cp| *cp == denied_canonical || cp.starts_with(&denied_canonical))
        });

        if is_denied {
            debug!(
                "Proxy seccomp: unix socket {} blocked by deny list",
                raw_path.display()
            );
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }

        // Allowed: emulate connect for TOCTOU safety; continue for send syscalls
        match notif.data.nr {
            SYS_CONNECT => {
                emulate_connect(
                    notify_fd,
                    notif.id,
                    notif.pid,
                    notif.data.args[0] as i32,
                    &sa,
                )?;
            }
            _ => {
                if notif_id_valid(notify_fd, notif.id)? {
                    let _ = continue_notif(notify_fd, notif.id);
                }
            }
        }
        return Ok(());
    }

    // Non-AF_UNIX: sendto/sendmsg have no network-level restriction here
    if matches!(notif.data.nr, SYS_SENDTO | SYS_SENDMSG) {
        if notif_id_valid(notify_fd, notif.id)? {
            let _ = continue_notif(notify_fd, notif.id);
        }
        return Ok(());
    }

    // For AF_INET/AF_INET6 connect/bind: re-read sockaddr for port checking
    let sockaddr = match read_notif_sockaddr(notif.pid, addr_ptr, addrlen) {
        Ok(info) => info,
        Err(e) => {
            debug!("Failed to re-read sockaddr for proxy port check: {}", e);
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }
    };

    // TOCTOU check
    if !notif_id_valid(notify_fd, notif.id)? {
        debug!("Network seccomp notification expired (TOCTOU check)");
        return Ok(());
    }

    let allowed = match notif.data.nr {
        SYS_CONNECT => {
            // Allow connect only to loopback + proxy port
            let port_match = sockaddr.port == config.proxy_port;
            if sockaddr.is_loopback && port_match {
                debug!(
                    "Proxy seccomp: allowing connect to loopback:{}",
                    sockaddr.port
                );
                true
            } else {
                debug!(
                    "Proxy seccomp: denying connect to family={} port={} loopback={}",
                    sockaddr.family, sockaddr.port, sockaddr.is_loopback
                );
                false
            }
        }
        SYS_BIND => {
            // Allow bind only on configured bind ports
            let port_allowed = config.proxy_bind_ports.contains(&sockaddr.port);
            if port_allowed {
                debug!("Proxy seccomp: allowing bind on port {}", sockaddr.port);
                true
            } else {
                debug!(
                    "Proxy seccomp: denying bind on port {} (allowed: {:?})",
                    sockaddr.port, config.proxy_bind_ports
                );
                false
            }
        }
        other => {
            warn!(
                "Unexpected syscall {} in proxy seccomp handler, denying",
                other
            );
            false
        }
    };

    if allowed {
        // SECCOMP_USER_NOTIF_FLAG_CONTINUE: let the kernel proceed with its
        // already-copied sockaddr. Safe for connect/bind (move_addr_to_kernel).
        if let Err(e) = continue_notif(notify_fd, notif.id) {
            debug!("continue_notif failed for network notification: {}", e);
            // Must respond to avoid leaving the child blocked. Propagate if
            // deny also fails — the notification is orphaned.
            return deny_notif(notify_fd, notif.id);
        }
    } else {
        respond_notif_errno(notify_fd, notif.id, libc::EACCES)?;
    }

    Ok(())
}

/// Check if a path matches any capability in the initial set.
///
/// Prefers the most specific capability. If the path is covered but the
/// requested access mode is not granted, returns
/// `InitialCapabilityMatch::Insufficient`.
fn match_initial_capability<'a>(
    path: &std::path::Path,
    requested: AccessMode,
    initial_caps: &'a [InitialCapability],
) -> InitialCapabilityMatch<'a> {
    let mut best_covering: Option<&'a InitialCapability> = None;
    let mut best_sufficient: Option<&'a InitialCapability> = None;
    let mut best_covering_score = 0usize;
    let mut best_sufficient_score = 0usize;

    for cap in initial_caps {
        let covers = if cap.is_file {
            path == cap.path
        } else {
            path.starts_with(&cap.path)
        };

        if !covers {
            continue;
        }

        let score = cap.path.as_os_str().len();
        if score >= best_covering_score {
            best_covering = Some(cap);
            best_covering_score = score;
        }

        if cap.access.contains(requested) && score >= best_sufficient_score {
            best_sufficient = Some(cap);
            best_sufficient_score = score;
        }
    }

    if let Some(cap) = best_sufficient {
        InitialCapabilityMatch::Sufficient(cap)
    } else if let Some(cap) = best_covering {
        InitialCapabilityMatch::Insufficient(cap)
    } else {
        InitialCapabilityMatch::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // -----------------------------------------------------------------------
    // Helpers shared by integration tests
    // -----------------------------------------------------------------------

    struct TestApproveAll;
    impl ApprovalBackend for TestApproveAll {
        fn request_capability(
            &self,
            _req: &nono::supervisor::CapabilityRequest,
        ) -> nono::Result<ApprovalDecision> {
            Ok(ApprovalDecision::Granted)
        }
        fn backend_name(&self) -> &str {
            "test-approve-all"
        }
    }

    /// Build a `SupervisorConfig` for integration tests with the given denied socket paths.
    fn test_config<'a>(
        backend: &'a dyn ApprovalBackend,
        denied: &'a [PathBuf],
    ) -> SupervisorConfig<'a> {
        SupervisorConfig {
            protected_roots: &[],
            approval_backend: backend,
            session_id: "test",
            attach_initial_client: false,
            detach_sequence: None,
            open_url_origins: &[],
            open_url_allow_localhost: false,
            allow_launch_services_active: false,
            proxy_port: 0,
            proxy_bind_ports: vec![],
            denied_socket_paths: denied,
        }
    }

    /// Run one seccomp notification from the child through the proxy filter handler,
    /// then return the errno the child's syscall saw (0 = success).
    ///
    /// Uses `install_seccomp_proxy_filter` + `handle_network_notification` so that
    /// socket interception tests exercise the same code path used in production
    /// (the proxy filter is the single top-most seccomp filter, LIFO).
    ///
    /// # Arguments
    /// * `denied_paths` - paths to block in `denied_socket_paths`
    /// * `child_action` - closure run in the child after seccomp is installed.
    ///   It receives a pipe write-end and should write one i32 errno byte via
    ///   the pipe then call `libc::_exit(0)`.
    ///
    /// # Safety
    /// Uses raw `fork()`. Must only be called from a single-threaded test
    /// or a dedicated forked sub-process context.
    #[cfg(target_os = "linux")]
    fn run_socket_interception_test<F>(denied_paths: &[PathBuf], child_action: F) -> i32
    where
        F: FnOnce(i32) + 'static, // pipe write-end fd
    {
        use nono::sandbox::{install_seccomp_proxy_filter, pidfd_getfd, pidfd_open};

        let has_denied_sockets = !denied_paths.is_empty();

        // Pipe: child writes errno (i32) to report result; parent reads it.
        let mut result_pipe = [0_i32; 2];
        // SAFETY: pipe2 is safe to call with a valid array.
        let pipe_ret = unsafe { libc::pipe2(result_pipe.as_mut_ptr(), libc::O_CLOEXEC) };
        assert_eq!(pipe_ret, 0, "pipe2 failed");

        // Pipe: child writes the raw notify_fd number (i32) so the parent can
        // retrieve it via pidfd_getfd without using sendmsg (which would be
        // intercepted by the proxy filter when has_denied_sockets=true).
        let mut fd_pipe = [0_i32; 2];
        // SAFETY: pipe2 is safe to call with a valid array.
        let pipe_ret = unsafe { libc::pipe2(fd_pipe.as_mut_ptr(), libc::O_CLOEXEC) };
        assert_eq!(pipe_ret, 0, "fd_pipe2 failed");

        // Fork.
        // SAFETY: We are in a test helper. The child does minimal, safe work and calls _exit.
        let child_pid = unsafe { libc::fork() };
        assert!(child_pid >= 0, "fork failed");

        if child_pid == 0 {
            // ---- child ----
            unsafe { libc::close(result_pipe[0]) };
            unsafe { libc::close(fd_pipe[0]) };

            // Install proxy filter (no bind ports, denied_sockets based on test config).
            // This sets no_new_privs and installs the seccomp filter. After this,
            // sendmsg/sendto may be intercepted, so use a plain pipe to hand off the
            // notify_fd number to the parent (parent uses pidfd_getfd to duplicate it).
            let notify_fd = match install_seccomp_proxy_filter(false, has_denied_sockets) {
                Ok(fd) => fd,
                Err(e) => {
                    let msg = format!("install_seccomp_proxy_filter: {e}\n");
                    unsafe {
                        libc::write(2, msg.as_ptr().cast(), msg.len());
                        libc::_exit(1);
                    }
                }
            };

            // Write raw fd number to pipe — write() is not intercepted by proxy filter.
            let raw_fd: i32 = notify_fd.as_raw_fd();
            // SAFETY: fd_pipe[1] is a valid writable pipe end.
            let n = unsafe {
                libc::write(
                    fd_pipe[1],
                    (&raw_fd as *const i32).cast(),
                    std::mem::size_of::<i32>(),
                )
            };
            if n != std::mem::size_of::<i32>() as isize {
                unsafe { libc::_exit(2) };
            }
            unsafe { libc::close(fd_pipe[1]) };
            // Keep notify_fd alive until _exit — parent holds a dup via pidfd_getfd.
            std::mem::forget(notify_fd);

            // Run the test action (do the socket syscall, write errno, _exit).
            child_action(result_pipe[1]);

            // Should not reach here — child_action must call _exit.
            unsafe { libc::_exit(99) };
        }

        // ---- parent ----
        unsafe { libc::close(result_pipe[1]) };
        unsafe { libc::close(fd_pipe[1]) };

        // Read the raw notify_fd number from the child via the plain pipe.
        let mut raw_fd_buf = [0i32; 1];
        let n = unsafe {
            libc::read(
                fd_pipe[0],
                raw_fd_buf.as_mut_ptr().cast(),
                std::mem::size_of::<i32>(),
            )
        };
        unsafe { libc::close(fd_pipe[0]) };
        assert_eq!(
            n,
            std::mem::size_of::<i32>() as isize,
            "failed to read notify_fd from child pipe"
        );
        let child_notify_raw_fd = raw_fd_buf[0];

        // Use pidfd_open + pidfd_getfd to duplicate the child's notify_fd into
        // the parent without needing sendmsg/SCM_RIGHTS (which would be intercepted).
        let pidfd = pidfd_open(child_pid as u32).expect("pidfd_open failed");
        let notify_owned =
            pidfd_getfd(pidfd.as_raw_fd(), child_notify_raw_fd).expect("pidfd_getfd failed");

        let backend = TestApproveAll;
        let config = test_config(&backend, denied_paths);
        let mut rate_limiter = RateLimiter::new(100, 100);

        // Handle exactly one notification (the socket syscall from the child).
        handle_network_notification(notify_owned.as_raw_fd(), &config, &mut rate_limiter)
            .expect("handle_network_notification failed");

        // Wait for child to exit.
        let mut status = 0;
        unsafe { libc::waitpid(child_pid, &mut status, 0) };

        // Read errno from pipe.
        let mut errno_buf = [0i32; 1];
        let n = unsafe {
            libc::read(
                result_pipe[0],
                errno_buf.as_mut_ptr().cast(),
                std::mem::size_of::<i32>(),
            )
        };
        unsafe { libc::close(result_pipe[0]) };

        if n != std::mem::size_of::<i32>() as isize {
            // Child exited without writing (early failure, e.g. _exit(1))
            let exit_code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                -1
            };
            panic!("child did not write errno (exit code {})", exit_code);
        }

        errno_buf[0]
    }

    /// Write an i32 errno value to the pipe and call `_exit(0)`.
    ///
    /// # Safety
    /// Only safe to call after fork in the child process.
    #[cfg(target_os = "linux")]
    unsafe fn report_errno_and_exit(pipe_write: i32, errno_val: i32) -> ! {
        libc::write(
            pipe_write,
            (&errno_val as *const i32).cast(),
            std::mem::size_of::<i32>(),
        );
        libc::_exit(0);
    }

    // -----------------------------------------------------------------------
    // Integration tests: Step 2
    // -----------------------------------------------------------------------

    /// Connect to a denied unix socket path must return EPERM.
    // Requires a real Linux kernel outside any seccomp-sandboxed environment.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore]
    fn test_connect_to_denied_path_returns_eperm() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let sock_path = tmp.path().join("denied.sock");

        // Create a listener so the path exists and connect could succeed
        // if not blocked. This distinguishes EPERM from ECONNREFUSED.
        let listener = std::os::unix::net::UnixListener::bind(&sock_path).expect("bind listener");

        let denied = vec![sock_path.clone()];
        let sock_path_c = sock_path.clone();

        let errno_val = run_socket_interception_test(&denied, move |pipe_write| {
            // Create a SOCK_STREAM socket.
            // SAFETY: socket() returns a valid fd or -1.
            let sockfd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            if sockfd < 0 {
                unsafe { libc::_exit(3) };
            }

            // Build sockaddr_un.
            let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
            let path_bytes = sock_path_c.as_os_str().as_encoded_bytes();
            let copy_len = path_bytes.len().min(107);
            // SAFETY: copying path bytes into a zeroed sockaddr_un.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    path_bytes.as_ptr(),
                    addr.sun_path.as_mut_ptr().cast::<u8>(),
                    copy_len,
                );
            }
            let addrlen =
                (std::mem::size_of::<libc::sa_family_t>() + copy_len + 1) as libc::socklen_t;

            // SAFETY: connect() on a valid sockfd/addr.
            let ret = unsafe {
                libc::connect(
                    sockfd,
                    &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                    addrlen,
                )
            };
            let errno_val = if ret < 0 {
                // SAFETY: errno is valid after a failed syscall.
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            } else {
                0
            };
            // SAFETY: child cleanup.
            unsafe { report_errno_and_exit(pipe_write, errno_val) };
        });

        drop(listener); // let the listener go — test is over
        assert_eq!(
            errno_val,
            libc::EPERM,
            "expected EPERM for denied unix socket, got {}",
            errno_val
        );
    }

    /// Connect to an allowed unix socket path must succeed (errno 0).
    // Requires a real Linux kernel outside any seccomp-sandboxed environment.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore]
    fn test_connect_to_allowed_path_succeeds() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let sock_path = tmp.path().join("allowed.sock");

        // Create a listener so connect() actually succeeds.
        let listener = std::os::unix::net::UnixListener::bind(&sock_path).expect("bind listener");
        // Spawn acceptor thread so the listener doesn't block connect indefinitely.
        std::thread::spawn(move || {
            let _ = listener.accept();
        });

        let sock_path_c = sock_path.clone();
        // No denied paths — socket is allowed through.
        let errno_val = run_socket_interception_test(&[], move |pipe_write| {
            let sockfd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            if sockfd < 0 {
                unsafe { libc::_exit(3) };
            }

            let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
            let path_bytes = sock_path_c.as_os_str().as_encoded_bytes();
            let copy_len = path_bytes.len().min(107);
            unsafe {
                std::ptr::copy_nonoverlapping(
                    path_bytes.as_ptr(),
                    addr.sun_path.as_mut_ptr().cast::<u8>(),
                    copy_len,
                );
            }
            let addrlen =
                (std::mem::size_of::<libc::sa_family_t>() + copy_len + 1) as libc::socklen_t;

            let ret = unsafe {
                libc::connect(
                    sockfd,
                    &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                    addrlen,
                )
            };
            let errno_val = if ret < 0 {
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            } else {
                0
            };
            unsafe { report_errno_and_exit(pipe_write, errno_val) };
        });

        assert_eq!(
            errno_val, 0,
            "expected success (errno 0) for allowed unix socket, got {}",
            errno_val
        );
    }

    /// AF_INET connect must pass through without EPERM (R3: only AF_UNIX is intercepted).
    // Requires a real Linux kernel outside any seccomp-sandboxed environment.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore]
    fn test_af_inet_connect_passes_through() {
        // Use a path that would look like a denial if checked, but AF_INET should
        // never reach the unix-socket deny-list check.
        let dummy_denied = vec![PathBuf::from("/nonexistent/should-not-matter.sock")];

        let errno_val = run_socket_interception_test(&dummy_denied, move |pipe_write| {
            // Create a SOCK_STREAM AF_INET socket and try to connect to
            // 127.0.0.1:1 (port 1 is almost certainly not listening, so we
            // expect ECONNREFUSED — but NOT EPERM).
            let sockfd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if sockfd < 0 {
                unsafe { libc::_exit(3) };
            }

            let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_port = 1u16.to_be(); // port 1, big-endian
            addr.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]);

            let ret = unsafe {
                libc::connect(
                    sockfd,
                    &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            let errno_val = if ret < 0 {
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            } else {
                0
            };
            unsafe { report_errno_and_exit(pipe_write, errno_val) };
        });

        assert_ne!(
            errno_val,
            libc::EPERM,
            "AF_INET connect must not be blocked with EPERM (got EPERM)"
        );
        // ECONNREFUSED is the expected result for port 1.
        // We accept any errno except EPERM — the point is the supervisor didn't block it.
    }

    // -----------------------------------------------------------------------
    // Integration tests: Step 3 — sendmsg / sendto hardening
    // -----------------------------------------------------------------------

    /// sendto() to a denied SOCK_DGRAM unix socket path must return EPERM.
    // Requires a real Linux kernel outside any seccomp-sandboxed environment.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore]
    fn test_sendto_denied_dgram_unix_socket_returns_eperm() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let sock_path = tmp.path().join("dgram-denied.sock");

        // Create a bound DGRAM listener so sendto has a valid destination.
        let listener =
            std::os::unix::net::UnixDatagram::bind(&sock_path).expect("bind dgram listener");

        let denied = vec![sock_path.clone()];
        let sock_path_c = sock_path.clone();

        let errno_val = run_socket_interception_test(&denied, move |pipe_write| {
            let sockfd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
            if sockfd < 0 {
                unsafe { libc::_exit(3) };
            }

            let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
            let path_bytes = sock_path_c.as_os_str().as_encoded_bytes();
            let copy_len = path_bytes.len().min(107);
            unsafe {
                std::ptr::copy_nonoverlapping(
                    path_bytes.as_ptr(),
                    addr.sun_path.as_mut_ptr().cast::<u8>(),
                    copy_len,
                );
            }
            let addrlen =
                (std::mem::size_of::<libc::sa_family_t>() + copy_len + 1) as libc::socklen_t;

            let data = b"hello";
            let ret = unsafe {
                libc::sendto(
                    sockfd,
                    data.as_ptr().cast(),
                    data.len(),
                    0,
                    &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                    addrlen,
                )
            };
            let errno_val = if ret < 0 {
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            } else {
                0
            };
            unsafe { report_errno_and_exit(pipe_write, errno_val) };
        });

        drop(listener);
        assert_eq!(
            errno_val,
            libc::EPERM,
            "expected EPERM for sendto to denied unix socket, got {}",
            errno_val
        );
    }

    /// sendmsg() to a denied SOCK_DGRAM unix socket path must return EPERM.
    // Requires a real Linux kernel outside any seccomp-sandboxed environment.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore]
    fn test_sendmsg_denied_dgram_unix_socket_returns_eperm() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let sock_path = tmp.path().join("dgram-msg-denied.sock");

        let listener =
            std::os::unix::net::UnixDatagram::bind(&sock_path).expect("bind dgram listener");

        let denied = vec![sock_path.clone()];
        let sock_path_c = sock_path.clone();

        let errno_val = run_socket_interception_test(&denied, move |pipe_write| {
            let sockfd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
            if sockfd < 0 {
                unsafe { libc::_exit(3) };
            }

            let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
            let path_bytes = sock_path_c.as_os_str().as_encoded_bytes();
            let copy_len = path_bytes.len().min(107);
            unsafe {
                std::ptr::copy_nonoverlapping(
                    path_bytes.as_ptr(),
                    addr.sun_path.as_mut_ptr().cast::<u8>(),
                    copy_len,
                );
            }
            let addrlen =
                (std::mem::size_of::<libc::sa_family_t>() + copy_len + 1) as libc::socklen_t;

            let data = b"hello";
            let iov = libc::iovec {
                iov_base: data.as_ptr() as *mut libc::c_void,
                iov_len: data.len(),
            };
            let msg = libc::msghdr {
                msg_name: &addr as *const libc::sockaddr_un as *mut libc::c_void,
                msg_namelen: addrlen,
                msg_iov: &iov as *const libc::iovec as *mut libc::iovec,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            };
            // SAFETY: sendmsg with valid socket and message.
            let ret = unsafe { libc::sendmsg(sockfd, &msg, 0) };
            let errno_val = if ret < 0 {
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            } else {
                0
            };
            unsafe { report_errno_and_exit(pipe_write, errno_val) };
        });

        drop(listener);
        assert_eq!(
            errno_val,
            libc::EPERM,
            "expected EPERM for sendmsg to denied unix socket, got {}",
            errno_val
        );
    }

    // -----------------------------------------------------------------------
    // Step 3: Hardening verifications
    // -----------------------------------------------------------------------

    /// Verify error propagation: connect() to a non-listening socket returns
    /// the real errno (ECONNREFUSED), not EPERM or a swallowed error.
    ///
    /// This confirms that `emulate_connect` correctly forwards connect() errors
    /// from the supervisor back to the child via `respond_notif_errno`.
    // Requires a real Linux kernel outside any seccomp-sandboxed environment.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore]
    fn test_connect_error_propagated_to_child() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let sock_path = tmp.path().join("no-listener.sock");

        // Create the socket file via bind, then immediately drop the listener
        // so nothing is listening — connect should get ECONNREFUSED.
        let listener = std::os::unix::net::UnixListener::bind(&sock_path).expect("bind listener");
        drop(listener); // no longer accepting

        // No denied paths — the supervisor will call emulate_connect.
        let sock_path_c = sock_path.clone();
        let errno_val = run_socket_interception_test(&[], move |pipe_write| {
            let sockfd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            if sockfd < 0 {
                unsafe { libc::_exit(3) };
            }

            let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
            let path_bytes = sock_path_c.as_os_str().as_encoded_bytes();
            let copy_len = path_bytes.len().min(107);
            unsafe {
                std::ptr::copy_nonoverlapping(
                    path_bytes.as_ptr(),
                    addr.sun_path.as_mut_ptr().cast::<u8>(),
                    copy_len,
                );
            }
            let addrlen =
                (std::mem::size_of::<libc::sa_family_t>() + copy_len + 1) as libc::socklen_t;

            let ret = unsafe {
                libc::connect(
                    sockfd,
                    &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                    addrlen,
                )
            };
            let errno_val = if ret < 0 {
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            } else {
                0
            };
            unsafe { report_errno_and_exit(pipe_write, errno_val) };
        });

        // The child must see ECONNREFUSED (or ENOENT if socket file was cleaned up),
        // NOT EPERM. The key invariant: emulate_connect forwards the real errno.
        assert_ne!(
            errno_val,
            libc::EPERM,
            "error propagation broken: child saw EPERM instead of the real connect() error"
        );
        assert!(
            errno_val == libc::ECONNREFUSED || errno_val == libc::ENOENT,
            "expected ECONNREFUSED or ENOENT for no-listener socket, got {}",
            errno_val
        );
    }

    /// Verify non-blocking connect emulation:
    /// A non-blocking socket connect to a slow/unavailable path should return
    /// EINPROGRESS (async connect in progress), not block or return EPERM.
    ///
    /// This confirms `emulate_connect` preserves non-blocking semantics by
    /// calling connect() on the dup'd fd which shares the O_NONBLOCK flag.
    // Requires a real Linux kernel outside any seccomp-sandboxed environment.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore]
    fn test_nonblocking_connect_returns_einprogress() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let sock_path = tmp.path().join("nonblock.sock");

        // Create a listener but don't accept connections — so the backlog fills
        // and non-blocking connects will return EINPROGRESS.
        // We use a small backlog of 0 to ensure the first connect may block.
        let listener = std::os::unix::net::UnixListener::bind(&sock_path).expect("bind listener");

        let sock_path_c = sock_path.clone();
        let errno_val = run_socket_interception_test(&[], move |pipe_write| {
            // Create non-blocking SOCK_STREAM socket.
            let sockfd =
                unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
            if sockfd < 0 {
                unsafe { libc::_exit(3) };
            }

            let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
            let path_bytes = sock_path_c.as_os_str().as_encoded_bytes();
            let copy_len = path_bytes.len().min(107);
            unsafe {
                std::ptr::copy_nonoverlapping(
                    path_bytes.as_ptr(),
                    addr.sun_path.as_mut_ptr().cast::<u8>(),
                    copy_len,
                );
            }
            let addrlen =
                (std::mem::size_of::<libc::sa_family_t>() + copy_len + 1) as libc::socklen_t;

            let ret = unsafe {
                libc::connect(
                    sockfd,
                    &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                    addrlen,
                )
            };
            let errno_val = if ret < 0 {
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            } else {
                0
            };
            unsafe { report_errno_and_exit(pipe_write, errno_val) };
        });

        drop(listener);

        // For a non-blocking connect, the kernel may:
        // - Return 0 immediately (connected, backlog not full)
        // - Return EINPROGRESS (async in progress)
        // The critical invariant: must NOT be EPERM (not blocked by supervisor)
        // and must NOT be EWOULDBLOCK (connect on SOCK_STREAM doesn't use EWOULDBLOCK).
        assert_ne!(
            errno_val,
            libc::EPERM,
            "non-blocking connect must not be blocked with EPERM"
        );
        assert!(
            errno_val == 0 || errno_val == libc::EINPROGRESS,
            "non-blocking connect should succeed (0) or return EINPROGRESS, got {}",
            errno_val
        );
    }

    // -----------------------------------------------------------------------
    // Step 3: TOCTOU verification (code-review level)
    // -----------------------------------------------------------------------
    //
    // `emulate_connect()` is TOCTOU-safe by construction:
    // 1. `read_sockaddr_un()` copies the sockaddr bytes from child memory into
    //    a `SockaddrUn` owned by the supervisor.
    // 2. `notif_id_valid()` is called to confirm the notification is still live.
    // 3. `emulate_connect()` builds a fresh `libc::sockaddr_un` from the
    //    supervisor's `SockaddrUn` struct — it never dereferences any child
    //    pointer again.
    // 4. The kernel `connect()` call uses the supervisor's stack-allocated addr,
    //    so even if the child mutates its original buffer after step 1, the
    //    supervisor's copy is unaffected.
    //
    // This design is verified by inspection; the address pointer argument to
    // the child's original `connect()` syscall is never used by the supervisor
    // after step 1.  The integration tests above exercise the full path and
    // would catch any regression that re-reads child memory at connect time.

    #[test]
    fn test_rate_limiter_allows_burst() {
        let mut limiter = RateLimiter::new(10, 5);
        for _ in 0..5 {
            assert!(limiter.try_acquire());
        }
        assert!(!limiter.try_acquire());
    }

    #[test]
    fn test_rate_limiter_refills_over_time() {
        let mut limiter = RateLimiter::new(10, 3);
        for _ in 0..3 {
            assert!(limiter.try_acquire());
        }
        assert!(!limiter.try_acquire());
        limiter.last_refill -= std::time::Duration::from_millis(500);
        assert!(limiter.try_acquire());
    }

    #[test]
    fn test_file_capability_exact_match_only() {
        let caps = vec![InitialCapability {
            path: PathBuf::from("/home/user/config.json"),
            access: AccessMode::Read,
            is_file: true,
        }];

        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/config.json"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::Sufficient(_)
        ));

        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/config.json/subpath"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::None
        ));

        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/other.json"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::None
        ));
    }

    #[test]
    fn test_directory_capability_allows_subpaths() {
        let caps = vec![InitialCapability {
            path: PathBuf::from("/home/user/project"),
            access: AccessMode::Read,
            is_file: false,
        }];

        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/project"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::Sufficient(_)
        ));

        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/project/src/main.rs"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::Sufficient(_)
        ));

        assert!(matches!(
            match_initial_capability(&PathBuf::from("/home/user/other"), AccessMode::Read, &caps),
            InitialCapabilityMatch::None
        ));
    }

    #[test]
    fn test_file_capability_does_not_authorize_fake_subpath() {
        let caps = vec![InitialCapability {
            path: PathBuf::from("/foo/bar"),
            access: AccessMode::Read,
            is_file: true,
        }];

        assert!(matches!(
            match_initial_capability(&PathBuf::from("/foo/bar"), AccessMode::Read, &caps),
            InitialCapabilityMatch::Sufficient(_)
        ));
        assert!(matches!(
            match_initial_capability(&PathBuf::from("/foo/bar/subpath"), AccessMode::Read, &caps),
            InitialCapabilityMatch::None
        ));
        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/foo/bar/deep/nested/path"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::None
        ));
    }

    #[test]
    fn test_mixed_file_and_directory_capabilities() {
        let caps = vec![
            InitialCapability {
                path: PathBuf::from("/etc/passwd"),
                access: AccessMode::Read,
                is_file: true,
            },
            InitialCapability {
                path: PathBuf::from("/home/user/project"),
                access: AccessMode::Read,
                is_file: false,
            },
        ];

        assert!(matches!(
            match_initial_capability(&PathBuf::from("/etc/passwd"), AccessMode::Read, &caps),
            InitialCapabilityMatch::Sufficient(_)
        ));
        assert!(matches!(
            match_initial_capability(&PathBuf::from("/etc/passwd/fake"), AccessMode::Read, &caps),
            InitialCapabilityMatch::None
        ));

        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/project"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::Sufficient(_)
        ));
        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/project/src/lib.rs"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::Sufficient(_)
        ));
    }

    #[test]
    fn test_directory_capability_reports_insufficient_access() {
        let caps = vec![InitialCapability {
            path: PathBuf::from("/home/user/project"),
            access: AccessMode::Read,
            is_file: false,
        }];

        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/project/output.txt"),
                AccessMode::Write,
                &caps
            ),
            InitialCapabilityMatch::Insufficient(_)
        ));
    }
}
