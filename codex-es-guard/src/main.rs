use endpoint_sec::sys::{es_auth_result_t, es_event_type_t};
use endpoint_sec::{Client, Event, EventRenameDestinationFile, Message};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CACHE_TTL_SECS: u64 = 5;
const DEFAULT_FILE_MODE: u32 = 0o644;
const DEFAULT_DIR_MODE: u32 = 0o700;

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
struct SecurityPolicy {
    protected_zones: Vec<String>,
    temporary_overrides: Vec<TemporaryOverrideEntry>,

    #[serde(default = "default_allow_vcs_metadata_in_ai_context")]
    allow_vcs_metadata_in_ai_context: bool,

    #[serde(default = "default_trusted_tools")]
    trusted_tools: Vec<String>,

    #[serde(default = "default_ai_agent_patterns")]
    ai_agent_patterns: Vec<String>,

    #[serde(default)]
    allow_trusted_tools_in_ai_context: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct TemporaryOverrideRule {
    path: String,
    #[serde(default)]
    expires_at: Option<u64>,
    #[serde(default)]
    created_at: Option<u64>,
    #[serde(default)]
    created_by: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
enum TemporaryOverrideEntry {
    Path(String),
    Rule(TemporaryOverrideRule),
}

fn default_trusted_tools() -> Vec<String> {
    [
        // VCS
        "git",
        "jj",
        // Rust
        "cargo",
        "rustup",
        "rustc",
        // Swift / Xcode
        "swift",
        "swiftc",
        "xcodebuild",
        "xcrun",
        // Nix
        "nix",
        "nix-build",
        "nix-store",
        "nix-env",
        "nix-daemon",
        // System / package manager
        "brew",
        // Build systems
        "make",
        "cmake",
        "ninja",
        // Go
        "go",
        // Docker
        "docker",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn default_allow_vcs_metadata_in_ai_context() -> bool {
    true
}

fn default_ai_agent_patterns() -> Vec<String> {
    ["codex", "claude", "claude-code"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

#[derive(Debug, Clone)]
struct CachedAncestor {
    ai_ancestor: Option<String>,
    updated_at: u64,
}

struct LockDirGuard {
    path: PathBuf,
}

impl Drop for LockDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

fn acquire_lock_dir(lock_path: &Path) -> io::Result<LockDirGuard> {
    for _ in 0..100 {
        match fs::create_dir(lock_path) {
            Ok(_) => {
                return Ok(LockDirGuard {
                    path: lock_path.to_path_buf(),
                });
            },
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                thread::sleep(Duration::from_millis(50));
                continue;
            },
            Err(err) => return Err(err),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        format!("policy lock busy: {}", lock_path.display()),
    ))
}

fn trim_trailing_slashes(path: &str) -> &str {
    if path == "/" {
        return "/";
    }
    path.trim_end_matches('/')
}

fn path_prefix_match(path: &str, prefix: &str) -> bool {
    let normalized_path = trim_trailing_slashes(path);
    let normalized_prefix = trim_trailing_slashes(prefix);

    if normalized_prefix.is_empty() || !normalized_prefix.starts_with('/') {
        return false;
    }
    if normalized_prefix == "/" {
        return normalized_path.starts_with('/');
    }
    normalized_path == normalized_prefix || normalized_path.starts_with(&format!("{}/", normalized_prefix))
}

fn ensure_dir_not_symlink(path: &Path, mode: u32) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("refuse symlink directory: {}", path.display()),
                ));
            }
            if !meta.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("not a directory: {}", path.display()),
                ));
            }
            Ok(())
        },
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let owner = path
                .parent()
                .and_then(|parent| fs::symlink_metadata(parent).ok())
                .map(|meta| (meta.uid(), meta.gid()));
            fs::create_dir(path)?;
            if let Some((uid, gid)) = owner {
                let dir_file = File::open(path)?;
                let rc = unsafe { libc::fchown(dir_file.as_raw_fd(), uid, gid) };
                if rc != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
            Ok(())
        },
        Err(err) => Err(err),
    }
}

fn open_read_no_follow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

fn open_append_no_follow(path: &Path, mode: u32) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(mode)
        .open(path)
}

fn open_truncate_no_follow(path: &Path, mode: u32) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(mode)
        .open(path)
}

fn verify_regular_file(file: &File, path: &Path) -> io::Result<()> {
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("not a regular file: {}", path.display()),
        ));
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct DenialRecord {
    ts: u64,
    op: String,
    path: String,
    dest: Option<String>,
    zone: String,
    process: String,
    ancestor: String,
}

impl SecurityPolicy {
    fn is_override_active_for_path(&self, target_path: &str, now: u64) -> bool {
        self.temporary_overrides
            .iter()
            .any(|entry| !entry.is_expired(now) && path_prefix_match(target_path, entry.path()))
    }

    fn is_protected(&self, target_path: &str) -> bool {
        let in_zone = self
            .protected_zones
            .iter()
            .any(|zone| path_prefix_match(target_path, zone));
        if !in_zone {
            return false;
        }

        let is_overridden = self.is_override_active_for_path(target_path, now_ts());
        if is_overridden {
            return false;
        }

        true
    }

    fn matched_zone(&self, target_path: &str) -> String {
        self.protected_zones
            .iter()
            .find(|zone| path_prefix_match(target_path, zone.as_str()))
            .cloned()
            .unwrap_or_default()
    }

    fn is_trusted_tool(&self, exe_name: &str) -> bool {
        self.trusted_tools.iter().any(|tool| exe_name == tool.as_str())
    }

    fn matches_ai_agent(&self, exe_path: &str) -> bool {
        let exe_name = exe_path.rsplit('/').next().unwrap_or(exe_path);
        self.ai_agent_patterns
            .iter()
            .any(|pattern| exe_name.contains(pattern.as_str()))
    }

    fn sanitize_overrides(&mut self, now: u64) -> bool {
        let before = self.temporary_overrides.len();
        self.temporary_overrides.retain(|entry| {
            let path = entry.path();
            !entry.is_expired(now)
                && !path.is_empty()
                && path.starts_with('/')
                && path != "/"
                && self.protected_zones.iter().any(|zone| path_prefix_match(path, zone))
        });

        let mut seen_paths: HashSet<String> = HashSet::new();
        let mut deduped: Vec<TemporaryOverrideEntry> = Vec::with_capacity(self.temporary_overrides.len());
        for entry in self.temporary_overrides.iter().rev() {
            let path = trim_trailing_slashes(entry.path()).to_string();
            if seen_paths.insert(path) {
                deduped.push(entry.clone());
            }
        }
        deduped.reverse();

        let changed = before != deduped.len() || before != self.temporary_overrides.len();
        self.temporary_overrides = deduped;
        changed
    }
}

impl TemporaryOverrideEntry {
    fn path(&self) -> &str {
        match self {
            TemporaryOverrideEntry::Path(path) => path.as_str(),
            TemporaryOverrideEntry::Rule(rule) => rule.path.as_str(),
        }
    }

    fn expires_at(&self) -> Option<u64> {
        match self {
            TemporaryOverrideEntry::Path(_) => None,
            TemporaryOverrideEntry::Rule(rule) => rule.expires_at,
        }
    }

    fn is_expired(&self, now: u64) -> bool {
        matches!(self.expires_at(), Some(exp) if exp <= now)
    }
}

fn load_policy(policy_path: &str) -> Option<SecurityPolicy> {
    let path = Path::new(policy_path);
    let mut file = open_read_no_follow(path).ok()?;
    verify_regular_file(&file, path).ok()?;

    let mut content = String::new();
    file.read_to_string(&mut content).ok()?;
    serde_json::from_str(&content).ok()
}

fn save_policy(policy_path: &str, policy: &SecurityPolicy) -> io::Result<()> {
    let path = Path::new(policy_path);
    let lock_path = PathBuf::from(format!("{}.lock", policy_path));
    let _lock = acquire_lock_dir(&lock_path)?;

    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "policy path has no parent"))?;
    ensure_dir_not_symlink(parent, DEFAULT_DIR_MODE)?;

    let existing_meta = match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "refuse to save policy via symlink",
                ));
            }
            if !meta.file_type().is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "policy path is not a regular file",
                ));
            }
            Some(meta)
        },
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(err) => return Err(err),
    };

    let serialized =
        serde_json::to_vec_pretty(policy).map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;

    let final_mode = existing_meta
        .as_ref()
        .map(|m| m.mode() & 0o777)
        .unwrap_or(DEFAULT_FILE_MODE);
    let fallback_owner = fs::symlink_metadata(parent).ok().map(|meta| (meta.uid(), meta.gid()));
    let final_owner = existing_meta
        .as_ref()
        .map(|meta| (meta.uid(), meta.gid()))
        .or(fallback_owner);

    let mut tmp_path: Option<PathBuf> = None;
    let mut tmp_file: Option<File> = None;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("es_policy.json");

    for attempt in 0..32 {
        let candidate = parent.join(format!(
            ".{}.tmp.{}.{}.{}",
            file_name,
            std::process::id(),
            now_ts(),
            attempt
        ));
        let open_result = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(DEFAULT_FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&candidate);
        match open_result {
            Ok(file) => {
                tmp_path = Some(candidate);
                tmp_file = Some(file);
                break;
            },
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }

    let tmp_path = tmp_path.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "failed to allocate temp policy file",
        )
    })?;
    let mut tmp_file =
        tmp_file.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "failed to open temp policy file"))?;
    verify_regular_file(&tmp_file, &tmp_path)?;

    tmp_file.write_all(&serialized)?;
    tmp_file.sync_all()?;
    tmp_file.set_permissions(fs::Permissions::from_mode(final_mode))?;

    if let Some((uid, gid)) = final_owner {
        let rc = unsafe { libc::fchown(tmp_file.as_raw_fd(), uid, gid) };
        if rc != 0 {
            let _ = fs::remove_file(&tmp_path);
            return Err(io::Error::last_os_error());
        }
    }

    drop(tmp_file);
    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }
    Ok(())
}

fn is_system_temp(path: &str, home: &str) -> bool {
    path_prefix_match(path, &format!("{}/.Trash", home))
        || path_prefix_match(path, "/private/tmp")
        || path_prefix_match(path, "/private/var/folders")
        || path.ends_with(".DS_Store")
}

fn log_denial(home: &str, record: &DenialRecord) {
    let codex_dir = PathBuf::from(home).join(".codex");
    if let Err(err) = ensure_dir_not_symlink(&codex_dir, DEFAULT_DIR_MODE) {
        eprintln!("[log] cannot use codex dir: {}", err);
        return;
    }

    let guard_dir = codex_dir.join("es-guard");
    if let Err(err) = ensure_dir_not_symlink(&guard_dir, DEFAULT_DIR_MODE) {
        eprintln!("[log] cannot use guard dir: {}", err);
        return;
    }

    let log_path = guard_dir.join("denials.jsonl");
    let feedback_path = guard_dir.join("last_denial.txt");

    if let Ok(json) = serde_json::to_string(record) {
        if let Ok(mut file) = open_append_no_follow(&log_path, DEFAULT_FILE_MODE) {
            if verify_regular_file(&file, &log_path).is_ok() {
                if let Ok(meta) = file.metadata() {
                    if meta.len() > 1_000_000 {
                        let _ = file.set_len(0);
                    }
                }
                let _ = writeln!(file, "{}", json);
            }
        }
    }

    // Write human-readable feedback for AI agents
    let dest_info = record
        .dest
        .as_deref()
        .map(|d| format!("\nDest: {}", d))
        .unwrap_or_default();
    let feedback = format!(
        "[ES-GUARD DENIED]\n\
         Operation: {}\n\
         Path: {}{}\n\
         Zone: {}\n\
         Process: {} (via {})\n\
         \n\
         Recommended (safer first step): es-guard-quarantine {}\n\
         This moves the target into ./temp under your CURRENT working directory.\n\
         \n\
         If you must permanently delete via AI, request one-time override with TTL:\n\
         es-guard-override --minutes 3 {}\n\
         (Use --no-expire only for emergency/manual cleanup)\n\
         Then retry the operation.\n",
        record.op, record.path, dest_info, record.zone, record.process, record.ancestor, record.path, record.path
    );
    if let Ok(mut file) = open_truncate_no_follow(&feedback_path, DEFAULT_FILE_MODE) {
        if verify_regular_file(&file, &feedback_path).is_ok() {
            let _ = file.write_all(feedback.as_bytes());
            let _ = file.sync_data();
        }
    }
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// --- Process tree walking (macOS) ---

fn get_process_path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    let ret = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32) };
    if ret > 0 {
        buf.truncate(ret as usize);
        String::from_utf8(buf).ok()
    } else {
        None
    }
}

/// Get the process argv[0] via sysctl KERN_PROCARGS2.
/// This reflects process.title changes (e.g., Node.js setting title to "claude").
fn get_process_argv0(pid: i32) -> Option<String> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size: libc::size_t = 0;

    // First call: get buffer size
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || size == 0 {
        return None;
    }

    let mut buf = vec![0u8; size];
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || size < 8 {
        return None;
    }

    // Layout: argc(i32) + exec_path + \0 + padding(\0s) + argv[0] + \0 + ...
    let mut pos = 4; // skip argc
                     // skip exec_path
    while pos < size && buf[pos] != 0 {
        pos += 1;
    }
    // skip null padding
    while pos < size && buf[pos] == 0 {
        pos += 1;
    }
    // read argv[0]
    let start = pos;
    while pos < size && buf[pos] != 0 {
        pos += 1;
    }

    if start < pos {
        let argv0 = String::from_utf8_lossy(&buf[start..pos]).to_string();
        // Extract basename
        Some(argv0.rsplit('/').next().unwrap_or(&argv0).to_string())
    } else {
        None
    }
}

/// Query proc_bsdinfo for a process. Returns (ppid, comm_name).
fn get_process_info(pid: i32) -> Option<(i32, String)> {
    const PROC_PIDTBSDINFO: i32 = 3;
    let mut buf = [0u8; 256];
    let ret = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len() as i32,
        )
    };
    if ret > 20 {
        let ppid = u32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]) as i32;
        let ppid = if ppid > 0 && ppid != pid { ppid } else { 0 };
        // pbi_comm at offset 48 (16 bytes)
        let comm_end = buf[48..64].iter().position(|&b| b == 0).unwrap_or(16);
        let comm = String::from_utf8_lossy(&buf[48..48 + comm_end]).to_string();
        Some((ppid, comm))
    } else {
        None
    }
}

fn exe_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Walk the process tree to find if any ancestor is an AI agent.
/// Returns (is_ai_context, ai_ancestor_name).
fn find_ai_ancestor(pid: i32, policy: &SecurityPolicy, cache: &mut HashMap<i32, CachedAncestor>) -> Option<String> {
    let ts = now_ts();
    let mut current = pid;
    let mut depth = 0;

    while current > 1 && depth < 30 {
        if let Some(cached) = cache.get(&current) {
            if ts.saturating_sub(cached.updated_at) <= CACHE_TTL_SECS {
                return cached.ai_ancestor.clone();
            }
        }

        // Check executable path (Mach-O binary name)
        let exe_path = get_process_path(current);
        let exe_match = exe_path.as_ref().map(|p| policy.matches_ai_agent(p)).unwrap_or(false);

        // Check argv[0] (reflects process.title, e.g. Node.js "claude")
        let argv0 = get_process_argv0(current);
        let argv0_match = argv0
            .as_ref()
            .map(|a| policy.ai_agent_patterns.iter().any(|pat| a.contains(pat.as_str())))
            .unwrap_or(false);

        if exe_match || argv0_match {
            let label = if argv0_match {
                argv0.unwrap_or_else(|| exe_path.as_ref().map(|p| exe_name(p).to_string()).unwrap_or_default())
            } else {
                exe_path.as_ref().map(|p| exe_name(p).to_string()).unwrap_or_default()
            };
            cache.insert(
                current,
                CachedAncestor {
                    ai_ancestor: Some(label.clone()),
                    updated_at: ts,
                },
            );
            return Some(label);
        }

        // Walk up to parent via proc_bsdinfo
        match get_process_info(current).map(|(pp, _)| pp).filter(|&pp| pp > 0) {
            Some(pp) => current = pp,
            None => break,
        }
        depth += 1;
    }

    cache.insert(
        pid,
        CachedAncestor {
            ai_ancestor: None,
            updated_at: ts,
        },
    );
    None
}

fn process_name_for_pid(pid: i32) -> Option<String> {
    get_process_path(pid).map(|path| exe_name(&path).to_string())
}

/// Check if the immediate process is a trusted tool.
fn is_trusted_process_name(process_name: &str, policy: &SecurityPolicy) -> bool {
    policy.is_trusted_tool(process_name)
}

fn is_vcs_tool(process_name: &str) -> bool {
    matches!(process_name, "git" | "jj")
}

fn is_vcs_metadata_path(path: &str) -> bool {
    trim_trailing_slashes(path)
        .split('/')
        .any(|component| component == ".git" || component == ".jj")
}

fn should_allow_vcs_metadata_unlink_in_ai_context(
    path: &str,
    process_name: Option<&str>,
    policy: &SecurityPolicy,
) -> bool {
    if !policy.allow_vcs_metadata_in_ai_context || !is_vcs_metadata_path(path) {
        return false;
    }
    let process_name = match process_name {
        Some(name) => name,
        None => return false,
    };

    is_vcs_tool(process_name) && is_trusted_process_name(process_name, policy)
}

fn should_allow_vcs_metadata_rename_in_ai_context(
    source_path: &str,
    dest_path: &str,
    process_name: Option<&str>,
    policy: &SecurityPolicy,
) -> bool {
    if !policy.allow_vcs_metadata_in_ai_context
        || !is_vcs_metadata_path(source_path)
        || !is_vcs_metadata_path(dest_path)
    {
        return false;
    }
    let process_name = match process_name {
        Some(name) => name,
        None => return false,
    };

    is_vcs_tool(process_name) && is_trusted_process_name(process_name, policy)
}

/// Core decision: should this operation be denied?
/// Returns Some((process_name, ancestor_name)) if denied, None if allowed.
fn should_deny(
    path: &str,
    pid: i32,
    home: &str,
    policy: &SecurityPolicy,
    cache: &mut HashMap<i32, CachedAncestor>,
) -> Option<(String, String)> {
    // 1. Not in protected zone → ALLOW
    if !policy.is_protected(path) {
        return None;
    }

    // 2. System temp paths → ALLOW
    if is_system_temp(path, home) {
        return None;
    }

    // 3. Not in AI agent process tree → ALLOW (user operation)
    let ai_ancestor = match find_ai_ancestor(pid, policy, cache) {
        Some(name) => name,
        None => return None,
    };

    let process_name = process_name_for_pid(pid).unwrap_or_else(|| format!("pid:{}", pid));

    // 4. Keep git/jj commit internals workable while still blocking `git rm` on working tree files.
    if should_allow_vcs_metadata_unlink_in_ai_context(path, Some(process_name.as_str()), policy) {
        return None;
    }

    // 5. Optional compatibility mode for trusted tools in AI context.
    if policy.allow_trusted_tools_in_ai_context && is_trusted_process_name(process_name.as_str(), policy) {
        return None;
    }

    // 6. In AI agent context and protected path → DENY
    Some((process_name, ai_ancestor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_override_path_still_decodes_and_applies() {
        let json = r#"{
            "protected_zones": ["/Users/jqwang/0"],
            "temporary_overrides": ["/Users/jqwang/00-nixos-config/nixos-config"]
        }"#;
        let policy: SecurityPolicy = serde_json::from_str(json).expect("policy json should decode");
        assert!(
            !policy.is_protected("/Users/jqwang/00-nixos-config/nixos-config/file.txt"),
            "legacy string override should still bypass protection"
        );
    }

    #[test]
    fn sanitize_overrides_removes_expired_entries() {
        let mut policy = SecurityPolicy {
            protected_zones: vec!["/Users/jqwang/00-nixos-config".to_string()],
            temporary_overrides: vec![TemporaryOverrideEntry::Rule(TemporaryOverrideRule {
                path: "/Users/jqwang/00-nixos-config".to_string(),
                expires_at: Some(100),
                created_at: Some(1),
                created_by: Some("test".to_string()),
            })],
            allow_vcs_metadata_in_ai_context: true,
            trusted_tools: default_trusted_tools(),
            ai_agent_patterns: default_ai_agent_patterns(),
            allow_trusted_tools_in_ai_context: false,
        };

        let changed = policy.sanitize_overrides(100);
        assert!(changed, "expired override should be removed");
        assert!(policy.temporary_overrides.is_empty());
    }

    #[test]
    fn sanitize_overrides_deduplicates_paths_by_last_entry() {
        let mut policy = SecurityPolicy {
            protected_zones: vec!["/Users/jqwang/00-nixos-config".to_string()],
            temporary_overrides: vec![
                TemporaryOverrideEntry::Path("/Users/jqwang/00-nixos-config/nixos-config".to_string()),
                TemporaryOverrideEntry::Rule(TemporaryOverrideRule {
                    path: "/Users/jqwang/00-nixos-config/nixos-config".to_string(),
                    expires_at: Some(9_999_999_999),
                    created_at: Some(2),
                    created_by: Some("newer".to_string()),
                }),
            ],
            allow_vcs_metadata_in_ai_context: true,
            trusted_tools: default_trusted_tools(),
            ai_agent_patterns: default_ai_agent_patterns(),
            allow_trusted_tools_in_ai_context: false,
        };

        let changed = policy.sanitize_overrides(1);
        assert!(changed, "duplicate overrides should be compacted");
        assert_eq!(policy.temporary_overrides.len(), 1);
        assert_eq!(
            policy.temporary_overrides[0].expires_at(),
            Some(9_999_999_999),
            "newest override entry should win after dedup"
        );
    }

    #[test]
    fn path_prefix_match_respects_directory_boundaries() {
        assert!(path_prefix_match(
            "/Users/jqwang/project/a.txt",
            "/Users/jqwang/project"
        ));
        assert!(path_prefix_match(
            "/Users/jqwang/project",
            "/Users/jqwang/project"
        ));
        assert!(!path_prefix_match(
            "/Users/jqwang/project-backup/a.txt",
            "/Users/jqwang/project"
        ));
        assert!(!path_prefix_match(
            "/Users/jqwang/projectx",
            "/Users/jqwang/project"
        ));
    }

    #[test]
    fn sanitize_overrides_drops_invalid_or_outside_zone_paths() {
        let mut policy = SecurityPolicy {
            protected_zones: vec!["/Users/jqwang/project".to_string()],
            temporary_overrides: vec![
                TemporaryOverrideEntry::Path("/".to_string()),
                TemporaryOverrideEntry::Path("relative/path".to_string()),
                TemporaryOverrideEntry::Path("/Users/jqwang/other/file".to_string()),
                TemporaryOverrideEntry::Path("/Users/jqwang/project/file.txt".to_string()),
            ],
            allow_vcs_metadata_in_ai_context: true,
            trusted_tools: default_trusted_tools(),
            ai_agent_patterns: default_ai_agent_patterns(),
            allow_trusted_tools_in_ai_context: false,
        };

        let changed = policy.sanitize_overrides(1);
        assert!(changed, "invalid paths should be removed");
        assert_eq!(policy.temporary_overrides.len(), 1);
        assert_eq!(
            policy.temporary_overrides[0].path(),
            "/Users/jqwang/project/file.txt"
        );
    }

    #[test]
    fn vcs_metadata_path_detection_respects_component_boundary() {
        assert!(is_vcs_metadata_path("/Users/jqwang/repo/.git/index.lock"));
        assert!(is_vcs_metadata_path("/Users/jqwang/repo/.jj/working_copy"));
        assert!(!is_vcs_metadata_path("/Users/jqwang/repo/.gitignore"));
        assert!(!is_vcs_metadata_path("/Users/jqwang/repo/git/.git-backup"));
    }

    #[test]
    fn vcs_metadata_unlink_allow_requires_vcs_tool_and_flag() {
        let mut policy = SecurityPolicy::default();
        policy.trusted_tools = default_trusted_tools();
        policy.allow_vcs_metadata_in_ai_context = true;

        assert!(should_allow_vcs_metadata_unlink_in_ai_context(
            "/Users/jqwang/repo/.git/index.lock",
            Some("git"),
            &policy
        ));
        assert!(!should_allow_vcs_metadata_unlink_in_ai_context(
            "/Users/jqwang/repo/src/main.rs",
            Some("git"),
            &policy
        ));
        assert!(!should_allow_vcs_metadata_unlink_in_ai_context(
            "/Users/jqwang/repo/.git/index.lock",
            Some("rm"),
            &policy
        ));

        policy.allow_vcs_metadata_in_ai_context = false;
        assert!(!should_allow_vcs_metadata_unlink_in_ai_context(
            "/Users/jqwang/repo/.git/index.lock",
            Some("git"),
            &policy
        ));
    }

    #[test]
    fn vcs_metadata_rename_allow_requires_both_paths_in_metadata() {
        let mut policy = SecurityPolicy::default();
        policy.trusted_tools = default_trusted_tools();
        policy.allow_vcs_metadata_in_ai_context = true;

        assert!(should_allow_vcs_metadata_rename_in_ai_context(
            "/Users/jqwang/repo/.git/index.lock",
            "/Users/jqwang/repo/.git/index",
            Some("git"),
            &policy
        ));
        assert!(!should_allow_vcs_metadata_rename_in_ai_context(
            "/Users/jqwang/repo/.git/index.lock",
            "/private/tmp/index.lock",
            Some("git"),
            &policy
        ));
    }
}

fn main() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let policy_path = format!("{}/.codex/es_policy.json", home);

    let initial_policy = load_policy(&policy_path).unwrap_or_default();
    let global_policy = Arc::new(Mutex::new(initial_policy));

    // Process ancestry cache (cleared on policy reload)
    let ancestor_cache: Arc<Mutex<HashMap<i32, CachedAncestor>>> = Arc::new(Mutex::new(HashMap::new()));

    // Policy hot-reload thread (1s polling)
    let policy_clone = global_policy.clone();
    let cache_clone = ancestor_cache.clone();
    let path_clone = policy_path.clone();
    thread::spawn(move || {
        let mut last_mtime = SystemTime::UNIX_EPOCH;
        loop {
            let mut snapshot_to_save: Option<SecurityPolicy> = None;

            if let Ok(metadata) = fs::metadata(&path_clone) {
                if let Ok(mtime) = metadata.modified() {
                    if mtime != last_mtime {
                        if let Some(mut new_policy) = load_policy(&path_clone) {
                            let changed_by_sanitize = new_policy.sanitize_overrides(now_ts());
                            if let Ok(mut lock) = policy_clone.lock() {
                                *lock = new_policy.clone();
                                // Clear cache on policy change
                                if let Ok(mut c) = cache_clone.lock() {
                                    c.clear();
                                }
                                println!("[policy] reloaded");
                                last_mtime = mtime;
                                if changed_by_sanitize {
                                    snapshot_to_save = Some(new_policy);
                                }
                            }
                        }
                    }
                }
            }

            {
                if let Ok(mut lock) = policy_clone.lock() {
                    if lock.sanitize_overrides(now_ts()) {
                        snapshot_to_save = Some(lock.clone());
                        if let Ok(mut c) = cache_clone.lock() {
                            c.clear();
                        }
                    }
                }
            }

            if let Some(policy_snapshot) = snapshot_to_save {
                if let Err(err) = save_policy(&path_clone, &policy_snapshot) {
                    eprintln!("[policy] failed to persist sanitized policy: {}", err);
                } else if let Ok(metadata) = fs::metadata(&path_clone) {
                    if let Ok(mtime) = metadata.modified() {
                        last_mtime = mtime;
                    }
                }
            }
            thread::sleep(Duration::from_secs(1));
        }
    });

    let safe_policy = AssertUnwindSafe(global_policy);
    let safe_cache = AssertUnwindSafe(ancestor_cache);
    let home_for_handler = home.clone();

    let handler = move |client: &mut Client<'_>, message: Message| {
        let current_policy = safe_policy
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let pid = message.process().audit_token().pid();

        match message.event() {
            Some(Event::AuthUnlink(unlink)) => {
                let path = unlink.target().path().to_string_lossy();

                let mut cache = safe_cache.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some((proc_name, ancestor)) =
                    should_deny(&path, pid, &home_for_handler, &current_policy, &mut cache)
                {
                    let zone = current_policy.matched_zone(&path);
                    println!(
                        "[DENY] unlink by {} (via {}): {}",
                        proc_name, ancestor, path
                    );
                    log_denial(
                        &home_for_handler,
                        &DenialRecord {
                            ts: now_ts(),
                            op: "unlink".into(),
                            path: path.to_string(),
                            dest: None,
                            zone,
                            process: proc_name,
                            ancestor,
                        },
                    );
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_DENY, false);
                } else {
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                }
            },
            Some(Event::AuthRename(rename)) => {
                let source_path = rename.source().path().to_string_lossy();
                let dest_path_str = match rename.destination() {
                    Some(EventRenameDestinationFile::ExistingFile(file)) => file.path().to_string_lossy().into_owned(),
                    Some(EventRenameDestinationFile::NewPath { directory, filename }) => {
                        format!(
                            "{}/{}",
                            directory.path().to_string_lossy(),
                            filename.to_string_lossy()
                        )
                    },
                    None => String::new(),
                };

                // For rename: deny if moving OUT of protected zone in AI context
                let mut cache = safe_cache.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                let deny_reason =
                    if !current_policy.is_protected(&source_path) || is_system_temp(&source_path, &home_for_handler) {
                        None
                    } else if let Some(ai_ancestor) = find_ai_ancestor(pid, &current_policy, &mut cache) {
                        let process_name = process_name_for_pid(pid).unwrap_or_else(|| format!("pid:{}", pid));
                        if should_allow_vcs_metadata_rename_in_ai_context(
                            &source_path,
                            &dest_path_str,
                            Some(process_name.as_str()),
                            &current_policy,
                        ) {
                            None
                        } else if current_policy.allow_trusted_tools_in_ai_context
                            && is_trusted_process_name(process_name.as_str(), &current_policy)
                        {
                            None
                        } else if !current_policy
                            .protected_zones
                            .iter()
                            .any(|zone| path_prefix_match(&dest_path_str, zone))
                        {
                            Some((process_name, ai_ancestor))
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                if let Some((proc_name, ancestor)) = deny_reason {
                    let zone = current_policy.matched_zone(&source_path);
                    println!(
                        "[DENY] rename by {} (via {}): {} -> {}",
                        proc_name, ancestor, source_path, dest_path_str
                    );
                    log_denial(
                        &home_for_handler,
                        &DenialRecord {
                            ts: now_ts(),
                            op: "rename".into(),
                            path: source_path.to_string(),
                            dest: Some(dest_path_str),
                            zone,
                            process: proc_name,
                            ancestor,
                        },
                    );
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_DENY, false);
                } else {
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                }
            },
            _ => {
                let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
            },
        }
    };

    println!("Attempting to create ES Client...");
    let mut client = Client::new(handler)
        .expect("Failed to create Endpoint Security client. Ensure you run as root and have proper entitlements.");

    client
        .subscribe(&[
            es_event_type_t::ES_EVENT_TYPE_AUTH_UNLINK,
            es_event_type_t::ES_EVENT_TYPE_AUTH_RENAME,
        ])
        .expect("Failed to subscribe");

    println!("Codex-ES-Guard started [process-aware mode]");
    println!("Policy: ~/.codex/es_policy.json");
    println!("Denial log: ~/.codex/es-guard/denials.jsonl");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
