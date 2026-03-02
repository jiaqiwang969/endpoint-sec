use endpoint_sec::sys::{es_auth_result_t, es_event_type_t};
use endpoint_sec::{Client, Event, EventRenameDestinationFile, Message};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::panic::AssertUnwindSafe;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CACHE_TTL_SECS: u64 = 5;
const DEFAULT_FILE_MODE: u32 = 0o644;
const DEFAULT_DIR_MODE: u32 = 0o700;
const RUNTIME_OVERRIDE_FILE_MODE: u32 = 0o600;
const OVERRIDE_DEFAULT_MINUTES: u64 = 3;
const OVERRIDE_MAX_MINUTES: u64 = 30;
const OVERRIDE_STORE_DIR: &str = "/var/db/codex-es-guard";
const MAX_OVERRIDE_PATH_LEN: usize = 4096;
const MAX_RUNTIME_OVERRIDES: usize = 512;
const MAX_OVERRIDE_REQUEST_SIZE_BYTES: u64 = 8192;
const MAX_OVERRIDE_REQUESTS_PER_MINUTE: usize = 120;
const MAX_OVERRIDE_REQUEST_FILES_PER_CYCLE: usize = 256;
const STALE_RESPONSE_RETENTION_SECS: u64 = 300;
const OVERRIDE_AUDIT_MAX_BYTES: u64 = 1_000_000;

#[derive(Debug, Deserialize)]
struct OverrideRequest {
    id: String,
    action: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    minutes: Option<u64>,
    #[serde(default)]
    requester_pid: Option<i32>,
}

#[derive(Debug, Serialize)]
struct OverrideResponse {
    id: String,
    status: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
struct SecurityPolicy {
    protected_zones: Vec<String>,
    temporary_overrides: Vec<TemporaryOverrideEntry>,

    #[serde(default = "default_auto_protect_home_digit_children")]
    auto_protect_home_digit_children: bool,

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

fn default_auto_protect_home_digit_children() -> bool {
    true
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

fn home_digit_root(path: &str, home: &str) -> Option<String> {
    let normalized_path = trim_trailing_slashes(path);
    let normalized_home = trim_trailing_slashes(home);
    let home_prefix = format!("{}/", normalized_home);

    if !normalized_path.starts_with(&home_prefix) {
        return None;
    }
    let suffix = &normalized_path[home_prefix.len()..];
    let first_component = suffix.split('/').next().unwrap_or("");
    if first_component.is_empty() {
        return None;
    }

    if first_component
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_digit())
    {
        Some(format!("{}/{}", normalized_home, first_component))
    } else {
        None
    }
}

fn normalize_absolute_path(path: &str) -> Option<String> {
    if !path.starts_with('/') {
        return None;
    }

    let mut parts: Vec<String> = Vec::new();
    for component in Path::new(path).components() {
        match component {
            Component::RootDir => {},
            Component::CurDir => {},
            Component::ParentDir => {
                let _ = parts.pop();
            },
            Component::Normal(segment) => {
                parts.push(segment.to_string_lossy().to_string());
            },
            _ => return None,
        }
    }

    if parts.is_empty() {
        Some("/".to_string())
    } else {
        Some(format!("/{}", parts.join("/")))
    }
}

fn sanitize_component(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        "default".to_string()
    } else {
        sanitized
    }
}

fn policy_user_name(home: &str) -> String {
    let fallback = "default";
    let base = Path::new(home)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(fallback);
    sanitize_component(base)
}

fn runtime_override_db_path(home: &str) -> PathBuf {
    let user = policy_user_name(home);
    PathBuf::from(OVERRIDE_STORE_DIR).join(format!("{}.json", user))
}

fn override_request_dir(home: &str) -> PathBuf {
    PathBuf::from(home)
        .join(".codex")
        .join("es-guard")
        .join("override-requests")
}

fn request_response_path(request_dir: &Path, id: &str) -> PathBuf {
    request_dir.join(format!("{}.response.json", sanitize_component(id)))
}

fn ensure_guard_dirs(home: &str) -> io::Result<PathBuf> {
    let codex_dir = PathBuf::from(home).join(".codex");
    ensure_dir_not_symlink(&codex_dir, DEFAULT_DIR_MODE)?;

    let guard_dir = codex_dir.join("es-guard");
    ensure_dir_not_symlink(&guard_dir, DEFAULT_DIR_MODE)?;
    Ok(guard_dir)
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

#[derive(Debug, Serialize)]
struct OverrideAuditRecord {
    ts: u64,
    request_id: String,
    action: String,
    path: Option<String>,
    minutes: Option<u64>,
    status: String,
    message: String,
    requester_pid: Option<i32>,
    requester_process: Option<String>,
}

impl SecurityPolicy {
    fn is_override_active_for_path(&self, target_path: &str, now: u64) -> bool {
        self.temporary_overrides
            .iter()
            .any(|entry| !entry.is_expired(now) && path_prefix_match(target_path, entry.path()))
    }

    fn is_in_configured_zone(&self, target_path: &str) -> bool {
        self.protected_zones
            .iter()
            .any(|zone| path_prefix_match(target_path, zone))
    }

    fn is_in_auto_home_digit_zone(&self, target_path: &str, home: &str) -> bool {
        self.auto_protect_home_digit_children && home_digit_root(target_path, home).is_some()
    }

    fn is_in_any_zone(&self, target_path: &str, home: &str) -> bool {
        self.is_in_configured_zone(target_path) || self.is_in_auto_home_digit_zone(target_path, home)
    }

    fn is_protected(&self, target_path: &str, home: &str) -> bool {
        let in_zone = self.is_in_any_zone(target_path, home);
        if !in_zone {
            return false;
        }

        let is_overridden = self.is_override_active_for_path(target_path, now_ts());
        if is_overridden {
            return false;
        }

        true
    }

    fn matched_zone(&self, target_path: &str, home: &str) -> String {
        if let Some(zone) = self
            .protected_zones
            .iter()
            .find(|zone| path_prefix_match(target_path, zone.as_str()))
            .cloned()
        {
            return zone;
        }

        if self.auto_protect_home_digit_children {
            if let Some(auto_zone) = home_digit_root(target_path, home) {
                return auto_zone;
            }
        }

        String::new()
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

    fn sanitize_overrides(&mut self, now: u64, home: &str) -> bool {
        let before = self.temporary_overrides.len();
        let protected_zones = self.protected_zones.clone();
        let auto_home_digit = self.auto_protect_home_digit_children;
        self.temporary_overrides.retain(|entry| {
            let path = entry.path();
            let in_configured_zone = protected_zones
                .iter()
                .any(|zone| path_prefix_match(path, zone.as_str()));
            let in_auto_zone = auto_home_digit && home_digit_root(path, home).is_some();
            !entry.is_expired(now)
                && !path.is_empty()
                && path.starts_with('/')
                && path != "/"
                && (in_configured_zone || in_auto_zone)
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

fn load_runtime_overrides(path: &Path) -> io::Result<Vec<TemporaryOverrideEntry>> {
    let mut file = match open_read_no_follow(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
        Err(err) => return Err(err),
    };
    verify_regular_file(&file, path)?;

    let mut content = String::new();
    file.read_to_string(&mut content)?;
    let decoded = serde_json::from_str::<Vec<TemporaryOverrideEntry>>(&content)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    Ok(decoded)
}

fn save_runtime_overrides(path: &Path, overrides: &[TemporaryOverrideEntry]) -> io::Result<()> {
    let lock_path = PathBuf::from(format!("{}.lock", path.display()));
    let _lock = acquire_lock_dir(&lock_path)?;

    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "override path has no parent"))?;
    ensure_dir_not_symlink(parent, DEFAULT_DIR_MODE)?;

    let existing_meta = match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "refuse to save runtime overrides via symlink",
                ));
            }
            if !meta.file_type().is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "runtime override path is not a regular file",
                ));
            }
            Some(meta)
        },
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(err) => return Err(err),
    };

    let serialized =
        serde_json::to_vec_pretty(overrides).map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;

    let final_mode = existing_meta
        .as_ref()
        .map(|m| m.mode() & 0o777)
        .unwrap_or(RUNTIME_OVERRIDE_FILE_MODE);
    let fallback_owner = fs::symlink_metadata(parent).ok().map(|meta| (meta.uid(), meta.gid()));
    let final_owner = existing_meta
        .as_ref()
        .map(|meta| (meta.uid(), meta.gid()))
        .or(fallback_owner);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("overrides.json");

    let mut tmp_path: Option<PathBuf> = None;
    let mut tmp_file: Option<File> = None;
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
            .mode(RUNTIME_OVERRIDE_FILE_MODE)
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
            "failed to allocate temp runtime override file",
        )
    })?;
    let mut tmp_file = tmp_file.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Other,
            "failed to open temp runtime override file",
        )
    })?;
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

fn is_dangerous_override_path(path: &str, policy: &SecurityPolicy, home: &str) -> bool {
    let normalized = trim_trailing_slashes(path);
    let normalized_home = trim_trailing_slashes(home);

    if normalized == "/" || normalized == normalized_home {
        return true;
    }
    if policy
        .protected_zones
        .iter()
        .any(|zone| trim_trailing_slashes(zone.as_str()) == normalized)
    {
        return true;
    }
    if policy.auto_protect_home_digit_children {
        if let Some(auto_root) = home_digit_root(normalized, home) {
            if trim_trailing_slashes(auto_root.as_str()) == normalized {
                return true;
            }
        }
    }
    false
}

fn apply_override_request(
    req: &OverrideRequest,
    policy: &SecurityPolicy,
    home: &str,
    overrides: &mut Vec<TemporaryOverrideEntry>,
) -> (bool, OverrideResponse) {
    let action = req.action.trim().to_lowercase();
    match action.as_str() {
        "grant" => {
            let raw_path = match req.path.as_deref() {
                Some(path) => path.trim(),
                None => "",
            };
            if raw_path.is_empty() {
                return (
                    false,
                    OverrideResponse {
                        id: req.id.clone(),
                        status: "error".to_string(),
                        message: "missing path".to_string(),
                        expires_at: None,
                    },
                );
            }
            let path = match normalize_absolute_path(raw_path) {
                Some(path) => path,
                None => {
                    return (
                        false,
                        OverrideResponse {
                            id: req.id.clone(),
                            status: "error".to_string(),
                            message: "invalid absolute path".to_string(),
                            expires_at: None,
                        },
                    );
                },
            };
            if path == "/" {
                return (
                    false,
                    OverrideResponse {
                        id: req.id.clone(),
                        status: "error".to_string(),
                        message: "invalid absolute path".to_string(),
                        expires_at: None,
                    },
                );
            }
            if path.len() > MAX_OVERRIDE_PATH_LEN {
                return (
                    false,
                    OverrideResponse {
                        id: req.id.clone(),
                        status: "error".to_string(),
                        message: format!("path too long (max {})", MAX_OVERRIDE_PATH_LEN),
                        expires_at: None,
                    },
                );
            }
            if !policy.is_in_any_zone(path.as_str(), home) {
                return (
                    false,
                    OverrideResponse {
                        id: req.id.clone(),
                        status: "error".to_string(),
                        message: "path outside protected zones".to_string(),
                        expires_at: None,
                    },
                );
            }
            if is_dangerous_override_path(path.as_str(), policy, home) {
                return (
                    false,
                    OverrideResponse {
                        id: req.id.clone(),
                        status: "error".to_string(),
                        message: "broad path override is not allowed".to_string(),
                        expires_at: None,
                    },
                );
            }

            let minutes = req.minutes.unwrap_or(OVERRIDE_DEFAULT_MINUTES);
            if minutes == 0 {
                return (
                    false,
                    OverrideResponse {
                        id: req.id.clone(),
                        status: "error".to_string(),
                        message: "no-expire override is disabled for automated requests".to_string(),
                        expires_at: None,
                    },
                );
            }
            if minutes > OVERRIDE_MAX_MINUTES {
                return (
                    false,
                    OverrideResponse {
                        id: req.id.clone(),
                        status: "error".to_string(),
                        message: format!("minutes exceeds max allowed ({})", OVERRIDE_MAX_MINUTES),
                        expires_at: None,
                    },
                );
            }

            let now = now_ts();
            let expires_at = now.saturating_add(minutes.saturating_mul(60));
            let normalized = path.clone();
            overrides.retain(|entry| trim_trailing_slashes(entry.path()) != normalized.as_str());
            if overrides.len() >= MAX_RUNTIME_OVERRIDES {
                return (
                    false,
                    OverrideResponse {
                        id: req.id.clone(),
                        status: "error".to_string(),
                        message: format!("too many active overrides (max {})", MAX_RUNTIME_OVERRIDES),
                        expires_at: None,
                    },
                );
            }
            overrides.push(TemporaryOverrideEntry::Rule(TemporaryOverrideRule {
                path,
                expires_at: Some(expires_at),
                created_at: Some(now),
                created_by: Some("es-guard-helper".to_string()),
            }));

            (
                true,
                OverrideResponse {
                    id: req.id.clone(),
                    status: "ok".to_string(),
                    message: format!("override granted for {} minute(s)", minutes),
                    expires_at: Some(expires_at),
                },
            )
        },
        "remove" => {
            let raw_path = match req.path.as_deref() {
                Some(path) => path.trim(),
                None => "",
            };
            if raw_path.is_empty() {
                return (
                    false,
                    OverrideResponse {
                        id: req.id.clone(),
                        status: "error".to_string(),
                        message: "missing path".to_string(),
                        expires_at: None,
                    },
                );
            }
            let path = match normalize_absolute_path(raw_path) {
                Some(path) => path,
                None => {
                    return (
                        false,
                        OverrideResponse {
                            id: req.id.clone(),
                            status: "error".to_string(),
                            message: "invalid absolute path".to_string(),
                            expires_at: None,
                        },
                    );
                },
            };
            if path.len() > MAX_OVERRIDE_PATH_LEN {
                return (
                    false,
                    OverrideResponse {
                        id: req.id.clone(),
                        status: "error".to_string(),
                        message: format!("path too long (max {})", MAX_OVERRIDE_PATH_LEN),
                        expires_at: None,
                    },
                );
            }
            let before = overrides.len();
            overrides.retain(|entry| trim_trailing_slashes(entry.path()) != path.as_str());
            let removed = before.saturating_sub(overrides.len());
            (
                removed > 0,
                OverrideResponse {
                    id: req.id.clone(),
                    status: "ok".to_string(),
                    message: format!("removed {} override entries", removed),
                    expires_at: None,
                },
            )
        },
        "clear" => {
            let changed = !overrides.is_empty();
            overrides.clear();
            (
                changed,
                OverrideResponse {
                    id: req.id.clone(),
                    status: "ok".to_string(),
                    message: "all overrides cleared".to_string(),
                    expires_at: None,
                },
            )
        },
        _ => (
            false,
            OverrideResponse {
                id: req.id.clone(),
                status: "error".to_string(),
                message: format!("unknown action: {}", req.action),
                expires_at: None,
            },
        ),
    }
}

fn consume_override_request_budget(window: &mut VecDeque<u64>, now: u64) -> bool {
    while let Some(oldest) = window.front().copied() {
        if now.saturating_sub(oldest) < 60 {
            break;
        }
        let _ = window.pop_front();
    }

    if window.len() >= MAX_OVERRIDE_REQUESTS_PER_MINUTE {
        return false;
    }

    window.push_back(now);
    true
}

fn validate_override_request_origin(req: &OverrideRequest, policy: &SecurityPolicy) -> Result<(i32, String), String> {
    let pid = req.requester_pid.ok_or_else(|| "missing requester_pid".to_string())?;
    if pid <= 1 {
        return Err("invalid requester_pid".to_string());
    }

    let process = get_process_info(pid)
        .map(|(_, comm)| {
            if comm.trim().is_empty() {
                format!("pid:{}", pid)
            } else {
                comm
            }
        })
        .ok_or_else(|| format!("requester pid {} is not alive; retry request", pid))?;

    let mut cache = HashMap::new();
    if let Some(ai_ancestor) = find_ai_ancestor(pid, policy, &mut cache) {
        return Err(format!(
            "AI-originated override request is blocked (ancestor: {})",
            ai_ancestor
        ));
    }

    Ok((pid, process))
}

fn write_override_response(response_path: &Path, response: &OverrideResponse) -> io::Result<()> {
    let mut file = open_truncate_no_follow(response_path, DEFAULT_FILE_MODE)?;
    verify_regular_file(&file, response_path)?;
    let content = serde_json::to_vec(response).map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    file.write_all(&content)?;
    file.sync_data()?;
    Ok(())
}

fn prune_stale_response_files(request_dir: &Path, now: u64) {
    let Ok(iter) = fs::read_dir(request_dir) else {
        return;
    };

    for entry in iter.filter_map(Result::ok) {
        let path = entry.path();
        let is_response = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".response.json"));
        if !is_response {
            continue;
        }

        let modified_secs = match fs::metadata(&path)
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|mtime| mtime.duration_since(UNIX_EPOCH).ok())
            .map(|delta| delta.as_secs())
        {
            Some(ts) => ts,
            None => continue,
        };
        if now.saturating_sub(modified_secs) <= STALE_RESPONSE_RETENTION_SECS {
            continue;
        }
        if let Err(err) = fs::remove_file(&path) {
            eprintln!(
                "[override] failed to prune stale response {}: {}",
                path.display(),
                err
            );
        }
    }
}

fn log_override_audit(home: &str, record: &OverrideAuditRecord) {
    let guard_dir = match ensure_guard_dirs(home) {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("[audit] cannot use guard dir: {}", err);
            return;
        },
    };

    let log_path = guard_dir.join("override-audit.jsonl");
    if let Ok(json) = serde_json::to_string(record) {
        if let Ok(mut file) = open_append_no_follow(&log_path, DEFAULT_FILE_MODE) {
            if verify_regular_file(&file, &log_path).is_ok() {
                if let Ok(meta) = file.metadata() {
                    if meta.len() > OVERRIDE_AUDIT_MAX_BYTES {
                        let _ = file.set_len(0);
                    }
                }
                let _ = writeln!(file, "{}", json);
            }
        }
    }
}

fn process_override_requests(
    request_dir: &Path,
    policy: &SecurityPolicy,
    home: &str,
    overrides: &mut Vec<TemporaryOverrideEntry>,
    request_window: &mut VecDeque<u64>,
) -> bool {
    let guard_dir = match ensure_guard_dirs(home) {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("[override] cannot use guard dir: {}", err);
            return false;
        },
    };

    let expected_request_dir = guard_dir.join("override-requests");
    let active_request_dir = if request_dir == expected_request_dir.as_path() {
        request_dir
    } else {
        &expected_request_dir
    };

    if let Err(err) = ensure_dir_not_symlink(active_request_dir, DEFAULT_DIR_MODE) {
        eprintln!("[override] cannot use request dir: {}", err);
        return false;
    }
    prune_stale_response_files(active_request_dir, now_ts());

    let mut request_files: Vec<PathBuf> = match fs::read_dir(active_request_dir) {
        Ok(iter) => iter
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".request.json"))
            })
            .collect(),
        Err(err) => {
            eprintln!("[override] failed to scan request dir: {}", err);
            return false;
        },
    };
    request_files.sort();
    if request_files.len() > MAX_OVERRIDE_REQUEST_FILES_PER_CYCLE {
        request_files.truncate(MAX_OVERRIDE_REQUEST_FILES_PER_CYCLE);
    }

    let mut changed = false;
    for request_path in request_files {
        let request_id = request_path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".request.json"))
            .map(sanitize_component)
            .unwrap_or_else(|| format!("unknown-{}", now_ts()));
        let response_path = request_response_path(active_request_dir, &request_id);
        let request_action = "unknown".to_string();
        let request_path_value: Option<String> = None;
        let request_minutes: Option<u64> = None;
        let request_pid: Option<i32> = None;

        if !consume_override_request_budget(request_window, now_ts()) {
            let response = OverrideResponse {
                id: request_id.clone(),
                status: "error".to_string(),
                message: format!(
                    "override request rate limit exceeded (max {} per minute)",
                    MAX_OVERRIDE_REQUESTS_PER_MINUTE
                ),
                expires_at: None,
            };
            let _ = write_override_response(&response_path, &response);
            log_override_audit(
                home,
                &OverrideAuditRecord {
                    ts: now_ts(),
                    request_id: request_id.clone(),
                    action: request_action.clone(),
                    path: request_path_value.clone(),
                    minutes: request_minutes,
                    status: response.status.clone(),
                    message: response.message.clone(),
                    requester_pid: request_pid,
                    requester_process: None,
                },
            );
            let _ = fs::remove_file(&request_path);
            continue;
        }

        let request = match open_read_no_follow(&request_path).and_then(|mut file| {
            verify_regular_file(&file, &request_path)?;
            let meta = file.metadata()?;
            if meta.len() > MAX_OVERRIDE_REQUEST_SIZE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "request too large ({} bytes > {})",
                        meta.len(),
                        MAX_OVERRIDE_REQUEST_SIZE_BYTES
                    ),
                ));
            }
            let mut content = String::new();
            file.read_to_string(&mut content)?;
            serde_json::from_str::<OverrideRequest>(&content)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
        }) {
            Ok(req) => req,
            Err(err) => {
                let response = OverrideResponse {
                    id: request_id.clone(),
                    status: "error".to_string(),
                    message: format!("invalid request: {}", err),
                    expires_at: None,
                };
                let _ = write_override_response(&response_path, &response);
                log_override_audit(
                    home,
                    &OverrideAuditRecord {
                        ts: now_ts(),
                        request_id: request_id.clone(),
                        action: request_action.clone(),
                        path: request_path_value.clone(),
                        minutes: request_minutes,
                        status: response.status.clone(),
                        message: response.message.clone(),
                        requester_pid: request_pid,
                        requester_process: None,
                    },
                );
                let _ = fs::remove_file(&request_path);
                continue;
            },
        };

        let mut request = request;
        request.id = request_id.clone();
        let request_action = request.action.clone();
        let request_path_value = request.path.clone();
        let request_minutes = request.minutes;
        let request_pid = request.requester_pid;

        let (requester_pid, requester_process) = match validate_override_request_origin(&request, policy) {
            Ok((pid, process)) => (Some(pid), Some(process)),
            Err(err) => {
                let response = OverrideResponse {
                    id: request_id.clone(),
                    status: "error".to_string(),
                    message: err,
                    expires_at: None,
                };
                let _ = write_override_response(&response_path, &response);
                log_override_audit(
                    home,
                    &OverrideAuditRecord {
                        ts: now_ts(),
                        request_id: request_id.clone(),
                        action: request_action.clone(),
                        path: request_path_value.clone(),
                        minutes: request_minutes,
                        status: response.status.clone(),
                        message: response.message.clone(),
                        requester_pid: request_pid,
                        requester_process: None,
                    },
                );
                if let Err(remove_err) = fs::remove_file(&request_path) {
                    eprintln!("[override] failed to remove request file: {}", remove_err);
                }
                continue;
            },
        };

        let response_path = request_response_path(active_request_dir, request.id.as_str());
        let (request_changed, response) = apply_override_request(&request, policy, home, overrides);
        if request_changed {
            changed = true;
        }
        log_override_audit(
            home,
            &OverrideAuditRecord {
                ts: now_ts(),
                request_id: request.id.clone(),
                action: request_action,
                path: request_path_value,
                minutes: request_minutes,
                status: response.status.clone(),
                message: response.message.clone(),
                requester_pid,
                requester_process,
            },
        );
        if let Err(err) = write_override_response(&response_path, &response) {
            eprintln!("[override] failed to write response: {}", err);
        }
        if let Err(err) = fs::remove_file(&request_path) {
            eprintln!("[override] failed to remove request file: {}", err);
        }
    }

    changed
}

fn is_system_temp(path: &str, home: &str) -> bool {
    path_prefix_match(path, &format!("{}/.Trash", home))
        || path_prefix_match(path, "/private/tmp")
        || path_prefix_match(path, "/private/var/folders")
        || path.ends_with(".DS_Store")
}

fn log_denial(home: &str, record: &DenialRecord) {
    let guard_dir = match ensure_guard_dirs(home) {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("[log] cannot use guard dir: {}", err);
            return;
        },
    };

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
         (Short TTL only; no-expire is rejected by helper)\n\
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
    if !policy.is_protected(path, home) {
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

    fn test_policy() -> SecurityPolicy {
        SecurityPolicy {
            protected_zones: vec!["/Users/jqwang/project".to_string()],
            temporary_overrides: vec![],
            auto_protect_home_digit_children: true,
            allow_vcs_metadata_in_ai_context: true,
            trusted_tools: default_trusted_tools(),
            ai_agent_patterns: default_ai_agent_patterns(),
            allow_trusted_tools_in_ai_context: false,
        }
    }

    #[test]
    fn legacy_override_path_still_decodes_and_applies() {
        let json = r#"{
            "protected_zones": ["/Users/jqwang/0"],
            "temporary_overrides": ["/Users/jqwang/00-nixos-config/nixos-config"]
        }"#;
        let policy: SecurityPolicy = serde_json::from_str(json).expect("policy json should decode");
        assert!(
            !policy.is_protected(
                "/Users/jqwang/00-nixos-config/nixos-config/file.txt",
                "/Users/jqwang"
            ),
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
            auto_protect_home_digit_children: false,
            allow_vcs_metadata_in_ai_context: true,
            trusted_tools: default_trusted_tools(),
            ai_agent_patterns: default_ai_agent_patterns(),
            allow_trusted_tools_in_ai_context: false,
        };

        let changed = policy.sanitize_overrides(100, "/Users/jqwang");
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
            auto_protect_home_digit_children: false,
            allow_vcs_metadata_in_ai_context: true,
            trusted_tools: default_trusted_tools(),
            ai_agent_patterns: default_ai_agent_patterns(),
            allow_trusted_tools_in_ai_context: false,
        };

        let changed = policy.sanitize_overrides(1, "/Users/jqwang");
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
    fn normalize_absolute_path_collapses_dot_segments() {
        assert_eq!(
            normalize_absolute_path("/Users/jqwang/project/./a/../b.txt"),
            Some("/Users/jqwang/project/b.txt".to_string())
        );
        assert_eq!(
            normalize_absolute_path("/Users/jqwang/project/../../.ssh/id_rsa"),
            Some("/Users/.ssh/id_rsa".to_string())
        );
        assert_eq!(normalize_absolute_path("relative/path"), None);
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
            auto_protect_home_digit_children: false,
            allow_vcs_metadata_in_ai_context: true,
            trusted_tools: default_trusted_tools(),
            ai_agent_patterns: default_ai_agent_patterns(),
            allow_trusted_tools_in_ai_context: false,
        };

        let changed = policy.sanitize_overrides(1, "/Users/jqwang");
        assert!(changed, "invalid paths should be removed");
        assert_eq!(policy.temporary_overrides.len(), 1);
        assert_eq!(
            policy.temporary_overrides[0].path(),
            "/Users/jqwang/project/file.txt"
        );
    }

    #[test]
    fn home_digit_root_matches_first_path_component() {
        assert_eq!(
            home_digit_root("/Users/jqwang/01-agent/new-codex", "/Users/jqwang"),
            Some("/Users/jqwang/01-agent".to_string())
        );
        assert_eq!(
            home_digit_root("/Users/jqwang/0x-lab/demo.txt", "/Users/jqwang"),
            Some("/Users/jqwang/0x-lab".to_string())
        );
        assert_eq!(
            home_digit_root("/Users/jqwang/dev/project", "/Users/jqwang"),
            None
        );
        assert_eq!(home_digit_root("/tmp/01-agent", "/Users/jqwang"), None);
    }

    #[test]
    fn auto_home_digit_zone_applies_protection() {
        let policy = SecurityPolicy {
            protected_zones: vec![],
            temporary_overrides: vec![],
            auto_protect_home_digit_children: true,
            allow_vcs_metadata_in_ai_context: true,
            trusted_tools: default_trusted_tools(),
            ai_agent_patterns: default_ai_agent_patterns(),
            allow_trusted_tools_in_ai_context: false,
        };

        assert!(policy.is_protected("/Users/jqwang/01-agent/file.txt", "/Users/jqwang"));
        assert!(policy.is_protected("/Users/jqwang/0x-lab/file.txt", "/Users/jqwang"));
        assert!(!policy.is_protected("/Users/jqwang/dev/file.txt", "/Users/jqwang"));
        assert!(!policy.is_protected("/tmp/01-agent/file.txt", "/Users/jqwang"));
    }

    #[test]
    fn sanitize_overrides_keeps_auto_home_digit_entries() {
        let mut policy = SecurityPolicy {
            protected_zones: vec![],
            temporary_overrides: vec![
                TemporaryOverrideEntry::Path("/Users/jqwang/01-agent/file.txt".to_string()),
                TemporaryOverrideEntry::Path("/Users/jqwang/dev/file.txt".to_string()),
            ],
            auto_protect_home_digit_children: true,
            allow_vcs_metadata_in_ai_context: true,
            trusted_tools: default_trusted_tools(),
            ai_agent_patterns: default_ai_agent_patterns(),
            allow_trusted_tools_in_ai_context: false,
        };

        let changed = policy.sanitize_overrides(1, "/Users/jqwang");
        assert!(changed, "outside auto-zone entries should be removed");
        assert_eq!(policy.temporary_overrides.len(), 1);
        assert_eq!(
            policy.temporary_overrides[0].path(),
            "/Users/jqwang/01-agent/file.txt"
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

    #[test]
    fn apply_override_request_rejects_no_expire() {
        let policy = test_policy();
        let mut overrides = Vec::new();
        let request = OverrideRequest {
            id: "req-1".to_string(),
            action: "grant".to_string(),
            path: Some("/Users/jqwang/project/file.txt".to_string()),
            minutes: Some(0),
            requester_pid: None,
        };

        let (changed, response) = apply_override_request(&request, &policy, "/Users/jqwang", &mut overrides);
        assert!(!changed);
        assert_eq!(response.status, "error");
        assert!(response.message.contains("no-expire"));
        assert!(overrides.is_empty());
    }

    #[test]
    fn apply_override_request_rejects_zone_root_path() {
        let policy = test_policy();
        let mut overrides = Vec::new();
        let request = OverrideRequest {
            id: "req-2".to_string(),
            action: "grant".to_string(),
            path: Some("/Users/jqwang/project".to_string()),
            minutes: Some(3),
            requester_pid: None,
        };

        let (changed, response) = apply_override_request(&request, &policy, "/Users/jqwang", &mut overrides);
        assert!(!changed);
        assert_eq!(response.status, "error");
        assert!(response.message.contains("broad path"));
        assert!(overrides.is_empty());
    }

    #[test]
    fn apply_override_request_rejects_too_long_path() {
        let policy = test_policy();
        let mut overrides = Vec::new();
        let long_suffix = "a".repeat(MAX_OVERRIDE_PATH_LEN);
        let request = OverrideRequest {
            id: "req-long".to_string(),
            action: "grant".to_string(),
            path: Some(format!("/Users/jqwang/project/{}", long_suffix)),
            minutes: Some(1),
            requester_pid: None,
        };

        let (changed, response) = apply_override_request(&request, &policy, "/Users/jqwang", &mut overrides);
        assert!(!changed);
        assert_eq!(response.status, "error");
        assert!(response.message.contains("path too long"));
        assert!(overrides.is_empty());
    }

    #[test]
    fn apply_override_request_rejects_when_override_pool_full() {
        let policy = test_policy();
        let mut overrides = (0..MAX_RUNTIME_OVERRIDES)
            .map(|idx| {
                TemporaryOverrideEntry::Rule(TemporaryOverrideRule {
                    path: format!("/Users/jqwang/project/file-{}", idx),
                    expires_at: Some(now_ts().saturating_add(60)),
                    created_at: Some(now_ts()),
                    created_by: Some("seed".to_string()),
                })
            })
            .collect::<Vec<_>>();
        let request = OverrideRequest {
            id: "req-full".to_string(),
            action: "grant".to_string(),
            path: Some("/Users/jqwang/project/new-file".to_string()),
            minutes: Some(1),
            requester_pid: None,
        };

        let (changed, response) = apply_override_request(&request, &policy, "/Users/jqwang", &mut overrides);
        assert!(!changed);
        assert_eq!(response.status, "error");
        assert!(response.message.contains("too many active overrides"));
        assert_eq!(overrides.len(), MAX_RUNTIME_OVERRIDES);
    }

    #[test]
    fn override_request_budget_limits_per_minute() {
        let mut window = std::collections::VecDeque::new();
        for _ in 0..MAX_OVERRIDE_REQUESTS_PER_MINUTE {
            assert!(consume_override_request_budget(&mut window, 100));
        }
        assert!(!consume_override_request_budget(&mut window, 100));
        assert!(consume_override_request_budget(&mut window, 161));
    }

    #[test]
    fn validate_override_request_origin_requires_pid() {
        let policy = test_policy();
        let missing_pid = OverrideRequest {
            id: "req-origin-1".to_string(),
            action: "grant".to_string(),
            path: Some("/Users/jqwang/project/file.txt".to_string()),
            minutes: Some(1),
            requester_pid: None,
        };
        let err = validate_override_request_origin(&missing_pid, &policy).expect_err("pid is required");
        assert!(err.contains("missing requester_pid"));

        let invalid_pid = OverrideRequest {
            id: "req-origin-2".to_string(),
            action: "grant".to_string(),
            path: Some("/Users/jqwang/project/file.txt".to_string()),
            minutes: Some(1),
            requester_pid: Some(0),
        };
        let err = validate_override_request_origin(&invalid_pid, &policy).expect_err("pid must be positive");
        assert!(err.contains("invalid requester_pid"));
    }
}

fn main() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let policy_path = format!("{}/.codex/es_policy.json", home);
    let home_for_reload = home.clone();
    let runtime_override_path = runtime_override_db_path(&home);
    let request_dir_path = override_request_dir(&home);

    let mut initial_policy = load_policy(&policy_path).unwrap_or_default();
    initial_policy.temporary_overrides.clear();
    let mut runtime_overrides = match load_runtime_overrides(&runtime_override_path) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!("[override] failed to load runtime overrides: {}", err);
            Vec::new()
        },
    };
    initial_policy.temporary_overrides = runtime_overrides.clone();
    if initial_policy.sanitize_overrides(now_ts(), &home) {
        runtime_overrides = initial_policy.temporary_overrides.clone();
        if let Err(err) = save_runtime_overrides(&runtime_override_path, &runtime_overrides) {
            eprintln!(
                "[override] failed to persist sanitized runtime overrides: {}",
                err
            );
        }
    }
    if let Err(err) = save_policy(&policy_path, &initial_policy) {
        eprintln!("[policy] failed to write initial policy snapshot: {}", err);
    }

    let global_policy = Arc::new(Mutex::new(initial_policy));

    // Process ancestry cache (cleared on policy reload)
    let ancestor_cache: Arc<Mutex<HashMap<i32, CachedAncestor>>> = Arc::new(Mutex::new(HashMap::new()));

    // Policy hot-reload thread (1s polling)
    let policy_clone = global_policy.clone();
    let cache_clone = ancestor_cache.clone();
    let path_clone = policy_path.clone();
    let override_path_clone = runtime_override_path.clone();
    let request_path_clone = request_dir_path.clone();
    thread::spawn(move || {
        let mut static_policy = load_policy(&path_clone).unwrap_or_default();
        static_policy.temporary_overrides.clear();
        let mut runtime_overrides = match load_runtime_overrides(&override_path_clone) {
            Ok(entries) => entries,
            Err(err) => {
                eprintln!("[override] failed to load runtime overrides: {}", err);
                Vec::new()
            },
        };
        let mut request_window: VecDeque<u64> = VecDeque::new();
        let mut last_policy_mtime = fs::metadata(&path_clone)
            .and_then(|meta| meta.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let mut last_override_mtime = fs::metadata(&override_path_clone)
            .and_then(|meta| meta.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);

        loop {
            let mut changed = false;
            let mut overrides_changed = false;
            let mut should_mirror_policy = false;

            if let Ok(metadata) = fs::metadata(&path_clone) {
                if let Ok(mtime) = metadata.modified() {
                    if mtime != last_policy_mtime {
                        if let Some(mut new_policy) = load_policy(&path_clone) {
                            new_policy.temporary_overrides.clear();
                            static_policy = new_policy;
                            last_policy_mtime = mtime;
                            changed = true;
                            should_mirror_policy = true;
                            println!("[policy] reloaded static config");
                        }
                    }
                }
            }

            if let Ok(metadata) = fs::metadata(&override_path_clone) {
                if let Ok(mtime) = metadata.modified() {
                    if mtime != last_override_mtime {
                        match load_runtime_overrides(&override_path_clone) {
                            Ok(entries) => {
                                runtime_overrides = entries;
                                last_override_mtime = mtime;
                                changed = true;
                            },
                            Err(err) => {
                                eprintln!("[override] failed to reload runtime overrides: {}", err);
                            },
                        }
                    }
                }
            }

            if process_override_requests(
                &request_path_clone,
                &static_policy,
                &home_for_reload,
                &mut runtime_overrides,
                &mut request_window,
            ) {
                changed = true;
                overrides_changed = true;
            }

            let mut combined_policy = static_policy.clone();
            combined_policy.temporary_overrides = runtime_overrides.clone();
            if combined_policy.sanitize_overrides(now_ts(), &home_for_reload) {
                runtime_overrides = combined_policy.temporary_overrides.clone();
                combined_policy.temporary_overrides = runtime_overrides.clone();
                changed = true;
                overrides_changed = true;
            }

            if overrides_changed {
                if let Err(err) = save_runtime_overrides(&override_path_clone, &runtime_overrides) {
                    eprintln!("[override] failed to persist runtime overrides: {}", err);
                } else {
                    should_mirror_policy = true;
                    if let Ok(metadata) = fs::metadata(&override_path_clone) {
                        if let Ok(mtime) = metadata.modified() {
                            last_override_mtime = mtime;
                        }
                    }
                }
            }

            if changed {
                combined_policy.temporary_overrides = runtime_overrides.clone();
                if let Ok(mut lock) = policy_clone.lock() {
                    *lock = combined_policy.clone();
                    if let Ok(mut c) = cache_clone.lock() {
                        c.clear();
                    }
                }
            }

            if should_mirror_policy {
                if let Err(err) = save_policy(&path_clone, &combined_policy) {
                    eprintln!("[policy] failed to mirror runtime overrides: {}", err);
                } else if let Ok(metadata) = fs::metadata(&path_clone) {
                    if let Ok(mtime) = metadata.modified() {
                        last_policy_mtime = mtime;
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
                    let zone = current_policy.matched_zone(&path, &home_for_handler);
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
                let deny_reason = if !current_policy.is_protected(&source_path, &home_for_handler)
                    || is_system_temp(&source_path, &home_for_handler)
                {
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
                    } else if !current_policy.is_in_any_zone(&dest_path_str, &home_for_handler) {
                        Some((process_name, ai_ancestor))
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some((proc_name, ancestor)) = deny_reason {
                    let zone = current_policy.matched_zone(&source_path, &home_for_handler);
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
