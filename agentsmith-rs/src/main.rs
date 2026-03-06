use agentsmith_rs_core::sys::{es_auth_result_t, es_event_type_t};
use agentsmith_rs_core::{Client, Event, EventCreateDestinationFile, EventRenameDestinationFile, Message};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::panic::AssertUnwindSafe;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CACHE_TTL_SECS: u64 = 5;
const TRUST_CACHE_TTL_SECS: u64 = 300;
const CODESIGN_BIN: &str = "/usr/bin/codesign";
const MAXCOMLEN: usize = 16;
const DEFAULT_FILE_MODE: u32 = 0o644;
const DEFAULT_DIR_MODE: u32 = 0o700;
const RUNTIME_OVERRIDE_FILE_MODE: u32 = 0o600;
const OVERRIDE_DEFAULT_MINUTES: u64 = 3;
const OVERRIDE_MAX_MINUTES: u64 = 30;
const OVERRIDE_STORE_DIR: &str = "/var/db/agentsmith-rs";
const MAX_OVERRIDE_PATH_LEN: usize = 4096;
const MAX_RUNTIME_OVERRIDES: usize = 512;
const MAX_OVERRIDE_REQUEST_SIZE_BYTES: u64 = 8192;
const MAX_OVERRIDE_REQUESTS_PER_MINUTE: usize = 120;
const MAX_OVERRIDE_REQUEST_FILES_PER_CYCLE: usize = 256;
const STALE_RESPONSE_RETENTION_SECS: u64 = 300;
const OVERRIDE_AUDIT_MAX_BYTES: u64 = 1_000_000;
const TAINT_AUDIT_MAX_BYTES: u64 = 1_000_000;
const OVERRIDE_CREATED_BY_HELPER: &str = "agentsmith-helper";
const OVERRIDE_CREATED_BY_SENSITIVE_READ_HELPER: &str = "agentsmith-helper-sensitive-read";
const FFLAG_READ: i32 = 0x0000_0001;
const FFLAG_WRITE: i32 = 0x0000_0002;
const DEFAULT_TAINT_TTL_SECS: u64 = 600;
const CACHE_WATERMARK_LOG_INTERVAL_SECS: u64 = 10;
const TRUST_CACHE_PRUNE_INTERVAL_SECS: u64 = 10;
const SIGNATURE_CACHE_TTL_SECS: u64 = 3600;
const SIGNATURE_ERROR_CACHE_TTL_SECS: u64 = 30;
const SIGNATURE_CACHE_PRUNE_INTERVAL_SECS: u64 = 60;
const SIGNATURE_REFRESH_QUEUE_BOUND: usize = 1024;
const LOG_EVENT_QUEUE_BOUND: usize = 2048;
const LOG_QUEUE_FULL_WARN_INTERVAL_SECS: u64 = 5;
const AUDIT_ONLY_LOG_MAX_BYTES: u64 = 1_000_000;
const RUNTIME_HEALTH_LOG_INTERVAL_SECS: u64 = 10;
const CALLBACK_LATENCY_BUCKETS_US: [u64; 12] = [
    100, 250, 500, 1_000, 2_000, 5_000, 10_000, 20_000, 50_000, 100_000, 250_000, 500_000,
];
const POLICY_SELF_CHECK_WARNING_INTERVAL_SECS: u64 = 300;
const REASON_SENSITIVE_READ_NON_AI: &str = "SENSITIVE_READ_NON_AI";
const REASON_SENSITIVE_TRANSFER_OUT: &str = "SENSITIVE_TRANSFER_OUT";
const REASON_TAINT_WRITE_OUT: &str = "TAINT_WRITE_OUT";
const REASON_EXEC_EXFIL_TOOL: &str = "EXEC_EXFIL_TOOL";
const REASON_PROTECTED_ZONE_AI_DELETE: &str = "PROTECTED_ZONE_AI_DELETE";
const REASON_TRUST_IDENTITY_MISMATCH: &str = "TRUST_IDENTITY_MISMATCH";
const TRUST_SIGNATURE_PENDING_PREFIX: &str = "signature verification pending";

static LOG_EVENT_TX: OnceLock<mpsc::SyncSender<GuardLogMessage>> = OnceLock::new();
static LOG_QUEUE_FULL_LAST_WARN_TS: AtomicU64 = AtomicU64::new(0);
static SIGNATURE_QUEUE_PENDING: AtomicU64 = AtomicU64::new(0);
static SIGNATURE_QUEUE_DROPPED_FULL: AtomicU64 = AtomicU64::new(0);
static SIGNATURE_QUEUE_DROPPED_DISCONNECTED: AtomicU64 = AtomicU64::new(0);
static LOG_QUEUE_PENDING: AtomicU64 = AtomicU64::new(0);
static LOG_QUEUE_DROPPED_FULL: AtomicU64 = AtomicU64::new(0);
static LOG_QUEUE_DROPPED_DISCONNECTED: AtomicU64 = AtomicU64::new(0);

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

    #[serde(default)]
    sensitive_zones: Vec<String>,

    #[serde(default)]
    sensitive_export_allow_zones: Vec<String>,

    #[serde(default = "default_auto_protect_home_digit_children")]
    auto_protect_home_digit_children: bool,

    #[serde(default = "default_allow_vcs_metadata_in_ai_context")]
    allow_vcs_metadata_in_ai_context: bool,

    #[serde(default = "default_allow_git_merge_pull_in_ai_context")]
    allow_git_merge_pull_in_ai_context: bool,

    #[serde(default = "default_trusted_tools")]
    trusted_tools: Vec<String>,

    #[serde(default)]
    trusted_tool_identities: Vec<TrustedToolIdentity>,

    #[serde(default = "default_ai_agent_patterns")]
    ai_agent_patterns: Vec<String>,

    #[serde(default)]
    allow_trusted_tools_in_ai_context: bool,

    #[serde(default = "default_exec_exfil_tool_blocklist")]
    exec_exfil_tool_blocklist: Vec<String>,

    #[serde(default = "default_true")]
    read_gate_enabled: bool,

    #[serde(default = "default_true")]
    transfer_gate_enabled: bool,

    #[serde(default = "default_true")]
    exec_gate_enabled: bool,

    #[serde(default)]
    audit_only_mode: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    taint_ttl_seconds: Option<u64>,

    #[serde(default)]
    trusted_identity_require_cdhash: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
struct TrustedToolIdentity {
    path: String,
    signing_identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    team_identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cdhash: Option<String>,
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

fn default_true() -> bool {
    true
}

fn default_allow_vcs_metadata_in_ai_context() -> bool {
    true
}

fn default_allow_git_merge_pull_in_ai_context() -> bool {
    true
}

fn default_ai_agent_patterns() -> Vec<String> {
    ["codex", "claude", "claude-code"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn default_exec_exfil_tool_blocklist() -> Vec<String> {
    ["curl", "wget", "scp", "sftp", "rsync", "nc", "ncat", "netcat"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

#[derive(Debug, Clone)]
struct CachedAncestor {
    ai_ancestor: Option<String>,
    updated_at: u64,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ProcessIdentityKey {
    pid: i32,
    start_tvsec: u64,
    start_tvusec: u64,
    executable_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessStartTimeKey {
    start_tvsec: u64,
    start_tvusec: u64,
}

#[derive(Debug, Clone)]
struct CachedTrustedProcess {
    decision: TrustedProcessDecision,
    updated_at: u64,
}

#[derive(Debug, Clone)]
struct CachedBinarySignature {
    signature: Result<BinaryCodeSignature, String>,
    updated_at: u64,
}

#[derive(Debug, Default)]
struct TrustedProcessCache {
    entries: HashMap<ProcessIdentityKey, CachedTrustedProcess>,
    last_prune_at: u64,
}

#[derive(Debug, Default)]
struct BinarySignatureCache {
    entries: HashMap<String, CachedBinarySignature>,
    in_flight: HashSet<String>,
    last_prune_at: u64,
}

impl TrustedProcessCache {
    fn len(&self) -> usize {
        self.entries.len()
    }

    fn clear_all(&mut self) {
        self.entries.clear();
        self.last_prune_at = 0;
    }

    fn clear_pid(&mut self, pid: i32) {
        invalidate_trust_cache_for_pid(&mut self.entries, pid);
    }

    fn maybe_prune(&mut self, now: u64) {
        if self.last_prune_at != 0 && now.saturating_sub(self.last_prune_at) < TRUST_CACHE_PRUNE_INTERVAL_SECS {
            return;
        }
        prune_trust_cache(&mut self.entries, now);
        self.last_prune_at = now;
    }

    fn get(&mut self, key: &ProcessIdentityKey, now: u64) -> Option<CachedTrustedProcess> {
        if let Some(entry) = self.entries.get(key).cloned() {
            if now.saturating_sub(entry.updated_at) <= TRUST_CACHE_TTL_SECS {
                self.maybe_prune(now);
                return Some(entry);
            }
            self.entries.remove(key);
        }
        self.maybe_prune(now);
        None
    }

    fn insert(&mut self, key: ProcessIdentityKey, decision: TrustedProcessDecision, now: u64) {
        self.maybe_prune(now);
        self.entries.insert(
            key,
            CachedTrustedProcess {
                decision,
                updated_at: now,
            },
        );
    }
}

impl BinarySignatureCache {
    fn entry_ttl_secs(entry: &CachedBinarySignature) -> u64 {
        if entry.signature.is_err() {
            SIGNATURE_ERROR_CACHE_TTL_SECS
        } else {
            SIGNATURE_CACHE_TTL_SECS
        }
    }

    fn clear_all(&mut self) {
        self.entries.clear();
        self.in_flight.clear();
        self.last_prune_at = 0;
    }

    fn maybe_prune(&mut self, now: u64) {
        if self.last_prune_at != 0 && now.saturating_sub(self.last_prune_at) < SIGNATURE_CACHE_PRUNE_INTERVAL_SECS {
            return;
        }
        self.entries
            .retain(|_, entry| now.saturating_sub(entry.updated_at) <= Self::entry_ttl_secs(entry));
        self.last_prune_at = now;
    }

    fn get(&mut self, canonical_path: &str, now: u64) -> Option<Result<BinaryCodeSignature, String>> {
        if let Some(entry) = self.entries.get(canonical_path).cloned() {
            if now.saturating_sub(entry.updated_at) <= Self::entry_ttl_secs(&entry) {
                self.maybe_prune(now);
                return Some(entry.signature);
            }
            self.entries.remove(canonical_path);
        }
        self.maybe_prune(now);
        None
    }

    fn insert(&mut self, canonical_path: String, signature: Result<BinaryCodeSignature, String>, now: u64) {
        self.maybe_prune(now);
        self.entries.insert(
            canonical_path.clone(),
            CachedBinarySignature {
                signature,
                updated_at: now,
            },
        );
        self.in_flight.remove(canonical_path.as_str());
    }

    fn should_enqueue_refresh(&mut self, canonical_path: &str) -> bool {
        self.in_flight.insert(canonical_path.to_string())
    }

    fn cancel_in_flight_refresh(&mut self, canonical_path: &str) {
        self.in_flight.remove(canonical_path);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TrustedProcessDecision {
    Trusted,
    NotTrusted,
    IdentityMismatch(String),
}

impl TrustedProcessDecision {
    fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted)
    }

    fn is_identity_mismatch(&self) -> bool {
        matches!(self, Self::IdentityMismatch(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BinaryCodeSignature {
    signing_identifier: String,
    team_identifier: Option<String>,
    cdhash: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct TaintEntry {
    touched_at: u64,
    process_start: Option<ProcessStartTimeKey>,
}

#[derive(Debug, Default)]
struct TaintState {
    ttl_secs: u64,
    touched: HashMap<i32, TaintEntry>,
}

impl TaintState {
    fn new(ttl_secs: u64) -> Self {
        Self {
            ttl_secs,
            touched: HashMap::new(),
        }
    }

    fn set_ttl_secs(&mut self, ttl_secs: u64) {
        self.ttl_secs = ttl_secs;
        self.prune_expired(now_ts());
    }

    fn mark(&mut self, pid: i32, ts: u64) {
        self.mark_with_process_start(pid, ts, None);
    }

    fn mark_with_process_start(&mut self, pid: i32, ts: u64, process_start: Option<ProcessStartTimeKey>) {
        self.prune_expired(ts);
        self.touched.insert(
            pid,
            TaintEntry {
                touched_at: ts,
                process_start,
            },
        );
    }

    fn is_tainted(&self, pid: i32, now: u64) -> bool {
        let entry = match self.touched.get(&pid) {
            Some(entry) => entry,
            None => return false,
        };

        if now.saturating_sub(entry.touched_at) > self.ttl_secs {
            return false;
        }

        match entry.process_start {
            Some(expected_start) => {
                process_start_time_for_pid(pid).is_some_and(|actual_start| actual_start == expected_start)
            },
            None => true,
        }
    }

    fn inherit_from_parent(&mut self, parent_pid: i32, child_pid: i32, now: u64) -> bool {
        if parent_pid <= 0 || child_pid <= 0 || parent_pid == child_pid {
            return false;
        }
        self.prune_expired(now);
        if !self.is_tainted(parent_pid, now) || self.is_tainted(child_pid, now) {
            return false;
        }
        self.touched.insert(
            child_pid,
            TaintEntry {
                touched_at: now,
                process_start: process_start_time_for_pid(child_pid),
            },
        );
        true
    }

    fn clear_pid(&mut self, pid: i32) {
        self.touched.remove(&pid);
    }

    fn prune_expired(&mut self, now: u64) {
        self.touched
            .retain(|_, entry| now.saturating_sub(entry.touched_at) <= self.ttl_secs);
    }

    fn len(&self) -> usize {
        self.touched.len()
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct CacheWatermarkHighs {
    ancestor: usize,
    trusted: usize,
    taint: usize,
}

impl CacheWatermarkHighs {
    fn update(&mut self, ancestor: usize, trusted: usize, taint: usize) -> (usize, usize, usize) {
        self.ancestor = self.ancestor.max(ancestor);
        self.trusted = self.trusted.max(trusted);
        self.taint = self.taint.max(taint);
        (self.ancestor, self.trusted, self.taint)
    }
}

#[derive(Debug)]
struct CallbackLatencyMetrics {
    counts: [AtomicU64; CALLBACK_LATENCY_BUCKETS_US.len() + 1],
    total: AtomicU64,
    max_us: AtomicU64,
}

#[derive(Debug, Clone)]
struct CallbackLatencySnapshot {
    counts: [u64; CALLBACK_LATENCY_BUCKETS_US.len() + 1],
    total: u64,
    max_us: u64,
}

impl CallbackLatencySnapshot {
    fn percentile_upper_bound_us(&self, percentile: u64) -> u64 {
        if self.total == 0 {
            return 0;
        }
        let target = ((self.total * percentile).saturating_add(99)) / 100;
        let mut seen = 0u64;
        for (idx, count) in self.counts.iter().enumerate() {
            seen = seen.saturating_add(*count);
            if seen >= target {
                if idx < CALLBACK_LATENCY_BUCKETS_US.len() {
                    return CALLBACK_LATENCY_BUCKETS_US[idx];
                }
                return CALLBACK_LATENCY_BUCKETS_US[CALLBACK_LATENCY_BUCKETS_US.len() - 1].saturating_add(1);
            }
        }
        self.max_us
    }
}

impl CallbackLatencyMetrics {
    fn new() -> Self {
        Self {
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
            total: AtomicU64::new(0),
            max_us: AtomicU64::new(0),
        }
    }

    fn observe(&self, elapsed: Duration) {
        let elapsed_us = elapsed.as_micros() as u64;
        let idx = CALLBACK_LATENCY_BUCKETS_US
            .iter()
            .position(|upper| elapsed_us <= *upper)
            .unwrap_or(CALLBACK_LATENCY_BUCKETS_US.len());
        self.counts[idx].fetch_add(1, Ordering::Relaxed);
        self.total.fetch_add(1, Ordering::Relaxed);

        let mut current_max = self.max_us.load(Ordering::Relaxed);
        while elapsed_us > current_max {
            match self.max_us.compare_exchange_weak(
                current_max,
                elapsed_us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current_max = observed,
            }
        }
    }

    fn snapshot_and_reset(&self) -> CallbackLatencySnapshot {
        let mut counts = [0u64; CALLBACK_LATENCY_BUCKETS_US.len() + 1];
        for (idx, slot) in counts.iter_mut().enumerate() {
            *slot = self.counts[idx].swap(0, Ordering::Relaxed);
        }
        CallbackLatencySnapshot {
            counts,
            total: self.total.swap(0, Ordering::Relaxed),
            max_us: self.max_us.swap(0, Ordering::Relaxed),
        }
    }
}

struct CallbackLatencyGuard<'a> {
    started_at: Instant,
    metrics: &'a CallbackLatencyMetrics,
}

impl<'a> CallbackLatencyGuard<'a> {
    fn new(metrics: &'a CallbackLatencyMetrics) -> Self {
        Self {
            started_at: Instant::now(),
            metrics,
        }
    }
}

impl Drop for CallbackLatencyGuard<'_> {
    fn drop(&mut self) {
        self.metrics.observe(self.started_at.elapsed());
    }
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

fn path_prefix_match_single(path: &str, prefix: &str) -> bool {
    if prefix.is_empty() || !prefix.starts_with('/') {
        return false;
    }
    if prefix == "/" {
        return path.starts_with('/');
    }
    path == prefix || path.starts_with(&format!("{}/", prefix))
}

fn strip_alias_prefix(path: &str, alias_prefix: &str) -> Option<String> {
    if path == alias_prefix {
        return Some("/".to_string());
    }
    path.strip_prefix(alias_prefix)
        .filter(|suffix| suffix.starts_with('/'))
        .map(|suffix| trim_trailing_slashes(suffix).to_string())
}

fn equivalent_path_variants(path: &str) -> Vec<String> {
    let mut variants = vec![trim_trailing_slashes(path).to_string()];
    let mut index = 0usize;
    while index < variants.len() {
        let current = variants[index].clone();
        for alias in ["/System/Volumes/Data", "/private"] {
            if let Some(candidate) = strip_alias_prefix(current.as_str(), alias) {
                if candidate.starts_with('/') && !variants.iter().any(|existing| existing == &candidate) {
                    variants.push(candidate);
                }
            }
        }
        index += 1;
    }
    variants
}

fn path_prefix_match(path: &str, prefix: &str) -> bool {
    let normalized_path = trim_trailing_slashes(path);
    let normalized_prefix = trim_trailing_slashes(prefix);

    let path_variants = equivalent_path_variants(normalized_path);
    let prefix_variants = equivalent_path_variants(normalized_prefix);

    for path_variant in path_variants.iter() {
        for prefix_variant in prefix_variants.iter() {
            if path_prefix_match_single(path_variant.as_str(), prefix_variant.as_str()) {
                return true;
            }
        }
    }
    false
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
        .join(".agentsmith-rs")
        .join("guard")
        .join("override-requests")
}

fn request_response_path(request_dir: &Path, id: &str) -> PathBuf {
    request_dir.join(format!("{}.response.json", sanitize_component(id)))
}

fn ensure_guard_dirs(home: &str) -> io::Result<PathBuf> {
    let agentsmith_dir = PathBuf::from(home).join(".agentsmith-rs");
    ensure_dir_not_symlink(&agentsmith_dir, DEFAULT_DIR_MODE)?;

    let guard_dir = agentsmith_dir.join("guard");
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

#[derive(Debug, Serialize, Clone)]
struct DenialRecord {
    ts: u64,
    op: String,
    path: String,
    dest: Option<String>,
    zone: String,
    process: String,
    ancestor: String,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ppid: Option<i32>,
}

impl DenialRecord {
    #[cfg(test)]
    fn for_test_reason(reason: &str) -> Self {
        Self {
            ts: 0,
            op: "test".to_string(),
            path: "/tmp/test".to_string(),
            dest: None,
            zone: "test-zone".to_string(),
            process: "test-proc".to_string(),
            ancestor: "test-ancestor".to_string(),
            reason: reason.to_string(),
            pid: None,
            ppid: None,
        }
    }
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

#[derive(Debug, Serialize, Clone)]
struct TaintMarkRecord {
    ts: u64,
    path: String,
    process: String,
    ancestor: String,
    pid: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    ppid: Option<i32>,
}

#[derive(Debug)]
enum GuardLogMessage {
    Denial(DenialRecord),
    AuditOnly(DenialRecord),
    TaintMark(TaintMarkRecord),
}

impl SecurityPolicy {
    fn is_sensitive_path(&self, target_path: &str) -> bool {
        self.sensitive_zones
            .iter()
            .any(|zone| path_prefix_match(target_path, zone))
    }

    fn matched_sensitive_zone(&self, target_path: &str) -> String {
        self.sensitive_zones
            .iter()
            .find(|zone| path_prefix_match(target_path, zone))
            .cloned()
            .unwrap_or_default()
    }

    fn is_sensitive_export_allowed(&self, target_path: &str) -> bool {
        self.sensitive_export_allow_zones
            .iter()
            .any(|zone| path_prefix_match(target_path, zone))
    }

    fn taint_ttl_seconds_or_default(&self) -> u64 {
        self.taint_ttl_seconds
            .filter(|ttl| *ttl > 0)
            .unwrap_or(DEFAULT_TAINT_TTL_SECS)
    }

    fn is_override_active_for_path(&self, target_path: &str, now: u64) -> bool {
        self.temporary_overrides.iter().any(|entry| {
            !entry.is_expired(now) && !entry.is_sensitive_read_only() && path_prefix_match(target_path, entry.path())
        })
    }

    fn is_sensitive_read_override_active_for_path(&self, target_path: &str, now: u64) -> bool {
        self.temporary_overrides.iter().any(|entry| {
            !entry.is_expired(now) && entry.is_sensitive_read_only() && path_prefix_match(target_path, entry.path())
        })
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

    fn trusted_identity_candidates_for_process<'a>(&'a self, process_name: &str) -> Vec<&'a TrustedToolIdentity> {
        self.trusted_tool_identities
            .iter()
            .filter(|entry| {
                Path::new(entry.path.as_str())
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name == process_name)
            })
            .collect()
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
        let sensitive_zones = self.sensitive_zones.clone();
        let auto_home_digit = self.auto_protect_home_digit_children;
        self.temporary_overrides.retain(|entry| {
            let path = entry.path();
            let in_configured_zone = protected_zones
                .iter()
                .any(|zone| path_prefix_match(path, zone.as_str()));
            let in_sensitive_zone = sensitive_zones
                .iter()
                .any(|zone| path_prefix_match(path, zone.as_str()));
            let in_auto_zone = auto_home_digit && home_digit_root(path, home).is_some();
            !entry.is_expired(now)
                && !path.is_empty()
                && path.starts_with('/')
                && path != "/"
                && (in_configured_zone || in_auto_zone || in_sensitive_zone)
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

    fn created_by(&self) -> Option<&str> {
        match self {
            TemporaryOverrideEntry::Path(_) => None,
            TemporaryOverrideEntry::Rule(rule) => rule.created_by.as_deref(),
        }
    }

    fn is_sensitive_read_only(&self) -> bool {
        self.created_by() == Some(OVERRIDE_CREATED_BY_SENSITIVE_READ_HELPER)
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
    let file_name = path.file_name().and_then(|name| name.to_str()).unwrap_or("policy.json");

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
    if policy
        .sensitive_zones
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
        "grant" | "grant-sensitive-read" => {
            let is_sensitive_read_grant = action == "grant-sensitive-read";
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
            let path_in_scope = if is_sensitive_read_grant {
                policy.is_sensitive_path(path.as_str())
            } else {
                policy.is_in_any_zone(path.as_str(), home)
            };
            if !path_in_scope {
                let message = if is_sensitive_read_grant {
                    "path outside sensitive zones".to_string()
                } else {
                    "path outside protected zones".to_string()
                };
                return (
                    false,
                    OverrideResponse {
                        id: req.id.clone(),
                        status: "error".to_string(),
                        message,
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
                created_by: Some(if is_sensitive_read_grant {
                    OVERRIDE_CREATED_BY_SENSITIVE_READ_HELPER.to_string()
                } else {
                    OVERRIDE_CREATED_BY_HELPER.to_string()
                }),
            }));

            let message = if is_sensitive_read_grant {
                format!("sensitive read override granted for {} minute(s)", minutes)
            } else {
                format!("override granted for {} minute(s)", minutes)
            };

            (
                true,
                OverrideResponse {
                    id: req.id.clone(),
                    status: "ok".to_string(),
                    message,
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

    if !is_override_helper_process(pid) {
        return Err("requester process is not agentsmith-override helper".to_string());
    }

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

fn warning_relevant_trusted_tools(policy: &SecurityPolicy) -> Vec<&str> {
    if policy.trusted_tools.is_empty() {
        return vec![];
    }

    let trusted_set = policy
        .trusted_tools
        .iter()
        .map(|tool| tool.as_str())
        .collect::<HashSet<_>>();
    let mut relevant = HashSet::new();

    if policy.allow_trusted_tools_in_ai_context {
        relevant.extend(trusted_set.iter().copied());
    }

    if policy.allow_vcs_metadata_in_ai_context {
        for tool in ["git", "jj"] {
            if trusted_set.contains(tool) {
                relevant.insert(tool);
            }
        }
    }

    let mut tools = relevant.into_iter().collect::<Vec<_>>();
    tools.sort_unstable();
    tools
}

fn trusted_identity_configuration_warning(policy: &SecurityPolicy) -> Option<String> {
    let relevant_tools = warning_relevant_trusted_tools(policy);
    if relevant_tools.is_empty() {
        return None;
    }

    if policy.trusted_tool_identities.is_empty() {
        return Some(format!(
            "[WARN] trusted checks are active for [{}], but trusted_tool_identities is empty; these tools will fail-closed with TRUST_IDENTITY_MISMATCH. Run nix switch/make to refresh policy defaults or set trusted_tool_identities in ~/.agentsmith-rs/policy.json.",
            relevant_tools.join(", ")
        ));
    }

    let missing_tools = relevant_tools
        .iter()
        .filter(|tool| policy.trusted_identity_candidates_for_process(tool).is_empty())
        .map(|tool| (*tool).to_string())
        .collect::<Vec<_>>();
    if missing_tools.is_empty() {
        return None;
    }

    Some(format!(
        "[WARN] trusted_tool_identities is missing entries for trusted_tools [{}]; these tools will fail-closed with TRUST_IDENTITY_MISMATCH. Add matching identities or remove them from trusted_tools.",
        missing_tools.join(", ")
    ))
}

fn log_policy_self_checks(policy: &SecurityPolicy, warning_state: &mut Option<(String, u64)>, now: u64) {
    if let Some(warning) = trusted_identity_configuration_warning(policy) {
        let should_emit = match warning_state {
            Some((previous, ts))
                if previous == &warning && now.saturating_sub(*ts) < POLICY_SELF_CHECK_WARNING_INTERVAL_SECS =>
            {
                false
            },
            _ => true,
        };
        if should_emit {
            eprintln!("{}", warning);
            *warning_state = Some((warning, now));
        }
    } else {
        *warning_state = None;
    }
}

fn is_safe_taint_device_path(path: &str) -> bool {
    matches!(path, "/dev/null" | "/dev/tty" | "/dev/dtracehelper")
}

fn format_cache_watermark_log(
    ts: u64,
    ancestor_current: usize,
    ancestor_high: usize,
    trusted_current: usize,
    trusted_high: usize,
    taint_current: usize,
    taint_high: usize,
) -> String {
    format!(
        "[METRIC] cache-watermark ts={} ancestor={}/{} trusted={}/{} taint={}/{}",
        ts, ancestor_current, ancestor_high, trusted_current, trusted_high, taint_current, taint_high
    )
}

fn format_runtime_health_log(
    ts: u64,
    signature_queue_pending: u64,
    signature_queue_dropped_full: u64,
    signature_queue_dropped_disconnected: u64,
    log_queue_pending: u64,
    log_queue_dropped_full: u64,
    log_queue_dropped_disconnected: u64,
    callback_latency: &CallbackLatencySnapshot,
) -> String {
    format!(
        "[METRIC] runtime-health ts={} sigq_pending={} sigq_drop_full={} sigq_drop_disconnected={} logq_pending={} logq_drop_full={} logq_drop_disconnected={} cb_count={} cb_p50_us={} cb_p95_us={} cb_p99_us={} cb_max_us={}",
        ts,
        signature_queue_pending,
        signature_queue_dropped_full,
        signature_queue_dropped_disconnected,
        log_queue_pending,
        log_queue_dropped_full,
        log_queue_dropped_disconnected,
        callback_latency.total,
        callback_latency.percentile_upper_bound_us(50),
        callback_latency.percentile_upper_bound_us(95),
        callback_latency.percentile_upper_bound_us(99),
        callback_latency.max_us
    )
}

fn emit_cache_watermark_log(
    ancestor_cache: &Arc<Mutex<HashMap<i32, CachedAncestor>>>,
    trust_cache: &Arc<Mutex<TrustedProcessCache>>,
    taint_state: &Arc<Mutex<TaintState>>,
    highs: &mut CacheWatermarkHighs,
) {
    let ancestor_current = {
        let cache = ancestor_cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.len()
    };
    let trusted_current = {
        let cache = trust_cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.len()
    };
    let taint_current = {
        let taint = taint_state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        taint.len()
    };
    let (ancestor_high, trusted_high, taint_high) = highs.update(ancestor_current, trusted_current, taint_current);
    println!(
        "{}",
        format_cache_watermark_log(
            now_ts(),
            ancestor_current,
            ancestor_high,
            trusted_current,
            trusted_high,
            taint_current,
            taint_high
        )
    );
}

fn emit_runtime_health_log(callback_latency_metrics: &CallbackLatencyMetrics) {
    let callback_latency = callback_latency_metrics.snapshot_and_reset();
    println!(
        "{}",
        format_runtime_health_log(
            now_ts(),
            SIGNATURE_QUEUE_PENDING.load(Ordering::Relaxed),
            SIGNATURE_QUEUE_DROPPED_FULL.load(Ordering::Relaxed),
            SIGNATURE_QUEUE_DROPPED_DISCONNECTED.load(Ordering::Relaxed),
            LOG_QUEUE_PENDING.load(Ordering::Relaxed),
            LOG_QUEUE_DROPPED_FULL.load(Ordering::Relaxed),
            LOG_QUEUE_DROPPED_DISCONNECTED.load(Ordering::Relaxed),
            &callback_latency,
        )
    );
}

fn maybe_warn_log_queue_full(kind: &str) {
    let now = now_ts();
    let last_warn = LOG_QUEUE_FULL_LAST_WARN_TS.load(Ordering::Relaxed);
    if now.saturating_sub(last_warn) < LOG_QUEUE_FULL_WARN_INTERVAL_SECS {
        return;
    }
    if LOG_QUEUE_FULL_LAST_WARN_TS
        .compare_exchange(last_warn, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        eprintln!("[log] async queue full; dropping {} event", kind);
    }
}

fn process_log_message_sync(home: &str, message: GuardLogMessage) {
    match message {
        GuardLogMessage::Denial(record) => log_denial_sync(home, &record),
        GuardLogMessage::AuditOnly(record) => log_audit_only_sync(home, &record),
        GuardLogMessage::TaintMark(record) => log_taint_mark_sync(home, &record),
    }
}

fn decrement_queue_pending(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        value.checked_sub(1)
    });
}

fn enqueue_log_message_or_fallback(home: &str, message: GuardLogMessage) {
    if let Some(tx) = LOG_EVENT_TX.get() {
        let kind = match &message {
            GuardLogMessage::Denial(_) => "denial",
            GuardLogMessage::AuditOnly(_) => "audit-only",
            GuardLogMessage::TaintMark(_) => "taint",
        };
        LOG_QUEUE_PENDING.fetch_add(1, Ordering::Relaxed);
        match tx.try_send(message) {
            Ok(()) => {},
            Err(mpsc::TrySendError::Full(_)) => {
                decrement_queue_pending(&LOG_QUEUE_PENDING);
                LOG_QUEUE_DROPPED_FULL.fetch_add(1, Ordering::Relaxed);
                maybe_warn_log_queue_full(kind);
            },
            Err(mpsc::TrySendError::Disconnected(message)) => {
                decrement_queue_pending(&LOG_QUEUE_PENDING);
                LOG_QUEUE_DROPPED_DISCONNECTED.fetch_add(1, Ordering::Relaxed);
                process_log_message_sync(home, message);
            },
        }
        return;
    }

    process_log_message_sync(home, message);
}

fn init_async_log_worker(home: &str) {
    let (tx, rx) = mpsc::sync_channel::<GuardLogMessage>(LOG_EVENT_QUEUE_BOUND);
    if LOG_EVENT_TX.set(tx).is_err() {
        return;
    }

    let worker_home = home.to_string();
    thread::spawn(move || {
        while let Ok(message) = rx.recv() {
            process_log_message_sync(worker_home.as_str(), message);
            decrement_queue_pending(&LOG_QUEUE_PENDING);
        }
    });
}

fn log_denial(home: &str, record: &DenialRecord) {
    enqueue_log_message_or_fallback(home, GuardLogMessage::Denial(record.clone()));
}

fn log_audit_only(home: &str, record: &DenialRecord) {
    enqueue_log_message_or_fallback(home, GuardLogMessage::AuditOnly(record.clone()));
}

fn log_taint_mark(home: &str, record: &TaintMarkRecord) {
    enqueue_log_message_or_fallback(home, GuardLogMessage::TaintMark(record.clone()));
}

fn record_denial_or_audit_only(home: &str, policy: &SecurityPolicy, record: DenialRecord) -> bool {
    if policy.audit_only_mode {
        println!(
            "[AUDIT] allow op={} reason={} process={} ancestor={} path={}",
            record.op, record.reason, record.process, record.ancestor, record.path
        );
        log_audit_only(home, &record);
        return false;
    }

    log_denial(home, &record);
    true
}

fn log_denial_sync(home: &str, record: &DenialRecord) {
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

    let feedback = build_denial_feedback(home, record);
    if let Ok(mut file) = open_truncate_no_follow(&feedback_path, DEFAULT_FILE_MODE) {
        if verify_regular_file(&file, &feedback_path).is_ok() {
            let _ = file.write_all(feedback.as_bytes());
        }
    }
}

fn log_audit_only_sync(home: &str, record: &DenialRecord) {
    let guard_dir = match ensure_guard_dirs(home) {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("[log] cannot use guard dir: {}", err);
            return;
        },
    };

    let log_path = guard_dir.join("audit-only.jsonl");
    if let Ok(json) = serde_json::to_string(record) {
        if let Ok(mut file) = open_append_no_follow(&log_path, DEFAULT_FILE_MODE) {
            if verify_regular_file(&file, &log_path).is_ok() {
                if let Ok(meta) = file.metadata() {
                    if meta.len() > AUDIT_ONLY_LOG_MAX_BYTES {
                        let _ = file.set_len(0);
                    }
                }
                let _ = writeln!(file, "{}", json);
            }
        }
    }
}

fn log_taint_mark_sync(home: &str, record: &TaintMarkRecord) {
    let guard_dir = match ensure_guard_dirs(home) {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("[taint] cannot use guard dir: {}", err);
            return;
        },
    };

    let log_path = guard_dir.join("taint-marks.jsonl");
    if let Ok(json) = serde_json::to_string(record) {
        if let Ok(mut file) = open_append_no_follow(&log_path, DEFAULT_FILE_MODE) {
            if verify_regular_file(&file, &log_path).is_ok() {
                if let Ok(meta) = file.metadata() {
                    if meta.len() > TAINT_AUDIT_MAX_BYTES {
                        let _ = file.set_len(0);
                    }
                }
                let _ = writeln!(file, "{}", json);
            }
        }
    }
}

fn build_denial_feedback(home: &str, record: &DenialRecord) -> String {
    let dest_info = record
        .dest
        .as_deref()
        .map(|d| format!("\nDest: {}", d))
        .unwrap_or_default();
    let header = format!(
        "[AGENTSMITH DENIED]\n\
         Operation: {}\n\
         Reason: {}\n\
         Path: {}{}\n\
         Zone: {}\n\
         Process: {} (via {})\n{}{}\
         \n",
        record.op,
        record.reason,
        record.path,
        dest_info,
        record.zone,
        record.process,
        record.ancestor,
        record.pid.map(|pid| format!("Pid: {}\n", pid)).unwrap_or_default(),
        record.ppid.map(|ppid| format!("PPid: {}\n", ppid)).unwrap_or_default(),
    );

    let quarantine_dir = format!("{}/.agentsmith-rs/guard/quarantine", home);
    let guidance = match record.reason.as_str() {
        REASON_SENSITIVE_READ_NON_AI => format!(
            "Recommended next step:\n\
             - Sensitive read gate: non-AI reads are denied.\n\
             - Retry from AI context (Codex/Claude ancestor).\n\
             - If human review is required, export reviewed data only into: {}\n",
            quarantine_dir
        ),
        REASON_SENSITIVE_TRANSFER_OUT => format!(
            "Recommended next step:\n\
             - Sensitive export is blocked outside allow-zones.\n\
             - Move/copy only into quarantine allow-zone: {}\n\
             - Example: mv {} {}/\n",
            quarantine_dir, record.path, quarantine_dir
        ),
        REASON_TAINT_WRITE_OUT => format!(
            "Recommended next step:\n\
             - This process is tainted by a prior sensitive read.\n\
             - Write outputs only into: {}\n\
             - Or retry after taint TTL expires.\n",
            quarantine_dir
        ),
        REASON_EXEC_EXFIL_TOOL => "Recommended next step:\n\
             - Exfil tooling is blocked in AI context.\n\
             - Keep processing inside allowed local zones or approved channels.\n"
            .to_string(),
        REASON_TRUST_IDENTITY_MISMATCH => format!(
            "Recommended next step:\n\
             - Trusted process identity verification failed.\n\
             - Check `trusted_tool_identities` for exact path + signing identity.\n\
             - If high-security mode is on, ensure cdhash is pinned correctly.\n\
             - Current process: {}\n",
            record.process
        ),
        _ => format!(
            "Recommended (safer first step): agentsmith-quarantine {}\n\
             This moves the target into ./temp under your CURRENT working directory.\n\
             \n\
             If you must permanently delete via AI, request one-time override with TTL:\n\
             agentsmith-override --minutes 3 {}\n\
             (Short TTL only; no-expire is rejected by helper)\n\
             Then retry the operation.\n",
            record.path, record.path
        ),
    };

    format!("{}{}", header, guidance)
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
fn parse_procargs_argv(buf: &[u8]) -> Vec<String> {
    if buf.len() < 4 {
        return Vec::new();
    }
    let argc_raw = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if argc_raw <= 0 {
        return Vec::new();
    }
    let argc = argc_raw as usize;

    // Layout: argc(i32) + exec_path + \0 + padding(\0s) + argv[0] + \0 + argv[1] + ...
    let mut pos = 4;
    while pos < buf.len() && buf[pos] != 0 {
        pos += 1;
    }
    while pos < buf.len() && buf[pos] == 0 {
        pos += 1;
    }

    let mut args: Vec<String> = Vec::with_capacity(argc);
    while pos < buf.len() && args.len() < argc {
        while pos < buf.len() && buf[pos] == 0 {
            pos += 1;
        }
        if pos >= buf.len() {
            break;
        }

        let start = pos;
        while pos < buf.len() && buf[pos] != 0 {
            pos += 1;
        }
        if start < pos {
            args.push(String::from_utf8_lossy(&buf[start..pos]).to_string());
        }
    }

    args
}

fn get_process_argv(pid: i32) -> Option<Vec<String>> {
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

    buf.truncate(size);
    let args = parse_procargs_argv(&buf);
    if args.is_empty() {
        None
    } else {
        Some(args)
    }
}

fn get_process_argv0(pid: i32) -> Option<String> {
    get_process_argv(pid).and_then(|args| {
        args.first()
            .map(|argv0| argv0.rsplit('/').next().unwrap_or(argv0.as_str()).to_string())
    })
}

fn is_override_helper_argv(args: &[String]) -> bool {
    args.iter().any(|arg| {
        Path::new(arg)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == "agentsmith-override")
    })
}

fn is_override_helper_process(pid: i32) -> bool {
    let args = match get_process_argv(pid) {
        Some(args) => args,
        None => return false,
    };
    is_override_helper_argv(&args)
}

/// Query proc_bsdinfo for a process. Returns (ppid, comm_name).
#[repr(C)]
struct ProcBsdInfo {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: libc::uid_t,
    pbi_gid: libc::gid_t,
    pbi_ruid: libc::uid_t,
    pbi_rgid: libc::gid_t,
    pbi_svuid: libc::uid_t,
    pbi_svgid: libc::gid_t,
    rfu_1: u32,
    pbi_comm: [libc::c_char; MAXCOMLEN],
    pbi_name: [libc::c_char; MAXCOMLEN * 2],
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    pbi_start_tvsec: u64,
    pbi_start_tvusec: u64,
}

fn c_char_buf_to_string(buf: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = buf
        .iter()
        .copied()
        .take_while(|value| *value != 0)
        .map(|value| value as u8)
        .collect();
    String::from_utf8_lossy(&bytes).to_string()
}

fn get_process_bsd_info(pid: i32) -> Option<ProcBsdInfo> {
    const PROC_PIDTBSDINFO: i32 = 3;
    let mut info: ProcBsdInfo = unsafe { std::mem::zeroed() };
    let info_size = std::mem::size_of::<ProcBsdInfo>() as i32;
    let ret = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            &mut info as *mut ProcBsdInfo as *mut libc::c_void,
            info_size,
        )
    };
    if ret == info_size {
        Some(info)
    } else {
        None
    }
}

fn get_process_info(pid: i32) -> Option<(i32, String)> {
    let info = get_process_bsd_info(pid)?;
    let ppid_raw = info.pbi_ppid as i32;
    let ppid = if ppid_raw > 0 && ppid_raw != pid { ppid_raw } else { 0 };
    let comm = c_char_buf_to_string(&info.pbi_comm);
    Some((ppid, comm))
}

fn parent_pid_for_pid(pid: i32) -> Option<i32> {
    get_process_info(pid).map(|(ppid, _)| ppid).filter(|ppid| *ppid > 0)
}

fn pid_for_record(pid: i32) -> Option<i32> {
    (pid > 0).then_some(pid)
}

fn process_start_time_for_pid(pid: i32) -> Option<ProcessStartTimeKey> {
    let info = get_process_bsd_info(pid)?;
    Some(ProcessStartTimeKey {
        start_tvsec: info.pbi_start_tvsec,
        start_tvusec: info.pbi_start_tvusec,
    })
}

fn process_identity_key(pid: i32) -> Option<ProcessIdentityKey> {
    let info = get_process_bsd_info(pid)?;
    let executable_path = get_process_path(pid)?;
    Some(ProcessIdentityKey {
        pid,
        start_tvsec: info.pbi_start_tvsec,
        start_tvusec: info.pbi_start_tvusec,
        executable_path,
    })
}

fn exe_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Walk the process tree to find if any ancestor is an AI agent.
/// Returns (is_ai_context, ai_ancestor_name).
fn find_ai_ancestor(pid: i32, policy: &SecurityPolicy, cache: &mut HashMap<i32, CachedAncestor>) -> Option<String> {
    let ts = now_ts();
    cache.retain(|_, cached| ts.saturating_sub(cached.updated_at) <= CACHE_TTL_SECS);
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

fn canonicalize_executable_path_strict(executable_path: &str) -> Result<String, String> {
    let normalized = normalize_absolute_path(executable_path)
        .ok_or_else(|| format!("executable path is not absolute: {}", executable_path))?;
    let metadata =
        fs::symlink_metadata(&normalized).map_err(|err| format!("cannot stat executable {}: {}", normalized, err))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "symbolic-link executable path is rejected: {}",
            normalized
        ));
    }
    let canonical = fs::canonicalize(&normalized)
        .map_err(|err| format!("cannot canonicalize executable {}: {}", normalized, err))?;
    let canonical_text = canonical.to_string_lossy().to_string();
    if canonical_text != normalized {
        return Err(format!(
            "executable path must be canonical (got {}, canonical {})",
            normalized, canonical_text
        ));
    }
    Ok(canonical_text)
}

fn codesign_field(report: &str, key: &str) -> Option<String> {
    report
        .lines()
        .find_map(|line| line.strip_prefix(key).map(|value| value.trim().to_string()))
}

fn read_binary_signature(executable_path: &str) -> Result<BinaryCodeSignature, String> {
    let output = Command::new(CODESIGN_BIN)
        .args(["-dv", "--verbose=4", executable_path])
        .output()
        .map_err(|err| format!("failed to run codesign: {}", err))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let report = format!("{}\n{}", stdout, stderr);
    if !output.status.success() {
        return Err(format!(
            "codesign verification failed for {}: {}",
            executable_path,
            report.trim()
        ));
    }

    let signing_identifier = codesign_field(&report, "Identifier=")
        .ok_or_else(|| format!("missing signing identifier for {}", executable_path))?;
    let team_identifier = match codesign_field(&report, "TeamIdentifier=") {
        Some(value) if value == "not set" || value.is_empty() => None,
        Some(value) => Some(value),
        None => None,
    };
    let cdhash = codesign_field(&report, "CDHash=").map(|value| value.to_lowercase());

    Ok(BinaryCodeSignature {
        signing_identifier,
        team_identifier,
        cdhash,
    })
}

fn normalized_expected_trusted_identity_path(entry: &TrustedToolIdentity) -> Option<String> {
    normalize_absolute_path(entry.path.as_str()).map(|path| trim_trailing_slashes(&path).to_string())
}

fn trusted_identity_decision_from_signature(
    process_name: &str,
    canonical_path: &str,
    actual_signature: &BinaryCodeSignature,
    expected_identities: &[&TrustedToolIdentity],
    require_cdhash: bool,
) -> TrustedProcessDecision {
    let matched = expected_identities.iter().any(|entry| {
        let expected_path = match normalized_expected_trusted_identity_path(entry) {
            Some(path) => path,
            None => return false,
        };
        if expected_path != canonical_path {
            return false;
        }
        if entry.signing_identifier != actual_signature.signing_identifier {
            return false;
        }
        if entry.team_identifier != actual_signature.team_identifier {
            return false;
        }

        let expected_cdhash = entry.cdhash.as_ref().map(|value| value.to_lowercase());
        if require_cdhash && expected_cdhash.is_none() {
            return false;
        }
        if let Some(expected) = expected_cdhash {
            if actual_signature.cdhash.as_deref() != Some(expected.as_str()) {
                return false;
            }
        }

        true
    });
    if matched {
        return TrustedProcessDecision::Trusted;
    }

    let expected_paths = expected_identities
        .iter()
        .filter_map(|entry| normalized_expected_trusted_identity_path(entry))
        .collect::<Vec<_>>()
        .join(", ");
    let expected_signing_ids = expected_identities
        .iter()
        .map(|entry| entry.signing_identifier.clone())
        .collect::<Vec<_>>()
        .join(", ");
    let expected_team_ids = expected_identities
        .iter()
        .map(|entry| entry.team_identifier.clone().unwrap_or_else(|| "not set".to_string()))
        .collect::<Vec<_>>()
        .join(", ");

    TrustedProcessDecision::IdentityMismatch(format!(
        "identity mismatch for {}: path={} signing_id={} team_id={} (expected paths=[{}], signing_ids=[{}], team_ids=[{}])",
        process_name,
        canonical_path,
        actual_signature.signing_identifier,
        actual_signature
            .team_identifier
            .clone()
            .unwrap_or_else(|| "not set".to_string()),
        expected_paths,
        expected_signing_ids,
        expected_team_ids
    ))
}

#[cfg(test)]
fn evaluate_trusted_process_from_path(
    process_name: &str,
    executable_path: &str,
    policy: &SecurityPolicy,
) -> TrustedProcessDecision {
    if !policy.is_trusted_tool(process_name) {
        return TrustedProcessDecision::NotTrusted;
    }

    let expected_identities = policy.trusted_identity_candidates_for_process(process_name);
    if expected_identities.is_empty() {
        return TrustedProcessDecision::IdentityMismatch(format!(
            "trusted tool {} has no trusted_tool_identities entry",
            process_name
        ));
    }

    let canonical_path = match canonicalize_executable_path_strict(executable_path) {
        Ok(path) => path,
        Err(err) => return TrustedProcessDecision::IdentityMismatch(err),
    };
    let actual_signature = match read_binary_signature(&canonical_path) {
        Ok(signature) => signature,
        Err(err) => return TrustedProcessDecision::IdentityMismatch(err),
    };
    trusted_identity_decision_from_signature(
        process_name,
        canonical_path.as_str(),
        &actual_signature,
        expected_identities.as_slice(),
        policy.trusted_identity_require_cdhash,
    )
}

fn request_signature_refresh_if_needed(
    canonical_path: &str,
    signature_cache: &Arc<Mutex<BinarySignatureCache>>,
    signature_refresh_tx: &mpsc::SyncSender<String>,
) {
    let should_enqueue = {
        let mut cache = signature_cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.should_enqueue_refresh(canonical_path)
    };
    if !should_enqueue {
        return;
    }

    SIGNATURE_QUEUE_PENDING.fetch_add(1, Ordering::Relaxed);
    if let Err(err) = signature_refresh_tx.try_send(canonical_path.to_string()) {
        decrement_queue_pending(&SIGNATURE_QUEUE_PENDING);
        let mut cache = signature_cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.cancel_in_flight_refresh(canonical_path);
        match err {
            mpsc::TrySendError::Full(_) => {
                SIGNATURE_QUEUE_DROPPED_FULL.fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "[trust] signature refresh queue is full; skipping enqueue for {}",
                    canonical_path
                );
            },
            mpsc::TrySendError::Disconnected(_) => {
                SIGNATURE_QUEUE_DROPPED_DISCONNECTED.fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "[trust] signature refresh worker disconnected; unable to verify {}",
                    canonical_path
                );
            },
        }
    }
}

fn warm_signature_cache_for_policy(
    policy: &SecurityPolicy,
    signature_cache: &Arc<Mutex<BinarySignatureCache>>,
    signature_refresh_tx: &mpsc::SyncSender<String>,
) {
    let mut prewarm_paths = HashSet::new();
    for entry in policy.trusted_tool_identities.iter() {
        if let Some(path) = normalized_expected_trusted_identity_path(entry) {
            prewarm_paths.insert(path);
        }
    }

    for path in prewarm_paths.into_iter() {
        request_signature_refresh_if_needed(path.as_str(), signature_cache, signature_refresh_tx);
    }
}

fn spawn_signature_refresh_worker(
    signature_refresh_rx: mpsc::Receiver<String>,
    signature_cache: Arc<Mutex<BinarySignatureCache>>,
) {
    thread::spawn(move || {
        while let Ok(canonical_path) = signature_refresh_rx.recv() {
            let signature = read_binary_signature(canonical_path.as_str());
            let now = now_ts();
            let mut cache = signature_cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            cache.insert(canonical_path, signature, now);
            decrement_queue_pending(&SIGNATURE_QUEUE_PENDING);
        }
    });
}

fn evaluate_trusted_process_from_path_nonblocking(
    process_name: &str,
    executable_path: &str,
    policy: &SecurityPolicy,
    signature_cache: &Arc<Mutex<BinarySignatureCache>>,
    signature_refresh_tx: &mpsc::SyncSender<String>,
) -> TrustedProcessDecision {
    if !policy.is_trusted_tool(process_name) {
        return TrustedProcessDecision::NotTrusted;
    }

    let expected_identities = policy.trusted_identity_candidates_for_process(process_name);
    if expected_identities.is_empty() {
        return TrustedProcessDecision::IdentityMismatch(format!(
            "trusted tool {} has no trusted_tool_identities entry",
            process_name
        ));
    }

    let canonical_path = match canonicalize_executable_path_strict(executable_path) {
        Ok(path) => path,
        Err(err) => return TrustedProcessDecision::IdentityMismatch(err),
    };

    let now = now_ts();
    let cached_signature = {
        let mut cache = signature_cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.get(canonical_path.as_str(), now)
    };

    let actual_signature = match cached_signature {
        Some(Ok(signature)) => signature,
        Some(Err(err)) => return TrustedProcessDecision::IdentityMismatch(err),
        None => {
            request_signature_refresh_if_needed(
                canonical_path.as_str(),
                signature_cache,
                signature_refresh_tx,
            );
            return TrustedProcessDecision::IdentityMismatch(format!(
                "{}: {}",
                TRUST_SIGNATURE_PENDING_PREFIX, canonical_path
            ));
        },
    };

    trusted_identity_decision_from_signature(
        process_name,
        canonical_path.as_str(),
        &actual_signature,
        expected_identities.as_slice(),
        policy.trusted_identity_require_cdhash,
    )
}

fn trust_decision_is_signature_pending(decision: &TrustedProcessDecision) -> bool {
    matches!(
        decision,
        TrustedProcessDecision::IdentityMismatch(reason) if reason.starts_with(TRUST_SIGNATURE_PENDING_PREFIX)
    )
}

fn prune_trust_cache(cache: &mut HashMap<ProcessIdentityKey, CachedTrustedProcess>, now: u64) {
    cache.retain(|_, entry| now.saturating_sub(entry.updated_at) <= TRUST_CACHE_TTL_SECS);
}

fn invalidate_trust_cache_for_pid(cache: &mut HashMap<ProcessIdentityKey, CachedTrustedProcess>, pid: i32) {
    cache.retain(|key, _| key.pid != pid);
}

fn clear_process_state_for_pid(
    pid: i32,
    ancestor_cache: &mut HashMap<i32, CachedAncestor>,
    trust_cache: &mut TrustedProcessCache,
    taint_state: &mut TaintState,
) {
    if pid <= 0 {
        return;
    }
    ancestor_cache.remove(&pid);
    trust_cache.clear_pid(pid);
    taint_state.clear_pid(pid);
}

fn clear_trust_cache_for_exec(trust_cache: &Arc<Mutex<TrustedProcessCache>>, pid: i32) {
    let mut cache = trust_cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.clear_pid(pid);
}

fn evaluate_trusted_process(
    pid: i32,
    process_name: &str,
    policy: &SecurityPolicy,
    trust_cache: &Arc<Mutex<TrustedProcessCache>>,
    signature_cache: &Arc<Mutex<BinarySignatureCache>>,
    signature_refresh_tx: &mpsc::SyncSender<String>,
) -> TrustedProcessDecision {
    let now = now_ts();

    let key = process_identity_key(pid);
    if let Some(key) = key.as_ref() {
        let cached = {
            let mut cache = trust_cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            cache.get(key, now)
        };
        if let Some(entry) = cached {
            return entry.decision.clone();
        }
    }

    let executable_path = match get_process_path(pid) {
        Some(path) => path,
        None => {
            return TrustedProcessDecision::IdentityMismatch(format!(
                "unable to resolve executable path for pid {}",
                pid
            ))
        },
    };
    let decision = evaluate_trusted_process_from_path_nonblocking(
        process_name,
        &executable_path,
        policy,
        signature_cache,
        signature_refresh_tx,
    );
    if let Some(key) = key {
        if trust_decision_is_signature_pending(&decision) {
            return decision;
        }
        let mut cache = trust_cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.insert(key, decision.clone(), now);
    }
    decision
}

fn is_vcs_tool(process_name: &str) -> bool {
    matches!(process_name, "git" | "jj")
}

fn git_global_option_takes_value(option: &str) -> bool {
    matches!(
        option,
        "-C" | "-c" | "--exec-path" | "--git-dir" | "--work-tree" | "--namespace" | "--super-prefix" | "--config-env"
    )
}

fn git_subcommand_from_args(args: &[String]) -> Option<&str> {
    if args.len() < 2 {
        return None;
    }

    let mut idx = 1;
    while idx < args.len() {
        let arg = args[idx].as_str();
        if arg == "--" {
            idx += 1;
            break;
        }

        if arg.starts_with("--") {
            if let Some((opt, _)) = arg.split_once('=') {
                if git_global_option_takes_value(opt) {
                    idx += 1;
                    continue;
                }
            } else if git_global_option_takes_value(arg) {
                idx = idx.saturating_add(2);
                continue;
            }
            idx += 1;
            continue;
        }

        if arg.starts_with('-') {
            if git_global_option_takes_value(arg) {
                idx = idx.saturating_add(2);
            } else {
                idx += 1;
            }
            continue;
        }

        return Some(arg);
    }

    if idx < args.len() {
        Some(args[idx].as_str())
    } else {
        None
    }
}

fn is_git_merge_or_pull_invocation(args: &[String]) -> bool {
    matches!(git_subcommand_from_args(args), Some("merge" | "pull"))
}

fn should_allow_git_merge_pull_worktree_change_in_ai_context(
    process_name: &str,
    args: &[String],
    trusted_process: &TrustedProcessDecision,
    policy: &SecurityPolicy,
) -> bool {
    policy.allow_git_merge_pull_in_ai_context
        && process_name == "git"
        && trusted_process.is_trusted()
        && is_git_merge_or_pull_invocation(args)
}

fn should_allow_git_merge_pull_for_process(
    pid: i32,
    process_name: &str,
    trusted_process: &TrustedProcessDecision,
    policy: &SecurityPolicy,
) -> bool {
    if process_name != "git" {
        return false;
    }

    let args = match get_process_argv(pid) {
        Some(args) => args,
        None => return false,
    };
    should_allow_git_merge_pull_worktree_change_in_ai_context(process_name, &args, trusted_process, policy)
}

fn is_vcs_metadata_path(path: &str) -> bool {
    trim_trailing_slashes(path)
        .split('/')
        .any(|component| component == ".git" || component == ".jj")
}

fn should_allow_vcs_metadata_unlink_in_ai_context(
    path: &str,
    process_name: Option<&str>,
    trusted_process: &TrustedProcessDecision,
    policy: &SecurityPolicy,
) -> bool {
    if !policy.allow_vcs_metadata_in_ai_context || !is_vcs_metadata_path(path) {
        return false;
    }
    let process_name = match process_name {
        Some(name) => name,
        None => return false,
    };

    is_vcs_tool(process_name) && trusted_process.is_trusted()
}

fn should_allow_vcs_metadata_rename_in_ai_context(
    source_path: &str,
    dest_path: &str,
    process_name: Option<&str>,
    trusted_process: &TrustedProcessDecision,
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

    is_vcs_tool(process_name) && trusted_process.is_trusted()
}

fn is_read_intent(fflag: i32) -> bool {
    (fflag & FFLAG_READ) != 0 || !is_write_intent(fflag)
}

fn is_write_intent(fflag: i32) -> bool {
    (fflag & FFLAG_WRITE) != 0
}

fn should_fast_allow_open(path: &str, fflag: i32, policy: &SecurityPolicy) -> bool {
    !is_write_intent(fflag) && !policy.is_sensitive_path(path)
}

fn should_deny_sensitive_open_for_process(
    path: &str,
    is_ai_context: bool,
    fflag: i32,
    policy: &SecurityPolicy,
    is_guard_process: bool,
) -> bool {
    policy.read_gate_enabled
        && policy.is_sensitive_path(path)
        && is_read_intent(fflag)
        && !is_ai_context
        && !is_guard_process
        && !policy.is_sensitive_read_override_active_for_path(path, now_ts())
}

fn should_deny_sensitive_open(path: &str, is_ai_context: bool, fflag: i32, policy: &SecurityPolicy) -> bool {
    should_deny_sensitive_open_for_process(path, is_ai_context, fflag, policy, false)
}

fn is_sensitive_read_observer_process(process_name: &str) -> bool {
    process_name == "AgentSmith"
}

fn is_sensitive_read_observer_path(path: &str, home: &str) -> bool {
    let policy_path = format!("{}/.agentsmith-rs/policy.json", home);
    let policy_lock_path = format!("{}.lock", policy_path);
    let guard_dir = format!("{}/.agentsmith-rs/guard", home);
    path == policy_path
        || path == policy_lock_path
        || path_prefix_match(path, &policy_lock_path)
        || path_prefix_match(path, &guard_dir)
}

fn should_allow_sensitive_read_observer(path: &str, process_name: &str, home: &str) -> bool {
    is_sensitive_read_observer_process(process_name) && is_sensitive_read_observer_path(path, home)
}

fn should_mark_taint_on_sensitive_read(path: &str, policy: &SecurityPolicy, home: &str) -> bool {
    policy.is_sensitive_path(path) && !is_sensitive_read_observer_path(path, home)
}

fn should_deny_sensitive_transfer(source: &str, dest: &str, policy: &SecurityPolicy) -> bool {
    policy.transfer_gate_enabled
        && policy.is_sensitive_path(source)
        && !policy.is_sensitive_export_allowed(dest)
        && !policy.is_sensitive_path(dest)
}

fn should_allow_vcs_metadata_tainted_write(
    target_path: &str,
    process_name: Option<&str>,
    trusted_process: &TrustedProcessDecision,
    policy: &SecurityPolicy,
) -> bool {
    if !policy.allow_vcs_metadata_in_ai_context || !is_vcs_metadata_path(target_path) {
        return false;
    }
    let process_name = match process_name {
        Some(name) => name,
        None => return false,
    };

    is_vcs_tool(process_name) && trusted_process.is_trusted()
}

fn should_deny_tainted_write(
    pid: i32,
    target: &str,
    process_name: Option<&str>,
    trusted_process: &TrustedProcessDecision,
    now: u64,
    taint: &TaintState,
    policy: &SecurityPolicy,
) -> bool {
    taint.is_tainted(pid, now)
        && !is_safe_taint_device_path(target)
        && !policy.is_sensitive_export_allowed(target)
        && !policy.is_sensitive_path(target)
        && !should_allow_vcs_metadata_tainted_write(target, process_name, trusted_process, policy)
}

fn should_deny_tainted_open_write(
    pid: i32,
    path: &str,
    fflag: i32,
    process_name: Option<&str>,
    trusted_process: &TrustedProcessDecision,
    now: u64,
    taint: &TaintState,
    policy: &SecurityPolicy,
) -> bool {
    is_write_intent(fflag) && should_deny_tainted_write(pid, path, process_name, trusted_process, now, taint, policy)
}

fn should_deny_exec_in_ai_context(proc_name: &str, is_ai_context: bool, policy: &SecurityPolicy) -> bool {
    policy.exec_gate_enabled && is_ai_context && policy.exec_exfil_tool_blocklist.iter().any(|tool| tool == proc_name)
}

fn join_path_component(dir: &str, name: &str) -> String {
    let normalized_dir = trim_trailing_slashes(dir);
    if normalized_dir == "/" {
        format!("/{}", name)
    } else {
        format!("{}/{}", normalized_dir, name)
    }
}

#[derive(Debug)]
struct GateDenyDecision {
    process: String,
    ancestor: String,
    reason: &'static str,
}

/// Core decision: should this operation be denied?
/// Returns Some(decision) if denied, None if allowed.
fn should_deny(
    path: &str,
    pid: i32,
    home: &str,
    policy: &SecurityPolicy,
    cache: &mut HashMap<i32, CachedAncestor>,
    trust_cache: &Arc<Mutex<TrustedProcessCache>>,
    signature_cache: &Arc<Mutex<BinarySignatureCache>>,
    signature_refresh_tx: &mpsc::SyncSender<String>,
) -> Option<GateDenyDecision> {
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
    let trusted_process = evaluate_trusted_process(
        pid,
        process_name.as_str(),
        policy,
        trust_cache,
        signature_cache,
        signature_refresh_tx,
    );

    // 4. Keep git/jj commit internals workable while still blocking `git rm` on working tree files.
    if should_allow_vcs_metadata_unlink_in_ai_context(path, Some(process_name.as_str()), &trusted_process, policy) {
        return None;
    }
    let vcs_metadata_mismatch = policy.allow_vcs_metadata_in_ai_context
        && is_vcs_metadata_path(path)
        && is_vcs_tool(process_name.as_str())
        && trusted_process.is_identity_mismatch();

    // 5. Keep `git merge` / `git pull` workflow writable inside protected zones (no rebase/rm bypass).
    if should_allow_git_merge_pull_for_process(pid, process_name.as_str(), &trusted_process, policy) {
        return None;
    }
    let merge_pull_mismatch = policy.allow_git_merge_pull_in_ai_context
        && process_name == "git"
        && trusted_process.is_identity_mismatch()
        && get_process_argv(pid).is_some_and(|args| is_git_merge_or_pull_invocation(&args));

    // 5. Optional compatibility mode for trusted tools in AI context.
    if policy.allow_trusted_tools_in_ai_context && trusted_process.is_trusted() {
        return None;
    }
    let trusted_tool_mismatch = policy.allow_trusted_tools_in_ai_context
        && policy.is_trusted_tool(process_name.as_str())
        && trusted_process.is_identity_mismatch();

    let reason = if vcs_metadata_mismatch || merge_pull_mismatch || trusted_tool_mismatch {
        REASON_TRUST_IDENTITY_MISMATCH
    } else {
        REASON_PROTECTED_ZONE_AI_DELETE
    };

    // 6. In AI agent context and protected path → DENY
    Some(GateDenyDecision {
        process: process_name,
        ancestor: ai_ancestor,
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_policy_defaults_are_safe() {
        let policy: SecurityPolicy =
            serde_json::from_str(r#"{"protected_zones":[],"temporary_overrides":[]}"#).expect("default policy json");
        assert!(policy.sensitive_zones.is_empty());
        assert!(policy.read_gate_enabled);
        assert!(policy.transfer_gate_enabled);
        assert!(policy.exec_gate_enabled);
        assert!(!policy.audit_only_mode);
        assert!(policy.trusted_tool_identities.is_empty());
        assert!(!policy.trusted_identity_require_cdhash);
        assert_eq!(
            policy.taint_ttl_seconds_or_default(),
            DEFAULT_TAINT_TTL_SECS
        );
    }

    #[test]
    fn policy_taint_ttl_seconds_can_be_overridden() {
        let policy: SecurityPolicy = serde_json::from_str(
            r#"{
                "protected_zones":[],
                "temporary_overrides":[],
                "taint_ttl_seconds":42
            }"#,
        )
        .expect("policy json");
        assert_eq!(policy.taint_ttl_seconds_or_default(), 42);
    }

    #[test]
    fn policy_audit_only_mode_defaults_to_false() {
        let policy: SecurityPolicy =
            serde_json::from_str(r#"{"protected_zones":[],"temporary_overrides":[]}"#).expect("policy json");
        assert!(!policy.audit_only_mode);
    }

    #[test]
    fn policy_audit_only_mode_can_be_enabled() {
        let policy: SecurityPolicy = serde_json::from_str(
            r#"{
                "protected_zones":[],
                "temporary_overrides":[],
                "audit_only_mode":true
            }"#,
        )
        .expect("policy json");
        assert!(policy.audit_only_mode);
    }

    #[test]
    fn save_policy_preserves_taint_ttl_seconds_field() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "agentsmith-policy-roundtrip-{}-{}",
            std::process::id(),
            now_ts()
        ));
        fs::create_dir_all(&tmp_dir).expect("create temp dir");
        let policy_path = tmp_dir.join("policy.json");
        fs::write(
            &policy_path,
            r#"{
              "protected_zones": [],
              "temporary_overrides": [],
              "taint_ttl_seconds": 42
            }"#,
        )
        .expect("write policy json");

        let policy = load_policy(policy_path.to_str().expect("utf8 path")).expect("load policy");
        save_policy(policy_path.to_str().expect("utf8 path"), &policy).expect("save policy");

        let persisted = fs::read_to_string(&policy_path).expect("read persisted policy");
        let persisted_json: serde_json::Value = serde_json::from_str(&persisted).expect("decode persisted policy");
        assert_eq!(
            persisted_json.get("taint_ttl_seconds").and_then(|value| value.as_u64()),
            Some(42)
        );

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn sensitive_zone_boundary_match_is_correct() {
        let mut policy = test_policy();
        policy.sensitive_zones = vec!["/Users/jqwang/.codex".to_string()];
        assert!(policy.is_sensitive_path("/Users/jqwang/.codex/sessions/a.json"));
        assert!(!policy.is_sensitive_path("/Users/jqwang/.codexx/sessions/a.json"));
    }

    #[test]
    fn sensitive_destination_allows_only_allowlist() {
        let mut policy = test_policy();
        policy.sensitive_export_allow_zones = vec!["/Users/jqwang/.agentsmith-rs/guard/quarantine".to_string()];
        assert!(policy.is_sensitive_export_allowed("/Users/jqwang/.agentsmith-rs/guard/quarantine/a"));
        assert!(!policy.is_sensitive_export_allowed("/Users/jqwang/Desktop/a"));
    }

    #[test]
    fn open_read_on_sensitive_path_denies_non_ai_context() {
        let policy = test_sensitive_policy();
        let decision = decide_sensitive_open_for_test(
            "/Users/jqwang/.codex/chat/history.jsonl",
            false,
            FFLAG_READ,
            &policy,
        );
        assert!(decision.deny);
    }

    #[test]
    fn open_read_on_sensitive_path_denies_non_ai_with_zero_flag() {
        let policy = test_sensitive_policy();
        let decision = decide_sensitive_open_for_test("/Users/jqwang/.codex/chat/history.jsonl", false, 0, &policy);
        assert!(decision.deny);
    }

    #[test]
    fn open_read_on_sensitive_path_allows_ai_context() {
        let policy = test_sensitive_policy();
        let decision = decide_sensitive_open_for_test(
            "/Users/jqwang/.codex/chat/history.jsonl",
            true,
            FFLAG_READ,
            &policy,
        );
        assert!(!decision.deny);
    }

    #[test]
    fn open_read_on_sensitive_path_allows_temporary_override_for_human_read() {
        let mut policy = test_sensitive_policy();
        policy.temporary_overrides = vec![TemporaryOverrideEntry::Rule(TemporaryOverrideRule {
            path: "/Users/jqwang/.codex/chat".to_string(),
            expires_at: Some(now_ts().saturating_add(300)),
            created_at: Some(now_ts()),
            created_by: Some(OVERRIDE_CREATED_BY_SENSITIVE_READ_HELPER.to_string()),
        })];

        let decision = decide_sensitive_open_for_test(
            "/Users/jqwang/.codex/chat/history.jsonl",
            false,
            FFLAG_READ,
            &policy,
        );
        assert!(!decision.deny);
    }

    #[test]
    fn open_read_on_sensitive_path_allows_guard_process() {
        let policy = test_sensitive_policy();
        assert!(!should_deny_sensitive_open_for_process(
            "/Users/jqwang/.agentsmith-rs/policy.json",
            false,
            FFLAG_READ,
            &policy,
            true,
        ));
    }

    #[test]
    fn sensitive_read_observer_allows_policy_and_guard_logs() {
        let home = "/Users/jqwang";
        assert!(should_allow_sensitive_read_observer(
            "/Users/jqwang/.agentsmith-rs/policy.json",
            "AgentSmith",
            home,
        ));
        assert!(should_allow_sensitive_read_observer(
            "/Users/jqwang/.agentsmith-rs/policy.json.lock",
            "AgentSmith",
            home,
        ));
        assert!(should_allow_sensitive_read_observer(
            "/Users/jqwang/.agentsmith-rs/guard/denials.jsonl",
            "AgentSmith",
            home,
        ));
    }

    #[test]
    fn sensitive_read_observer_does_not_allow_chat_history_or_other_process() {
        let home = "/Users/jqwang";
        assert!(!should_allow_sensitive_read_observer(
            "/Users/jqwang/.codex/chat/history.jsonl",
            "AgentSmith",
            home,
        ));
        assert!(!should_allow_sensitive_read_observer(
            "/Users/jqwang/.agentsmith-rs/policy.json",
            "cat",
            home,
        ));
    }

    #[test]
    fn observer_metadata_reads_do_not_mark_taint() {
        let policy = test_sensitive_policy();
        let home = "/Users/jqwang";
        assert!(!should_mark_taint_on_sensitive_read(
            "/Users/jqwang/.agentsmith-rs/policy.json",
            &policy,
            home,
        ));
        assert!(!should_mark_taint_on_sensitive_read(
            "/Users/jqwang/.agentsmith-rs/guard/denials.jsonl",
            &policy,
            home,
        ));
        assert!(should_mark_taint_on_sensitive_read(
            "/Users/jqwang/.codex/chat/history.jsonl",
            &policy,
            home,
        ));
    }

    #[test]
    fn sensitive_source_to_desktop_is_denied() {
        let policy = test_sensitive_policy();
        assert!(should_deny_sensitive_transfer(
            "/Users/jqwang/.codex/sessions/a.json",
            "/Users/jqwang/Desktop/a.json",
            &policy
        ));
    }

    #[test]
    fn sensitive_source_to_quarantine_is_allowed() {
        let policy = test_sensitive_policy();
        assert!(!should_deny_sensitive_transfer(
            "/Users/jqwang/.codex/sessions/a.json",
            "/Users/jqwang/.agentsmith-rs/guard/quarantine/a.json",
            &policy
        ));
    }

    #[test]
    fn taint_expires_after_ttl() {
        let mut taint = TaintState::new(60);
        taint.mark(100, 1_000);
        assert!(taint.is_tainted(100, 1_030));
        assert!(!taint.is_tainted(100, 1_061));
    }

    #[test]
    fn taint_state_accepts_matching_pid_start_time_identity() {
        let mut taint = TaintState::new(60);
        let pid = std::process::id() as i32;
        let process_start = process_start_time_for_pid(pid).expect("current process start time must be available");
        taint.mark_with_process_start(pid, 1_000, Some(process_start));
        assert!(taint.is_tainted(pid, 1_030));
    }

    #[test]
    fn taint_state_rejects_pid_start_time_mismatch() {
        let mut taint = TaintState::new(60);
        let pid = std::process::id() as i32;
        taint.mark_with_process_start(
            pid,
            1_000,
            Some(ProcessStartTimeKey {
                start_tvsec: u64::MAX,
                start_tvusec: u64::MAX,
            }),
        );
        assert!(!taint.is_tainted(pid, 1_030));
    }

    #[test]
    fn taint_state_prune_expired_entries_keeps_recent_entries() {
        let mut taint = TaintState::new(60);
        taint.mark(100, 1_000);
        taint.mark(200, 1_150);
        taint.prune_expired(1_200);
        assert!(!taint.is_tainted(100, 1_200));
        assert!(taint.is_tainted(200, 1_200));
    }

    #[test]
    fn taint_state_inherits_to_child_pid_from_tainted_parent() {
        let mut taint = TaintState::new(60);
        taint.mark(100, 1_000);
        assert!(taint.inherit_from_parent(100, 200, 1_020));
        assert!(taint.is_tainted(200, 1_020));
    }

    #[test]
    fn taint_state_does_not_inherit_from_clean_parent() {
        let mut taint = TaintState::new(60);
        assert!(!taint.inherit_from_parent(100, 200, 1_020));
        assert!(!taint.is_tainted(200, 1_020));
    }

    #[test]
    fn tainted_process_write_outside_allow_zone_is_denied() {
        let policy = test_sensitive_policy();
        let mut taint = TaintState::new(600);
        taint.mark(100, 1_000);
        assert!(should_deny_tainted_write(
            100,
            "/Users/jqwang/Desktop/out.txt",
            Some("python3"),
            &TrustedProcessDecision::NotTrusted,
            1_100,
            &taint,
            &policy
        ));
    }

    #[test]
    fn tainted_git_metadata_write_is_allowed() {
        let policy = test_sensitive_policy();
        let mut taint = TaintState::new(600);
        taint.mark(100, 1_000);
        assert!(!should_deny_tainted_write(
            100,
            "/Users/jqwang/00-nixos-config/nixos-config/.git/index.lock",
            Some("git"),
            &TrustedProcessDecision::Trusted,
            1_100,
            &taint,
            &policy
        ));
    }

    #[test]
    fn tainted_non_vcs_metadata_write_is_denied() {
        let policy = test_sensitive_policy();
        let mut taint = TaintState::new(600);
        taint.mark(100, 1_000);
        assert!(should_deny_tainted_write(
            100,
            "/Users/jqwang/00-nixos-config/nixos-config/.git/index.lock",
            Some("python3"),
            &TrustedProcessDecision::NotTrusted,
            1_100,
            &taint,
            &policy
        ));
    }

    #[test]
    fn tainted_write_to_safe_device_paths_is_allowed() {
        let policy = test_sensitive_policy();
        let mut taint = TaintState::new(600);
        taint.mark(100, 1_000);

        for path in ["/dev/null", "/dev/tty", "/dev/dtracehelper"] {
            assert!(!should_deny_tainted_write(
                100,
                path,
                Some("bash"),
                &TrustedProcessDecision::NotTrusted,
                1_100,
                &taint,
                &policy
            ));
        }
    }

    #[test]
    fn tainted_write_to_other_device_paths_is_denied() {
        let policy = test_sensitive_policy();
        let mut taint = TaintState::new(600);
        taint.mark(100, 1_000);
        assert!(should_deny_tainted_write(
            100,
            "/dev/random",
            Some("bash"),
            &TrustedProcessDecision::NotTrusted,
            1_100,
            &taint,
            &policy
        ));
    }

    #[test]
    fn cache_watermark_highs_track_peaks() {
        let mut highs = CacheWatermarkHighs::default();
        assert_eq!(highs.update(2, 3, 1), (2, 3, 1));
        assert_eq!(highs.update(1, 4, 0), (2, 4, 1));
        assert_eq!(highs.update(8, 2, 9), (8, 4, 9));
    }

    #[test]
    fn cache_watermark_log_format_is_stable() {
        let line = format_cache_watermark_log(1_770_000_000, 2, 5, 3, 7, 1, 4);
        assert_eq!(
            line,
            "[METRIC] cache-watermark ts=1770000000 ancestor=2/5 trusted=3/7 taint=1/4"
        );
    }

    #[test]
    fn callback_latency_metrics_snapshot_tracks_percentiles_and_resets() {
        let metrics = CallbackLatencyMetrics::new();
        metrics.observe(Duration::from_micros(80));
        metrics.observe(Duration::from_micros(1_200));
        metrics.observe(Duration::from_micros(700_000));

        let snapshot = metrics.snapshot_and_reset();
        assert_eq!(snapshot.total, 3);
        assert_eq!(snapshot.max_us, 700_000);
        assert_eq!(snapshot.percentile_upper_bound_us(50), 2_000);
        assert_eq!(snapshot.percentile_upper_bound_us(95), 500_001);
        assert_eq!(snapshot.percentile_upper_bound_us(99), 500_001);

        let after_reset = metrics.snapshot_and_reset();
        assert_eq!(after_reset.total, 0);
        assert_eq!(after_reset.max_us, 0);
        assert_eq!(after_reset.percentile_upper_bound_us(95), 0);
    }

    #[test]
    fn runtime_health_log_format_is_stable() {
        let mut counts = [0u64; CALLBACK_LATENCY_BUCKETS_US.len() + 1];
        counts[0] = 1;
        counts[1] = 1;
        counts[CALLBACK_LATENCY_BUCKETS_US.len()] = 1;
        let callback_latency = CallbackLatencySnapshot {
            counts,
            total: 3,
            max_us: 700_000,
        };

        let line = format_runtime_health_log(1_770_000_000, 4, 1, 2, 9, 3, 5, &callback_latency);
        assert_eq!(
            line,
            "[METRIC] runtime-health ts=1770000000 sigq_pending=4 sigq_drop_full=1 sigq_drop_disconnected=2 logq_pending=9 logq_drop_full=3 logq_drop_disconnected=5 cb_count=3 cb_p50_us=250 cb_p95_us=500001 cb_p99_us=500001 cb_max_us=700000"
        );
    }

    #[test]
    fn write_intent_detection_requires_write_flag() {
        assert!(!is_write_intent(FFLAG_READ));
        assert!(is_write_intent(FFLAG_WRITE));
        assert!(is_write_intent(FFLAG_READ | FFLAG_WRITE));
    }

    #[test]
    fn read_intent_detection_handles_zero_and_read_flags() {
        assert!(is_read_intent(0));
        assert!(is_read_intent(FFLAG_READ));
        assert!(is_read_intent(FFLAG_READ | FFLAG_WRITE));
        assert!(!is_read_intent(FFLAG_WRITE));
    }

    #[test]
    fn auth_open_fast_allow_requires_non_sensitive_read_only_path() {
        let policy = test_sensitive_policy();
        assert!(should_fast_allow_open(
            "/Users/jqwang/project/notes.txt",
            FFLAG_READ,
            &policy
        ));
        assert!(!should_fast_allow_open(
            "/Users/jqwang/project/notes.txt",
            FFLAG_WRITE,
            &policy
        ));
        assert!(!should_fast_allow_open(
            "/Users/jqwang/.codex/config.toml",
            FFLAG_READ,
            &policy
        ));
    }

    #[test]
    fn tainted_open_write_outside_allow_zone_is_denied() {
        let policy = test_sensitive_policy();
        let mut taint = TaintState::new(600);
        taint.mark(100, 1_000);
        assert!(should_deny_tainted_open_write(
            100,
            "/Users/jqwang/Desktop/out.txt",
            FFLAG_WRITE,
            Some("python3"),
            &TrustedProcessDecision::NotTrusted,
            1_100,
            &taint,
            &policy
        ));
    }

    #[test]
    fn tainted_open_read_only_outside_allow_zone_is_allowed() {
        let policy = test_sensitive_policy();
        let mut taint = TaintState::new(600);
        taint.mark(100, 1_000);
        assert!(!should_deny_tainted_open_write(
            100,
            "/Users/jqwang/Desktop/out.txt",
            FFLAG_READ,
            Some("python3"),
            &TrustedProcessDecision::NotTrusted,
            1_100,
            &taint,
            &policy
        ));
    }

    #[test]
    fn exfil_tool_is_denied_in_ai_context() {
        let policy = test_sensitive_policy();
        assert!(should_deny_exec_in_ai_context("curl", true, &policy));
    }

    #[test]
    fn exfil_tool_is_allowed_outside_ai_context() {
        let policy = test_sensitive_policy();
        assert!(!should_deny_exec_in_ai_context("curl", false, &policy));
    }

    #[test]
    fn denial_record_includes_reason_code() {
        let record = DenialRecord::for_test_reason("SENSITIVE_READ_NON_AI");
        let json = serde_json::to_string(&record).expect("serialize");
        assert!(json.contains("SENSITIVE_READ_NON_AI"));
    }

    #[test]
    fn denial_feedback_for_sensitive_read_has_read_specific_guidance() {
        let record = DenialRecord::for_test_reason(REASON_SENSITIVE_READ_NON_AI);
        let feedback = build_denial_feedback("/Users/jqwang", &record);
        assert!(feedback.contains("non-AI reads are denied"));
        assert!(feedback.contains("AI context"));
        assert!(!feedback.contains("agentsmith-override --minutes 3"));
    }

    #[test]
    fn denial_feedback_for_protected_delete_keeps_override_guidance() {
        let record = DenialRecord::for_test_reason(REASON_PROTECTED_ZONE_AI_DELETE);
        let feedback = build_denial_feedback("/Users/jqwang", &record);
        assert!(feedback.contains("agentsmith-override --minutes 3"));
        assert!(feedback.contains("agentsmith-quarantine"));
    }

    #[test]
    fn denial_feedback_for_trust_mismatch_has_identity_guidance() {
        let mut record = DenialRecord::for_test_reason(REASON_TRUST_IDENTITY_MISMATCH);
        record.process = "git".to_string();
        let feedback = build_denial_feedback("/Users/jqwang", &record);
        assert!(feedback.contains("identity verification failed"));
        assert!(feedback.contains("trusted_tool_identities"));
    }

    #[test]
    fn trusted_identity_self_check_warns_when_identities_missing() {
        let mut policy = test_policy();
        policy.trusted_tools = vec!["git".to_string(), "cargo".to_string()];
        policy.trusted_tool_identities = vec![];

        let warning = trusted_identity_configuration_warning(&policy).expect("warning expected");
        assert!(warning.contains("trusted_tool_identities"));
        assert!(warning.contains("TRUST_IDENTITY_MISMATCH"));
        assert!(warning.contains("git"));
        assert!(!warning.contains("cargo"));
    }

    #[test]
    fn trusted_identity_self_check_ignores_unused_tools_for_warning_scope() {
        let mut policy = test_policy();
        policy.trusted_tools = vec!["git".to_string(), "cargo".to_string()];
        policy.trusted_tool_identities = vec![TrustedToolIdentity {
            path: "/usr/bin/git".to_string(),
            signing_identifier: "com.apple.git".to_string(),
            team_identifier: None,
            cdhash: None,
        }];

        assert!(trusted_identity_configuration_warning(&policy).is_none());
    }

    #[test]
    fn trusted_identity_self_check_warns_for_missing_tools_when_trusted_gate_enabled() {
        let mut policy = test_policy();
        policy.allow_trusted_tools_in_ai_context = true;
        policy.trusted_tools = vec!["git".to_string(), "cargo".to_string()];
        policy.trusted_tool_identities = vec![TrustedToolIdentity {
            path: "/usr/bin/git".to_string(),
            signing_identifier: "com.apple.git".to_string(),
            team_identifier: None,
            cdhash: None,
        }];

        let warning = trusted_identity_configuration_warning(&policy).expect("warning expected");
        assert!(warning.contains("cargo"));
        assert!(warning.contains("TRUST_IDENTITY_MISMATCH"));
    }

    #[test]
    fn trusted_identity_self_check_is_quiet_when_no_trusted_gates_are_active() {
        let mut policy = test_policy();
        policy.allow_vcs_metadata_in_ai_context = false;
        policy.allow_trusted_tools_in_ai_context = false;
        policy.trusted_tools = vec!["git".to_string()];
        policy.trusted_tool_identities = vec![];

        assert!(trusted_identity_configuration_warning(&policy).is_none());
    }

    #[test]
    fn trusted_identity_self_check_is_quiet_when_identities_present() {
        let mut policy = test_policy();
        policy.trusted_tools = vec!["git".to_string()];
        policy.trusted_tool_identities = vec![TrustedToolIdentity {
            path: "/usr/bin/git".to_string(),
            signing_identifier: "com.apple.git".to_string(),
            team_identifier: Some("not-real-team".to_string()),
            cdhash: None,
        }];

        assert!(trusted_identity_configuration_warning(&policy).is_none());
    }

    #[test]
    fn policy_self_check_warning_is_throttled_for_duplicate_messages() {
        let mut policy = test_policy();
        policy.trusted_tools = vec!["git".to_string()];
        policy.trusted_tool_identities = vec![];
        let mut warning_state = None;

        log_policy_self_checks(&policy, &mut warning_state, 1_000);
        let (first_warning, first_ts) = warning_state.clone().expect("warning state should be set");
        assert_eq!(first_ts, 1_000);

        log_policy_self_checks(&policy, &mut warning_state, 1_050);
        let (second_warning, second_ts) = warning_state.clone().expect("warning state should still be set");
        assert_eq!(first_warning, second_warning);
        assert_eq!(second_ts, 1_000);

        log_policy_self_checks(&policy, &mut warning_state, 1_401);
        let (_, third_ts) = warning_state.expect("warning state should remain set");
        assert_eq!(third_ts, 1_401);
    }

    #[derive(Debug)]
    struct SensitiveOpenDecision {
        deny: bool,
    }

    fn decide_sensitive_open_for_test(
        path: &str,
        is_ai_context: bool,
        fflag: i32,
        policy: &SecurityPolicy,
    ) -> SensitiveOpenDecision {
        SensitiveOpenDecision {
            deny: should_deny_sensitive_open(path, is_ai_context, fflag, policy),
        }
    }

    fn test_sensitive_policy() -> SecurityPolicy {
        let mut policy = test_policy();
        policy.sensitive_zones = vec!["/Users/jqwang/.codex".to_string()];
        policy.sensitive_export_allow_zones = vec!["/Users/jqwang/.agentsmith-rs/guard/quarantine".to_string()];
        policy
    }

    fn test_policy() -> SecurityPolicy {
        SecurityPolicy {
            protected_zones: vec!["/Users/jqwang/project".to_string()],
            temporary_overrides: vec![],
            auto_protect_home_digit_children: true,
            allow_vcs_metadata_in_ai_context: true,
            allow_git_merge_pull_in_ai_context: true,
            trusted_tools: default_trusted_tools(),
            trusted_tool_identities: vec![],
            ai_agent_patterns: default_ai_agent_patterns(),
            allow_trusted_tools_in_ai_context: false,
            exec_exfil_tool_blocklist: default_exec_exfil_tool_blocklist(),
            sensitive_zones: vec![],
            sensitive_export_allow_zones: vec![],
            read_gate_enabled: true,
            transfer_gate_enabled: true,
            exec_gate_enabled: true,
            audit_only_mode: false,
            taint_ttl_seconds: None,
            trusted_identity_require_cdhash: false,
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
            allow_git_merge_pull_in_ai_context: true,
            trusted_tools: default_trusted_tools(),
            trusted_tool_identities: vec![],
            ai_agent_patterns: default_ai_agent_patterns(),
            allow_trusted_tools_in_ai_context: false,
            exec_exfil_tool_blocklist: default_exec_exfil_tool_blocklist(),
            sensitive_zones: vec![],
            sensitive_export_allow_zones: vec![],
            read_gate_enabled: true,
            transfer_gate_enabled: true,
            exec_gate_enabled: true,
            audit_only_mode: false,
            taint_ttl_seconds: None,
            trusted_identity_require_cdhash: false,
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
            allow_git_merge_pull_in_ai_context: true,
            trusted_tools: default_trusted_tools(),
            trusted_tool_identities: vec![],
            ai_agent_patterns: default_ai_agent_patterns(),
            allow_trusted_tools_in_ai_context: false,
            exec_exfil_tool_blocklist: default_exec_exfil_tool_blocklist(),
            sensitive_zones: vec![],
            sensitive_export_allow_zones: vec![],
            read_gate_enabled: true,
            transfer_gate_enabled: true,
            exec_gate_enabled: true,
            audit_only_mode: false,
            taint_ttl_seconds: None,
            trusted_identity_require_cdhash: false,
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
    fn path_prefix_match_supports_system_volume_and_private_aliases() {
        assert!(path_prefix_match(
            "/System/Volumes/Data/Users/jqwang/.codex/config.toml",
            "/Users/jqwang/.codex"
        ));
        assert!(path_prefix_match(
            "/Users/jqwang/.codex/config.toml",
            "/System/Volumes/Data/Users/jqwang/.codex"
        ));
        assert!(path_prefix_match("/private/tmp/agentsmith-rs.tmp", "/tmp"));
        assert!(path_prefix_match("/tmp/agentsmith-rs.tmp", "/private/tmp"));
        assert!(!path_prefix_match(
            "/System/Volumes/Data/Users/jqwang/.codex-backup/config.toml",
            "/Users/jqwang/.codex"
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

    fn trusted_identity_for_path(path: &str) -> TrustedToolIdentity {
        let signature = read_binary_signature(path).expect("signed binary");
        TrustedToolIdentity {
            path: path.to_string(),
            signing_identifier: signature.signing_identifier,
            team_identifier: signature.team_identifier,
            cdhash: signature.cdhash,
        }
    }

    #[test]
    fn trusted_identity_accepts_real_system_git_and_xcrun() {
        let git_path = canonicalize_executable_path_strict("/usr/bin/git").expect("canonical git");
        let xcrun_path = canonicalize_executable_path_strict("/usr/bin/xcrun").expect("canonical xcrun");

        let mut policy = test_policy();
        policy.trusted_tools = vec!["git".to_string(), "xcrun".to_string()];
        policy.trusted_tool_identities = vec![
            trusted_identity_for_path(&git_path),
            trusted_identity_for_path(&xcrun_path),
        ];

        assert_eq!(
            evaluate_trusted_process_from_path("git", &git_path, &policy),
            TrustedProcessDecision::Trusted
        );
        assert_eq!(
            evaluate_trusted_process_from_path("xcrun", &xcrun_path, &policy),
            TrustedProcessDecision::Trusted
        );
    }

    #[test]
    fn trusted_identity_rejects_basename_spoof_binary() {
        let git_path = canonicalize_executable_path_strict("/usr/bin/git").expect("canonical git");
        let mut policy = test_policy();
        policy.trusted_tools = vec!["git".to_string()];
        policy.trusted_tool_identities = vec![trusted_identity_for_path(&git_path)];

        let tmp_dir = std::env::temp_dir().join(format!(
            "agentsmith-trust-spoof-{}-{}",
            std::process::id(),
            now_ts()
        ));
        fs::create_dir_all(&tmp_dir).expect("create spoof temp dir");
        let fake_git = tmp_dir.join("git");
        fs::write(&fake_git, "#!/bin/sh\necho fake-git\n").expect("write fake git");
        let mut perms = fs::metadata(&fake_git).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&fake_git, perms).expect("chmod fake git");

        let decision = evaluate_trusted_process_from_path("git", fake_git.to_str().expect("utf8 path"), &policy);
        assert!(matches!(
            decision,
            TrustedProcessDecision::IdentityMismatch(_)
        ));

        let _ = fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn trusted_identity_rejects_signed_binary_with_wrong_identity() {
        let git_path = canonicalize_executable_path_strict("/usr/bin/git").expect("canonical git");
        let xcrun_path = canonicalize_executable_path_strict("/usr/bin/xcrun").expect("canonical xcrun");

        let mut policy = test_policy();
        policy.trusted_tools = vec!["git".to_string()];
        policy.trusted_tool_identities = vec![trusted_identity_for_path(&git_path)];

        let decision = evaluate_trusted_process_from_path("git", &xcrun_path, &policy);
        assert!(matches!(
            decision,
            TrustedProcessDecision::IdentityMismatch(_)
        ));
    }

    #[test]
    fn trusted_identity_requires_trusted_tools_membership() {
        let git_path = canonicalize_executable_path_strict("/usr/bin/git").expect("canonical git");
        let mut policy = test_policy();
        policy.trusted_tools = vec![];
        policy.trusted_tool_identities = vec![trusted_identity_for_path(&git_path)];

        assert_eq!(
            evaluate_trusted_process_from_path("git", &git_path, &policy),
            TrustedProcessDecision::NotTrusted
        );
    }

    #[test]
    fn trusted_identity_rejects_symlink_executable_path() {
        let git_path = canonicalize_executable_path_strict("/usr/bin/git").expect("canonical git");
        let mut policy = test_policy();
        policy.trusted_tools = vec!["git".to_string()];
        policy.trusted_tool_identities = vec![trusted_identity_for_path(&git_path)];

        let tmp_dir = std::env::temp_dir().join(format!(
            "agentsmith-trust-symlink-{}-{}",
            std::process::id(),
            now_ts()
        ));
        fs::create_dir_all(&tmp_dir).expect("create symlink temp dir");
        let link_path = tmp_dir.join("git");
        std::os::unix::fs::symlink("/usr/bin/git", &link_path).expect("create symlink");

        let decision = evaluate_trusted_process_from_path("git", link_path.to_str().expect("utf8 path"), &policy);
        assert!(matches!(
            decision,
            TrustedProcessDecision::IdentityMismatch(_)
        ));

        let _ = fs::remove_dir_all(tmp_dir);
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
            allow_git_merge_pull_in_ai_context: true,
            trusted_tools: default_trusted_tools(),
            trusted_tool_identities: vec![],
            ai_agent_patterns: default_ai_agent_patterns(),
            allow_trusted_tools_in_ai_context: false,
            exec_exfil_tool_blocklist: default_exec_exfil_tool_blocklist(),
            sensitive_zones: vec![],
            sensitive_export_allow_zones: vec![],
            read_gate_enabled: true,
            transfer_gate_enabled: true,
            exec_gate_enabled: true,
            audit_only_mode: false,
            taint_ttl_seconds: None,
            trusted_identity_require_cdhash: false,
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
            allow_git_merge_pull_in_ai_context: true,
            trusted_tools: default_trusted_tools(),
            trusted_tool_identities: vec![],
            ai_agent_patterns: default_ai_agent_patterns(),
            allow_trusted_tools_in_ai_context: false,
            exec_exfil_tool_blocklist: default_exec_exfil_tool_blocklist(),
            sensitive_zones: vec![],
            sensitive_export_allow_zones: vec![],
            read_gate_enabled: true,
            transfer_gate_enabled: true,
            exec_gate_enabled: true,
            audit_only_mode: false,
            taint_ttl_seconds: None,
            trusted_identity_require_cdhash: false,
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
            allow_git_merge_pull_in_ai_context: true,
            trusted_tools: default_trusted_tools(),
            trusted_tool_identities: vec![],
            ai_agent_patterns: default_ai_agent_patterns(),
            allow_trusted_tools_in_ai_context: false,
            exec_exfil_tool_blocklist: default_exec_exfil_tool_blocklist(),
            sensitive_zones: vec![],
            sensitive_export_allow_zones: vec![],
            read_gate_enabled: true,
            transfer_gate_enabled: true,
            exec_gate_enabled: true,
            audit_only_mode: false,
            taint_ttl_seconds: None,
            trusted_identity_require_cdhash: false,
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
    fn sanitize_overrides_keeps_sensitive_zone_entries() {
        let mut policy = SecurityPolicy {
            protected_zones: vec![],
            temporary_overrides: vec![
                TemporaryOverrideEntry::Path("/Users/jqwang/.codex/chat/history.jsonl".to_string()),
                TemporaryOverrideEntry::Path("/Users/jqwang/other/file.txt".to_string()),
            ],
            auto_protect_home_digit_children: false,
            allow_vcs_metadata_in_ai_context: true,
            allow_git_merge_pull_in_ai_context: true,
            trusted_tools: default_trusted_tools(),
            trusted_tool_identities: vec![],
            ai_agent_patterns: default_ai_agent_patterns(),
            allow_trusted_tools_in_ai_context: false,
            exec_exfil_tool_blocklist: default_exec_exfil_tool_blocklist(),
            sensitive_zones: vec!["/Users/jqwang/.codex".to_string()],
            sensitive_export_allow_zones: vec![],
            read_gate_enabled: true,
            transfer_gate_enabled: true,
            exec_gate_enabled: true,
            audit_only_mode: false,
            taint_ttl_seconds: None,
            trusted_identity_require_cdhash: false,
        };

        let changed = policy.sanitize_overrides(1, "/Users/jqwang");
        assert!(changed, "outside sensitive-zone entries should be removed");
        assert_eq!(policy.temporary_overrides.len(), 1);
        assert_eq!(
            policy.temporary_overrides[0].path(),
            "/Users/jqwang/.codex/chat/history.jsonl"
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
            &TrustedProcessDecision::Trusted,
            &policy
        ));
        assert!(!should_allow_vcs_metadata_unlink_in_ai_context(
            "/Users/jqwang/repo/src/main.rs",
            Some("git"),
            &TrustedProcessDecision::Trusted,
            &policy
        ));
        assert!(!should_allow_vcs_metadata_unlink_in_ai_context(
            "/Users/jqwang/repo/.git/index.lock",
            Some("rm"),
            &TrustedProcessDecision::Trusted,
            &policy
        ));
        assert!(!should_allow_vcs_metadata_unlink_in_ai_context(
            "/Users/jqwang/repo/.git/index.lock",
            Some("git"),
            &TrustedProcessDecision::IdentityMismatch("sig mismatch".to_string()),
            &policy
        ));

        policy.allow_vcs_metadata_in_ai_context = false;
        assert!(!should_allow_vcs_metadata_unlink_in_ai_context(
            "/Users/jqwang/repo/.git/index.lock",
            Some("git"),
            &TrustedProcessDecision::Trusted,
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
            &TrustedProcessDecision::Trusted,
            &policy
        ));
        assert!(!should_allow_vcs_metadata_rename_in_ai_context(
            "/Users/jqwang/repo/.git/index.lock",
            "/private/tmp/index.lock",
            Some("git"),
            &TrustedProcessDecision::Trusted,
            &policy
        ));
        assert!(!should_allow_vcs_metadata_rename_in_ai_context(
            "/Users/jqwang/repo/.git/index.lock",
            "/Users/jqwang/repo/.git/index",
            Some("git"),
            &TrustedProcessDecision::IdentityMismatch("sig mismatch".to_string()),
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
    fn apply_override_request_allows_sensitive_zone_subpath() {
        let policy = test_sensitive_policy();
        let mut overrides = Vec::new();
        let request = OverrideRequest {
            id: "req-sensitive-allow".to_string(),
            action: "grant-sensitive-read".to_string(),
            path: Some("/Users/jqwang/.codex/chat/history.jsonl".to_string()),
            minutes: Some(3),
            requester_pid: None,
        };

        let (changed, response) = apply_override_request(&request, &policy, "/Users/jqwang", &mut overrides);
        assert!(changed);
        assert_eq!(response.status, "ok");
        assert_eq!(overrides.len(), 1);
        assert_eq!(
            overrides[0].path(),
            "/Users/jqwang/.codex/chat/history.jsonl"
        );
    }

    #[test]
    fn apply_override_request_rejects_sensitive_zone_root_path() {
        let policy = test_sensitive_policy();
        let mut overrides = Vec::new();
        let request = OverrideRequest {
            id: "req-sensitive-root".to_string(),
            action: "grant-sensitive-read".to_string(),
            path: Some("/Users/jqwang/.codex".to_string()),
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
    fn apply_override_request_rejects_sensitive_read_grant_outside_sensitive_zone() {
        let policy = test_sensitive_policy();
        let mut overrides = Vec::new();
        let request = OverrideRequest {
            id: "req-sensitive-outside".to_string(),
            action: "grant-sensitive-read".to_string(),
            path: Some("/Users/jqwang/project/file.txt".to_string()),
            minutes: Some(3),
            requester_pid: None,
        };

        let (changed, response) = apply_override_request(&request, &policy, "/Users/jqwang", &mut overrides);
        assert!(!changed);
        assert_eq!(response.status, "error");
        assert!(response.message.contains("outside sensitive"));
        assert!(overrides.is_empty());
    }

    #[test]
    fn sensitive_read_override_does_not_disable_protected_delete_gate() {
        let mut policy = test_policy();
        policy.temporary_overrides = vec![TemporaryOverrideEntry::Rule(TemporaryOverrideRule {
            path: "/Users/jqwang/project/file.txt".to_string(),
            expires_at: Some(now_ts().saturating_add(300)),
            created_at: Some(now_ts()),
            created_by: Some(OVERRIDE_CREATED_BY_SENSITIVE_READ_HELPER.to_string()),
        })];

        assert!(
            policy.is_protected("/Users/jqwang/project/file.txt", "/Users/jqwang"),
            "sensitive-read override should not bypass protected delete/move gate"
        );
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

    #[test]
    fn parse_procargs_argv_extracts_expected_arguments() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(3_i32).to_ne_bytes());
        payload.extend_from_slice(b"/bin/bash");
        payload.push(0);
        payload.push(0);
        payload.extend_from_slice(b"/bin/bash");
        payload.push(0);
        payload.extend_from_slice(b"/usr/local/bin/agentsmith-override");
        payload.push(0);
        payload.extend_from_slice(b"--clear");
        payload.push(0);

        let args = parse_procargs_argv(&payload);
        assert_eq!(args.len(), 3);
        assert_eq!(args[0], "/bin/bash");
        assert_eq!(args[1], "/usr/local/bin/agentsmith-override");
        assert_eq!(args[2], "--clear");
    }

    #[test]
    fn helper_argv_detection_requires_override_binary_argument() {
        let helper_args = vec![
            "/bin/bash".to_string(),
            "/usr/local/bin/agentsmith-override".to_string(),
            "--minutes".to_string(),
            "3".to_string(),
        ];
        assert!(is_override_helper_argv(&helper_args));

        let unrelated_args = vec!["/bin/bash".to_string(), "/tmp/custom-script.sh".to_string()];
        assert!(!is_override_helper_argv(&unrelated_args));
    }

    #[test]
    fn git_merge_or_pull_invocation_detects_allowed_subcommands() {
        let merge_args = vec![
            "git".to_string(),
            "-C".to_string(),
            "/Users/jqwang/00-nixos-config/agentsmith-rs-core".to_string(),
            "merge".to_string(),
            "feature/codex-sensitive-dlp-c".to_string(),
        ];
        assert!(is_git_merge_or_pull_invocation(&merge_args));

        let pull_args = vec![
            "git".to_string(),
            "--work-tree=/Users/jqwang/00-nixos-config/agentsmith-rs-core".to_string(),
            "pull".to_string(),
            "--ff-only".to_string(),
        ];
        assert!(is_git_merge_or_pull_invocation(&pull_args));
    }

    #[test]
    fn git_merge_or_pull_invocation_rejects_other_subcommands() {
        let rebase_args = vec!["git".to_string(), "rebase".to_string(), "main".to_string()];
        assert!(!is_git_merge_or_pull_invocation(&rebase_args));

        let rm_args = vec!["git".to_string(), "rm".to_string(), "README.md".to_string()];
        assert!(!is_git_merge_or_pull_invocation(&rm_args));
    }

    #[test]
    fn git_merge_or_pull_allow_requires_git_process_and_policy_flag() {
        let mut policy = test_policy();
        policy.allow_git_merge_pull_in_ai_context = true;

        let merge_args = vec!["git".to_string(), "merge".to_string(), "topic".to_string()];
        assert!(should_allow_git_merge_pull_worktree_change_in_ai_context(
            "git",
            &merge_args,
            &TrustedProcessDecision::Trusted,
            &policy
        ));
        assert!(!should_allow_git_merge_pull_worktree_change_in_ai_context(
            "bash",
            &merge_args,
            &TrustedProcessDecision::Trusted,
            &policy
        ));
        assert!(!should_allow_git_merge_pull_worktree_change_in_ai_context(
            "git",
            &merge_args,
            &TrustedProcessDecision::IdentityMismatch("sig mismatch".to_string()),
            &policy
        ));

        policy.allow_git_merge_pull_in_ai_context = false;
        assert!(!should_allow_git_merge_pull_worktree_change_in_ai_context(
            "git",
            &merge_args,
            &TrustedProcessDecision::Trusted,
            &policy
        ));
    }

    #[test]
    fn invalidate_trust_cache_for_pid_removes_all_cached_identities_for_pid() {
        let mut cache = HashMap::new();
        cache.insert(
            ProcessIdentityKey {
                pid: 123,
                start_tvsec: 11,
                start_tvusec: 22,
                executable_path: "/usr/bin/git".to_string(),
            },
            CachedTrustedProcess {
                decision: TrustedProcessDecision::Trusted,
                updated_at: 100,
            },
        );
        cache.insert(
            ProcessIdentityKey {
                pid: 123,
                start_tvsec: 11,
                start_tvusec: 22,
                executable_path: "/usr/bin/xcrun".to_string(),
            },
            CachedTrustedProcess {
                decision: TrustedProcessDecision::IdentityMismatch("mismatch".to_string()),
                updated_at: 100,
            },
        );
        cache.insert(
            ProcessIdentityKey {
                pid: 456,
                start_tvsec: 33,
                start_tvusec: 44,
                executable_path: "/usr/bin/git".to_string(),
            },
            CachedTrustedProcess {
                decision: TrustedProcessDecision::Trusted,
                updated_at: 100,
            },
        );

        invalidate_trust_cache_for_pid(&mut cache, 123);

        assert_eq!(cache.len(), 1);
        assert!(cache.keys().all(|key| key.pid != 123));
    }

    #[test]
    fn trusted_process_cache_get_removes_expired_entry_without_full_prune() {
        let key = ProcessIdentityKey {
            pid: 321,
            start_tvsec: 11,
            start_tvusec: 22,
            executable_path: "/usr/bin/git".to_string(),
        };
        let mut cache = TrustedProcessCache {
            entries: HashMap::from([(
                key.clone(),
                CachedTrustedProcess {
                    decision: TrustedProcessDecision::Trusted,
                    updated_at: 1_000,
                },
            )]),
            last_prune_at: 1_301,
        };

        let now = 1_301;
        let decision = cache.get(&key, now);
        assert!(decision.is_none());
        assert!(!cache.entries.contains_key(&key));
    }

    #[test]
    fn trusted_process_cache_periodic_prune_compacts_other_expired_entries() {
        let fresh_key = ProcessIdentityKey {
            pid: 111,
            start_tvsec: 11,
            start_tvusec: 22,
            executable_path: "/usr/bin/git".to_string(),
        };
        let stale_key = ProcessIdentityKey {
            pid: 222,
            start_tvsec: 33,
            start_tvusec: 44,
            executable_path: "/usr/bin/xcrun".to_string(),
        };
        let now = 2_000;
        let mut cache = TrustedProcessCache {
            entries: HashMap::from([
                (
                    fresh_key.clone(),
                    CachedTrustedProcess {
                        decision: TrustedProcessDecision::Trusted,
                        updated_at: now,
                    },
                ),
                (
                    stale_key.clone(),
                    CachedTrustedProcess {
                        decision: TrustedProcessDecision::Trusted,
                        updated_at: now.saturating_sub(TRUST_CACHE_TTL_SECS + 1),
                    },
                ),
            ]),
            last_prune_at: now.saturating_sub(TRUST_CACHE_PRUNE_INTERVAL_SECS),
        };

        let decision = cache.get(&fresh_key, now);
        assert!(decision.is_some());
        assert!(!cache.entries.contains_key(&stale_key));
    }

    #[test]
    fn binary_signature_cache_get_removes_expired_entry_without_full_prune() {
        let path = "/usr/bin/git".to_string();
        let now: u64 = 5_000;
        let mut cache = BinarySignatureCache {
            entries: HashMap::from([(
                path.clone(),
                CachedBinarySignature {
                    signature: Ok(BinaryCodeSignature {
                        signing_identifier: "com.apple.git".to_string(),
                        team_identifier: Some("APPLE123".to_string()),
                        cdhash: Some("abcd".to_string()),
                    }),
                    updated_at: now.saturating_sub(SIGNATURE_CACHE_TTL_SECS + 1),
                },
            )]),
            in_flight: HashSet::new(),
            last_prune_at: now,
        };

        let signature = cache.get(path.as_str(), now);
        assert!(signature.is_none());
        assert!(!cache.entries.contains_key(path.as_str()));
    }

    #[test]
    fn binary_signature_cache_in_flight_refresh_is_debounced_and_released() {
        let path = "/usr/bin/git";
        let now = 100;
        let mut cache = BinarySignatureCache::default();

        assert!(cache.should_enqueue_refresh(path));
        assert!(!cache.should_enqueue_refresh(path));

        cache.cancel_in_flight_refresh(path);
        assert!(cache.should_enqueue_refresh(path));

        cache.insert(
            path.to_string(),
            Ok(BinaryCodeSignature {
                signing_identifier: "com.apple.git".to_string(),
                team_identifier: Some("APPLE123".to_string()),
                cdhash: Some("abcd".to_string()),
            }),
            now,
        );
        assert!(cache.should_enqueue_refresh(path));
    }

    #[test]
    fn binary_signature_cache_expires_error_entries_faster_than_success_entries() {
        let now: u64 = 8_000;
        let ok_path = "/usr/bin/git".to_string();
        let err_path = "/usr/bin/xcrun".to_string();
        let stale_age = SIGNATURE_ERROR_CACHE_TTL_SECS + 1;
        let mut cache = BinarySignatureCache {
            entries: HashMap::from([
                (
                    ok_path.clone(),
                    CachedBinarySignature {
                        signature: Ok(BinaryCodeSignature {
                            signing_identifier: "com.apple.git".to_string(),
                            team_identifier: Some("APPLE123".to_string()),
                            cdhash: Some("abcd".to_string()),
                        }),
                        updated_at: now.saturating_sub(stale_age),
                    },
                ),
                (
                    err_path.clone(),
                    CachedBinarySignature {
                        signature: Err("codesign failed".to_string()),
                        updated_at: now.saturating_sub(stale_age),
                    },
                ),
            ]),
            in_flight: HashSet::new(),
            last_prune_at: 0,
        };

        assert!(cache.get(err_path.as_str(), now).is_none());
        assert!(cache.entries.contains_key(ok_path.as_str()));
        assert!(!cache.entries.contains_key(err_path.as_str()));
    }

    #[test]
    fn signature_pending_decision_uses_stable_prefix_marker() {
        let pending =
            TrustedProcessDecision::IdentityMismatch(format!("{}: /usr/bin/git", TRUST_SIGNATURE_PENDING_PREFIX));
        assert!(trust_decision_is_signature_pending(&pending));
        assert!(!trust_decision_is_signature_pending(
            &TrustedProcessDecision::IdentityMismatch("codesign failed".to_string())
        ));
    }

    #[test]
    fn clear_process_state_for_pid_removes_ancestor_trust_and_taint() {
        let mut ancestor_cache = HashMap::new();
        ancestor_cache.insert(
            123,
            CachedAncestor {
                ai_ancestor: Some("codex".to_string()),
                updated_at: 100,
            },
        );
        ancestor_cache.insert(
            456,
            CachedAncestor {
                ai_ancestor: None,
                updated_at: 100,
            },
        );

        let mut trust_cache = TrustedProcessCache::default();
        trust_cache.entries.insert(
            ProcessIdentityKey {
                pid: 123,
                start_tvsec: 11,
                start_tvusec: 22,
                executable_path: "/usr/bin/git".to_string(),
            },
            CachedTrustedProcess {
                decision: TrustedProcessDecision::Trusted,
                updated_at: 100,
            },
        );
        trust_cache.entries.insert(
            ProcessIdentityKey {
                pid: 456,
                start_tvsec: 33,
                start_tvusec: 44,
                executable_path: "/usr/bin/git".to_string(),
            },
            CachedTrustedProcess {
                decision: TrustedProcessDecision::Trusted,
                updated_at: 100,
            },
        );

        let mut taint = TaintState::new(600);
        taint.mark(123, 1_000);
        taint.mark(456, 1_000);

        clear_process_state_for_pid(123, &mut ancestor_cache, &mut trust_cache, &mut taint);

        assert!(!ancestor_cache.contains_key(&123));
        assert!(ancestor_cache.contains_key(&456));
        assert!(trust_cache.entries.keys().all(|key| key.pid != 123));
        assert!(trust_cache.entries.keys().any(|key| key.pid == 456));
        assert!(!taint.is_tainted(123, 1_001));
        assert!(taint.is_tainted(456, 1_001));
    }

    #[test]
    fn validate_override_request_origin_rejects_non_helper_process() {
        let policy = test_policy();
        let mut child = std::process::Command::new("sleep")
            .arg("2")
            .spawn()
            .expect("sleep should spawn");
        let request = OverrideRequest {
            id: "req-origin-3".to_string(),
            action: "clear".to_string(),
            path: None,
            minutes: None,
            requester_pid: Some(child.id() as i32),
        };
        let err = validate_override_request_origin(&request, &policy).expect_err("non-helper process must be rejected");
        assert!(err.contains("not agentsmith-override helper"));
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn main() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let policy_path = format!("{}/.agentsmith-rs/policy.json", home);
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
    let mut startup_policy_warning_state = None;
    log_policy_self_checks(&initial_policy, &mut startup_policy_warning_state, now_ts());

    let initial_taint_ttl = initial_policy.taint_ttl_seconds_or_default();
    let global_policy = Arc::new(Mutex::new(initial_policy));
    init_async_log_worker(&home);

    // Process ancestry cache (cleared on policy reload)
    let ancestor_cache: Arc<Mutex<HashMap<i32, CachedAncestor>>> = Arc::new(Mutex::new(HashMap::new()));
    let trusted_process_cache: Arc<Mutex<TrustedProcessCache>> = Arc::new(Mutex::new(TrustedProcessCache::default()));
    let binary_signature_cache: Arc<Mutex<BinarySignatureCache>> =
        Arc::new(Mutex::new(BinarySignatureCache::default()));
    let (signature_refresh_tx, signature_refresh_rx) = mpsc::sync_channel::<String>(SIGNATURE_REFRESH_QUEUE_BOUND);
    let taint_state = Arc::new(Mutex::new(TaintState::new(initial_taint_ttl)));
    spawn_signature_refresh_worker(signature_refresh_rx, binary_signature_cache.clone());
    {
        let policy_snapshot = global_policy
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        warm_signature_cache_for_policy(
            &policy_snapshot,
            &binary_signature_cache,
            &signature_refresh_tx,
        );
    }

    // Policy hot-reload thread (1s polling)
    let policy_clone = global_policy.clone();
    let cache_clone = ancestor_cache.clone();
    let trust_cache_clone = trusted_process_cache.clone();
    let signature_cache_clone = binary_signature_cache.clone();
    let signature_refresh_tx_clone = signature_refresh_tx.clone();
    let taint_clone = taint_state.clone();
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
        let mut policy_warning_state = None;

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
                log_policy_self_checks(&combined_policy, &mut policy_warning_state, now_ts());
                if let Ok(mut lock) = policy_clone.lock() {
                    *lock = combined_policy.clone();
                    if let Ok(mut c) = cache_clone.lock() {
                        c.clear();
                    }
                    if let Ok(mut trust_cache) = trust_cache_clone.lock() {
                        trust_cache.clear_all();
                    }
                }
                if let Ok(mut signature_cache) = signature_cache_clone.lock() {
                    signature_cache.clear_all();
                }
                warm_signature_cache_for_policy(
                    &combined_policy,
                    &signature_cache_clone,
                    &signature_refresh_tx_clone,
                );
                if let Ok(mut taint) = taint_clone.lock() {
                    taint.set_ttl_secs(combined_policy.taint_ttl_seconds_or_default());
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

    let cache_metrics_clone = ancestor_cache.clone();
    let trust_metrics_clone = trusted_process_cache.clone();
    let taint_metrics_clone = taint_state.clone();
    let callback_latency_metrics = Arc::new(CallbackLatencyMetrics::new());
    let callback_latency_metrics_clone = callback_latency_metrics.clone();
    thread::spawn(move || {
        let mut highs = CacheWatermarkHighs::default();
        loop {
            emit_cache_watermark_log(
                &cache_metrics_clone,
                &trust_metrics_clone,
                &taint_metrics_clone,
                &mut highs,
            );
            thread::sleep(Duration::from_secs(CACHE_WATERMARK_LOG_INTERVAL_SECS));
        }
    });
    thread::spawn(move || loop {
        emit_runtime_health_log(callback_latency_metrics_clone.as_ref());
        thread::sleep(Duration::from_secs(RUNTIME_HEALTH_LOG_INTERVAL_SECS));
    });

    let safe_policy = AssertUnwindSafe(global_policy);
    let safe_cache = AssertUnwindSafe(ancestor_cache);
    let safe_trust_cache = AssertUnwindSafe(trusted_process_cache);
    let safe_signature_cache = AssertUnwindSafe(binary_signature_cache);
    let safe_taint = AssertUnwindSafe(taint_state);
    let home_for_handler = home.clone();
    let guard_pid = std::process::id() as i32;
    let signature_refresh_tx_for_handler = signature_refresh_tx.clone();
    let callback_latency_metrics_for_handler = callback_latency_metrics.clone();

    let handler = move |client: &mut Client<'_>, message: Message| {
        let _callback_latency_guard = CallbackLatencyGuard::new(callback_latency_metrics_for_handler.as_ref());
        let current_policy = safe_policy
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let pid = message.process().audit_token().pid();

        match message.event() {
            Some(Event::AuthOpen(open)) => {
                let path = open.file().path().to_string_lossy().into_owned();
                let fflag = open.fflag();

                if should_fast_allow_open(path.as_str(), fflag, &current_policy) {
                    let _ = client.respond_flags_result(&message, fflag as u32, false);
                    return;
                }

                let process_name = process_name_for_pid(pid).unwrap_or_else(|| format!("pid:{}", pid));
                let is_guard_process = pid == guard_pid;

                if current_policy.is_sensitive_path(path.as_str()) && is_read_intent(fflag) {
                    let mut cache = safe_cache.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    let ai_ancestor = find_ai_ancestor(pid, &current_policy, &mut cache);
                    let is_ai_context = ai_ancestor.is_some();
                    let allow_observer_read =
                        should_allow_sensitive_read_observer(&path, process_name.as_str(), &home_for_handler);
                    let should_deny = should_deny_sensitive_open_for_process(
                        &path,
                        is_ai_context,
                        fflag,
                        &current_policy,
                        is_guard_process,
                    ) && !allow_observer_read;

                    if should_deny {
                        let ancestor = ai_ancestor.unwrap_or_else(|| "none".to_string());
                        let zone = current_policy.matched_sensitive_zone(path.as_str());
                        println!(
                            "[DENY] open(read) by {} (via {}): {}",
                            process_name, ancestor, path
                        );
                        let record = DenialRecord {
                            ts: now_ts(),
                            op: "open".into(),
                            path: path.clone(),
                            dest: None,
                            zone,
                            process: process_name.clone(),
                            ancestor,
                            reason: REASON_SENSITIVE_READ_NON_AI.to_string(),
                            pid: pid_for_record(pid),
                            ppid: parent_pid_for_pid(pid),
                        };
                        if record_denial_or_audit_only(&home_for_handler, &current_policy, record) {
                            let _ = client.respond_flags_result(&message, 0, false);
                        } else {
                            let _ = client.respond_flags_result(&message, fflag as u32, false);
                        }
                        return;
                    }

                    if is_ai_context
                        && should_mark_taint_on_sensitive_read(path.as_str(), &current_policy, &home_for_handler)
                    {
                        let marked_at = now_ts();
                        let process_start = process_start_time_for_pid(pid);
                        let mut taint = safe_taint.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                        taint.mark_with_process_start(pid, marked_at, process_start);
                        drop(taint);
                        let ancestor = ai_ancestor.as_deref().unwrap_or("unknown").to_string();
                        log_taint_mark(
                            &home_for_handler,
                            &TaintMarkRecord {
                                ts: marked_at,
                                path: path.clone(),
                                process: process_name.clone(),
                                ancestor,
                                pid,
                                ppid: parent_pid_for_pid(pid),
                            },
                        );
                    }
                }

                let (deny_taint_write, denial_reason) = if is_write_intent(fflag) {
                    let trusted_process = evaluate_trusted_process(
                        pid,
                        process_name.as_str(),
                        &current_policy,
                        &safe_trust_cache.0,
                        &safe_signature_cache.0,
                        &signature_refresh_tx_for_handler,
                    );
                    let deny_taint_write = {
                        let taint = safe_taint.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                        should_deny_tainted_open_write(
                            pid,
                            &path,
                            fflag,
                            Some(process_name.as_str()),
                            &trusted_process,
                            now_ts(),
                            &taint,
                            &current_policy,
                        )
                    };
                    let reason = if deny_taint_write
                        && current_policy.allow_vcs_metadata_in_ai_context
                        && is_vcs_metadata_path(path.as_str())
                        && is_vcs_tool(process_name.as_str())
                        && trusted_process.is_identity_mismatch()
                    {
                        REASON_TRUST_IDENTITY_MISMATCH
                    } else {
                        REASON_TAINT_WRITE_OUT
                    };
                    (deny_taint_write, reason)
                } else {
                    (false, REASON_TAINT_WRITE_OUT)
                };

                if deny_taint_write {
                    println!("[DENY] open(write-taint) by {}: {}", process_name, path);
                    let record = DenialRecord {
                        ts: now_ts(),
                        op: "open".into(),
                        path: path.clone(),
                        dest: None,
                        zone: "taint".to_string(),
                        process: process_name.clone(),
                        ancestor: "tainted".to_string(),
                        reason: denial_reason.to_string(),
                        pid: pid_for_record(pid),
                        ppid: parent_pid_for_pid(pid),
                    };
                    if record_denial_or_audit_only(&home_for_handler, &current_policy, record) {
                        let _ = client.respond_flags_result(&message, 0, false);
                    } else {
                        let _ = client.respond_flags_result(&message, fflag as u32, false);
                    }
                } else {
                    let _ = client.respond_flags_result(&message, fflag as u32, false);
                }
            },
            Some(Event::AuthExec(exec)) => {
                clear_trust_cache_for_exec(&safe_trust_cache.0, pid);
                let target_path = exec.target().executable().path().to_string_lossy().into_owned();
                let target_name = exe_name(&target_path).to_string();
                let parent_pid = parent_pid_for_pid(pid);
                let marked_at = now_ts();
                let inherited = {
                    let mut taint = safe_taint.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    parent_pid
                        .map(|ppid| taint.inherit_from_parent(ppid, pid, marked_at))
                        .unwrap_or(false)
                };
                if inherited {
                    log_taint_mark(
                        &home_for_handler,
                        &TaintMarkRecord {
                            ts: marked_at,
                            path: target_path.clone(),
                            process: target_name.clone(),
                            ancestor: format!("inherit-from-pid:{}", parent_pid.unwrap_or_default()),
                            pid,
                            ppid: parent_pid,
                        },
                    );
                }
                let mut cache = safe_cache.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                let ai_ancestor = find_ai_ancestor(pid, &current_policy, &mut cache);
                let is_ai_context = ai_ancestor.is_some();
                let should_deny = should_deny_exec_in_ai_context(target_name.as_str(), is_ai_context, &current_policy);

                if should_deny {
                    let ancestor = ai_ancestor.unwrap_or_else(|| "none".to_string());
                    println!(
                        "[DENY] exec by {} (via {}): {}",
                        target_name, ancestor, target_path
                    );
                    let record = DenialRecord {
                        ts: now_ts(),
                        op: "exec".into(),
                        path: target_path,
                        dest: None,
                        zone: "exec-blocklist".to_string(),
                        process: target_name,
                        ancestor,
                        reason: REASON_EXEC_EXFIL_TOOL.to_string(),
                        pid: pid_for_record(pid),
                        ppid: parent_pid_for_pid(pid),
                    };
                    if record_denial_or_audit_only(&home_for_handler, &current_policy, record) {
                        let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_DENY, false);
                    } else {
                        let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                    }
                } else {
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                }
            },
            Some(Event::NotifyFork(fork)) => {
                let child_pid = fork.child().audit_token().pid();
                let marked_at = now_ts();
                let inherited = {
                    let mut taint = safe_taint.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    taint.inherit_from_parent(pid, child_pid, marked_at)
                };
                if inherited {
                    let child_path = fork.child().executable().path().to_string_lossy().into_owned();
                    let child_name = exe_name(&child_path).to_string();
                    log_taint_mark(
                        &home_for_handler,
                        &TaintMarkRecord {
                            ts: marked_at,
                            path: child_path,
                            process: child_name,
                            ancestor: format!("inherit-from-pid:{}", pid),
                            pid: child_pid,
                            ppid: pid_for_record(pid),
                        },
                    );
                }
            },
            Some(Event::NotifyExit(_exit)) => {
                let mut cache = safe_cache.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                let mut trust_cache = safe_trust_cache
                    .0
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let mut taint = safe_taint.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                clear_process_state_for_pid(pid, &mut cache, &mut trust_cache, &mut taint);
                taint.prune_expired(now_ts());
            },
            Some(Event::AuthCreate(create)) => {
                let dest_path = match create.destination() {
                    Some(EventCreateDestinationFile::ExistingFile(file)) => file.path().to_string_lossy().into_owned(),
                    Some(EventCreateDestinationFile::NewPath {
                        directory, filename, ..
                    }) => {
                        let dest_dir = directory.path().to_string_lossy().into_owned();
                        let dest_name = filename.to_string_lossy().into_owned();
                        join_path_component(&dest_dir, &dest_name)
                    },
                    None => String::new(),
                };
                let process_name = process_name_for_pid(pid).unwrap_or_else(|| format!("pid:{}", pid));
                let trusted_process = evaluate_trusted_process(
                    pid,
                    process_name.as_str(),
                    &current_policy,
                    &safe_trust_cache.0,
                    &safe_signature_cache.0,
                    &signature_refresh_tx_for_handler,
                );
                let deny_taint = {
                    let taint = safe_taint.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    should_deny_tainted_write(
                        pid,
                        &dest_path,
                        Some(process_name.as_str()),
                        &trusted_process,
                        now_ts(),
                        &taint,
                        &current_policy,
                    )
                };
                let denial_reason = if deny_taint
                    && current_policy.allow_vcs_metadata_in_ai_context
                    && is_vcs_metadata_path(dest_path.as_str())
                    && is_vcs_tool(process_name.as_str())
                    && trusted_process.is_identity_mismatch()
                {
                    REASON_TRUST_IDENTITY_MISMATCH
                } else {
                    REASON_TAINT_WRITE_OUT
                };

                if deny_taint {
                    println!("[DENY] create(taint) by {}: {}", process_name, dest_path);
                    let record = DenialRecord {
                        ts: now_ts(),
                        op: "create".into(),
                        path: dest_path,
                        dest: None,
                        zone: "taint".to_string(),
                        process: process_name,
                        ancestor: "tainted".to_string(),
                        reason: denial_reason.to_string(),
                        pid: pid_for_record(pid),
                        ppid: parent_pid_for_pid(pid),
                    };
                    if record_denial_or_audit_only(&home_for_handler, &current_policy, record) {
                        let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_DENY, false);
                    } else {
                        let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                    }
                } else {
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                }
            },
            Some(Event::AuthTruncate(truncate)) => {
                let target_path = truncate.target().path().to_string_lossy().into_owned();
                let process_name = process_name_for_pid(pid).unwrap_or_else(|| format!("pid:{}", pid));
                let trusted_process = evaluate_trusted_process(
                    pid,
                    process_name.as_str(),
                    &current_policy,
                    &safe_trust_cache.0,
                    &safe_signature_cache.0,
                    &signature_refresh_tx_for_handler,
                );
                let deny_taint = {
                    let taint = safe_taint.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    should_deny_tainted_write(
                        pid,
                        &target_path,
                        Some(process_name.as_str()),
                        &trusted_process,
                        now_ts(),
                        &taint,
                        &current_policy,
                    )
                };
                let denial_reason = if deny_taint
                    && current_policy.allow_vcs_metadata_in_ai_context
                    && is_vcs_metadata_path(target_path.as_str())
                    && is_vcs_tool(process_name.as_str())
                    && trusted_process.is_identity_mismatch()
                {
                    REASON_TRUST_IDENTITY_MISMATCH
                } else {
                    REASON_TAINT_WRITE_OUT
                };

                if deny_taint {
                    println!(
                        "[DENY] truncate(taint) by {}: {}",
                        process_name, target_path
                    );
                    let record = DenialRecord {
                        ts: now_ts(),
                        op: "truncate".into(),
                        path: target_path,
                        dest: None,
                        zone: "taint".to_string(),
                        process: process_name,
                        ancestor: "tainted".to_string(),
                        reason: denial_reason.to_string(),
                        pid: pid_for_record(pid),
                        ppid: parent_pid_for_pid(pid),
                    };
                    if record_denial_or_audit_only(&home_for_handler, &current_policy, record) {
                        let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_DENY, false);
                    } else {
                        let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                    }
                } else {
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                }
            },
            Some(Event::AuthCopyFile(copyfile)) => {
                let source_path = copyfile.source().path().to_string_lossy().into_owned();
                let dest_path = if let Some(target_file) = copyfile.target_file() {
                    target_file.path().to_string_lossy().into_owned()
                } else {
                    let target_dir = copyfile.target_dir().path().to_string_lossy().into_owned();
                    let target_name = copyfile.target_name().to_string_lossy().into_owned();
                    join_path_component(&target_dir, &target_name)
                };
                let should_deny = should_deny_sensitive_transfer(&source_path, &dest_path, &current_policy);

                if should_deny {
                    let process_name = process_name_for_pid(pid).unwrap_or_else(|| format!("pid:{}", pid));
                    let zone = current_policy.matched_sensitive_zone(&source_path);
                    println!(
                        "[DENY] copyfile by {}: {} -> {}",
                        process_name, source_path, dest_path
                    );
                    let record = DenialRecord {
                        ts: now_ts(),
                        op: "copyfile".into(),
                        path: source_path,
                        dest: Some(dest_path),
                        zone,
                        process: process_name,
                        ancestor: "n/a".to_string(),
                        reason: REASON_SENSITIVE_TRANSFER_OUT.to_string(),
                        pid: pid_for_record(pid),
                        ppid: parent_pid_for_pid(pid),
                    };
                    if record_denial_or_audit_only(&home_for_handler, &current_policy, record) {
                        let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_DENY, false);
                    } else {
                        let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                    }
                } else {
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                }
            },
            Some(Event::AuthClone(clone)) => {
                let source_path = clone.source().path().to_string_lossy().into_owned();
                let target_dir = clone.target_dir().path().to_string_lossy().into_owned();
                let target_name = clone.target_name().to_string_lossy().into_owned();
                let dest_path = join_path_component(&target_dir, &target_name);
                let should_deny = should_deny_sensitive_transfer(&source_path, &dest_path, &current_policy);

                if should_deny {
                    let process_name = process_name_for_pid(pid).unwrap_or_else(|| format!("pid:{}", pid));
                    let zone = current_policy.matched_sensitive_zone(&source_path);
                    println!(
                        "[DENY] clone by {}: {} -> {}",
                        process_name, source_path, dest_path
                    );
                    let record = DenialRecord {
                        ts: now_ts(),
                        op: "clone".into(),
                        path: source_path,
                        dest: Some(dest_path),
                        zone,
                        process: process_name,
                        ancestor: "n/a".to_string(),
                        reason: REASON_SENSITIVE_TRANSFER_OUT.to_string(),
                        pid: pid_for_record(pid),
                        ppid: parent_pid_for_pid(pid),
                    };
                    if record_denial_or_audit_only(&home_for_handler, &current_policy, record) {
                        let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_DENY, false);
                    } else {
                        let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                    }
                } else {
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                }
            },
            Some(Event::AuthLink(link)) => {
                let source_path = link.source().path().to_string_lossy().into_owned();
                let target_dir = link.target_dir().path().to_string_lossy().into_owned();
                let target_name = link.target_filename().to_string_lossy().into_owned();
                let dest_path = join_path_component(&target_dir, &target_name);
                let should_deny = should_deny_sensitive_transfer(&source_path, &dest_path, &current_policy);

                if should_deny {
                    let process_name = process_name_for_pid(pid).unwrap_or_else(|| format!("pid:{}", pid));
                    let zone = current_policy.matched_sensitive_zone(&source_path);
                    println!(
                        "[DENY] link by {}: {} -> {}",
                        process_name, source_path, dest_path
                    );
                    let record = DenialRecord {
                        ts: now_ts(),
                        op: "link".into(),
                        path: source_path,
                        dest: Some(dest_path),
                        zone,
                        process: process_name,
                        ancestor: "n/a".to_string(),
                        reason: REASON_SENSITIVE_TRANSFER_OUT.to_string(),
                        pid: pid_for_record(pid),
                        ppid: parent_pid_for_pid(pid),
                    };
                    if record_denial_or_audit_only(&home_for_handler, &current_policy, record) {
                        let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_DENY, false);
                    } else {
                        let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                    }
                } else {
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                }
            },
            Some(Event::AuthExchangeData(exchange)) => {
                let path1 = exchange.file1().path().to_string_lossy().into_owned();
                let path2 = exchange.file2().path().to_string_lossy().into_owned();
                let deny_pair = if should_deny_sensitive_transfer(&path1, &path2, &current_policy) {
                    Some((path1.clone(), path2.clone()))
                } else if should_deny_sensitive_transfer(&path2, &path1, &current_policy) {
                    Some((path2.clone(), path1.clone()))
                } else {
                    None
                };

                if let Some((source_path, dest_path)) = deny_pair {
                    let process_name = process_name_for_pid(pid).unwrap_or_else(|| format!("pid:{}", pid));
                    let zone = current_policy.matched_sensitive_zone(&source_path);
                    println!(
                        "[DENY] exchangedata by {}: {} <-> {}",
                        process_name, path1, path2
                    );
                    let record = DenialRecord {
                        ts: now_ts(),
                        op: "exchangedata".into(),
                        path: source_path,
                        dest: Some(dest_path),
                        zone,
                        process: process_name,
                        ancestor: "n/a".to_string(),
                        reason: REASON_SENSITIVE_TRANSFER_OUT.to_string(),
                        pid: pid_for_record(pid),
                        ppid: parent_pid_for_pid(pid),
                    };
                    if record_denial_or_audit_only(&home_for_handler, &current_policy, record) {
                        let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_DENY, false);
                    } else {
                        let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                    }
                } else {
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                }
            },
            Some(Event::AuthUnlink(unlink)) => {
                let path = unlink.target().path().to_string_lossy();

                let mut cache = safe_cache.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(decision) = should_deny(
                    &path,
                    pid,
                    &home_for_handler,
                    &current_policy,
                    &mut cache,
                    &safe_trust_cache.0,
                    &safe_signature_cache.0,
                    &signature_refresh_tx_for_handler,
                ) {
                    let zone = current_policy.matched_zone(&path, &home_for_handler);
                    println!(
                        "[DENY] unlink by {} (via {}): {}",
                        decision.process, decision.ancestor, path
                    );
                    let record = DenialRecord {
                        ts: now_ts(),
                        op: "unlink".into(),
                        path: path.to_string(),
                        dest: None,
                        zone,
                        process: decision.process,
                        ancestor: decision.ancestor,
                        reason: decision.reason.to_string(),
                        pid: pid_for_record(pid),
                        ppid: parent_pid_for_pid(pid),
                    };
                    if record_denial_or_audit_only(&home_for_handler, &current_policy, record) {
                        let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_DENY, false);
                    } else {
                        let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                    }
                } else {
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                }
            },
            Some(Event::AuthRename(rename)) => {
                let source_path = rename.source().path().to_string_lossy().into_owned();
                let dest_path_str = match rename.destination() {
                    Some(EventRenameDestinationFile::ExistingFile(file)) => file.path().to_string_lossy().into_owned(),
                    Some(EventRenameDestinationFile::NewPath { directory, filename }) => {
                        let dest_dir = directory.path().to_string_lossy().into_owned();
                        let dest_name = filename.to_string_lossy().into_owned();
                        join_path_component(&dest_dir, &dest_name)
                    },
                    None => String::new(),
                };

                if should_deny_sensitive_transfer(&source_path, &dest_path_str, &current_policy) {
                    let process_name = process_name_for_pid(pid).unwrap_or_else(|| format!("pid:{}", pid));
                    let zone = current_policy.matched_sensitive_zone(&source_path);
                    println!(
                        "[DENY] rename(sensitive) by {}: {} -> {}",
                        process_name, source_path, dest_path_str
                    );
                    let record = DenialRecord {
                        ts: now_ts(),
                        op: "rename".into(),
                        path: source_path.clone(),
                        dest: Some(dest_path_str),
                        zone,
                        process: process_name,
                        ancestor: "n/a".to_string(),
                        reason: REASON_SENSITIVE_TRANSFER_OUT.to_string(),
                        pid: pid_for_record(pid),
                        ppid: parent_pid_for_pid(pid),
                    };
                    if record_denial_or_audit_only(&home_for_handler, &current_policy, record) {
                        let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_DENY, false);
                    } else {
                        let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                    }
                    return;
                }

                // For rename: deny if moving OUT of protected zone in AI context
                let mut cache = safe_cache.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                let deny_reason = if !current_policy.is_protected(source_path.as_str(), &home_for_handler)
                    || is_system_temp(&source_path, &home_for_handler)
                {
                    None
                } else if let Some(ai_ancestor) = find_ai_ancestor(pid, &current_policy, &mut cache) {
                    let process_name = process_name_for_pid(pid).unwrap_or_else(|| format!("pid:{}", pid));
                    let trusted_process = evaluate_trusted_process(
                        pid,
                        process_name.as_str(),
                        &current_policy,
                        &safe_trust_cache.0,
                        &safe_signature_cache.0,
                        &signature_refresh_tx_for_handler,
                    );
                    if should_allow_vcs_metadata_rename_in_ai_context(
                        &source_path,
                        &dest_path_str,
                        Some(process_name.as_str()),
                        &trusted_process,
                        &current_policy,
                    ) {
                        None
                    } else if should_allow_git_merge_pull_for_process(
                        pid,
                        process_name.as_str(),
                        &trusted_process,
                        &current_policy,
                    ) {
                        None
                    } else if current_policy.allow_trusted_tools_in_ai_context && trusted_process.is_trusted() {
                        None
                    } else if !current_policy.is_in_any_zone(&dest_path_str, &home_for_handler) {
                        let reason = if (current_policy.allow_vcs_metadata_in_ai_context
                            && is_vcs_metadata_path(source_path.as_str())
                            && is_vcs_metadata_path(dest_path_str.as_str())
                            && is_vcs_tool(process_name.as_str())
                            && trusted_process.is_identity_mismatch())
                            || (current_policy.allow_git_merge_pull_in_ai_context
                                && process_name == "git"
                                && trusted_process.is_identity_mismatch()
                                && get_process_argv(pid).is_some_and(|args| is_git_merge_or_pull_invocation(&args)))
                            || (current_policy.allow_trusted_tools_in_ai_context
                                && current_policy.is_trusted_tool(process_name.as_str())
                                && trusted_process.is_identity_mismatch())
                        {
                            REASON_TRUST_IDENTITY_MISMATCH
                        } else {
                            REASON_PROTECTED_ZONE_AI_DELETE
                        };
                        Some(GateDenyDecision {
                            process: process_name,
                            ancestor: ai_ancestor,
                            reason,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some(decision) = deny_reason {
                    let zone = current_policy.matched_zone(&source_path, &home_for_handler);
                    println!(
                        "[DENY] rename by {} (via {}): {} -> {}",
                        decision.process, decision.ancestor, source_path, dest_path_str
                    );
                    let record = DenialRecord {
                        ts: now_ts(),
                        op: "rename".into(),
                        path: source_path,
                        dest: Some(dest_path_str),
                        zone,
                        process: decision.process,
                        ancestor: decision.ancestor,
                        reason: decision.reason.to_string(),
                        pid: pid_for_record(pid),
                        ppid: parent_pid_for_pid(pid),
                    };
                    if record_denial_or_audit_only(&home_for_handler, &current_policy, record) {
                        let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_DENY, false);
                    } else {
                        let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                    }
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
            es_event_type_t::ES_EVENT_TYPE_AUTH_OPEN,
            es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXIT,
            es_event_type_t::ES_EVENT_TYPE_NOTIFY_FORK,
            es_event_type_t::ES_EVENT_TYPE_AUTH_EXEC,
            es_event_type_t::ES_EVENT_TYPE_AUTH_CREATE,
            es_event_type_t::ES_EVENT_TYPE_AUTH_TRUNCATE,
            es_event_type_t::ES_EVENT_TYPE_AUTH_COPYFILE,
            es_event_type_t::ES_EVENT_TYPE_AUTH_CLONE,
            es_event_type_t::ES_EVENT_TYPE_AUTH_LINK,
            es_event_type_t::ES_EVENT_TYPE_AUTH_EXCHANGEDATA,
            es_event_type_t::ES_EVENT_TYPE_AUTH_UNLINK,
            es_event_type_t::ES_EVENT_TYPE_AUTH_RENAME,
        ])
        .expect("Failed to subscribe");

    println!("Codex-ES-Guard started [process-aware mode]");
    println!("Policy: ~/.agentsmith-rs/policy.json");
    println!("Denial log: ~/.agentsmith-rs/guard/denials.jsonl");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
