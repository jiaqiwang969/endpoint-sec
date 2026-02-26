use endpoint_sec::{Client, Message, Event, EventRenameDestinationFile};
use endpoint_sec::sys::{es_event_type_t, es_auth_result_t};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::thread;
use std::panic::AssertUnwindSafe;

#[derive(Debug, Deserialize, Default, Clone)]
struct SecurityPolicy {
    protected_zones: Vec<String>,
    temporary_overrides: Vec<String>,

    #[serde(default = "default_trusted_tools")]
    trusted_tools: Vec<String>,

    #[serde(default = "default_ai_agent_patterns")]
    ai_agent_patterns: Vec<String>,
}

fn default_trusted_tools() -> Vec<String> {
    [
        // VCS
        "git", "jj",
        // Rust
        "cargo", "rustup", "rustc",
        // Node.js
        "npm", "yarn", "pnpm", "bun", "node",
        // Python
        "pip", "pip3", "poetry", "uv", "python", "python3",
        // Swift / Xcode
        "swift", "swiftc", "xcodebuild", "xcrun",
        // Nix
        "nix", "nix-build", "nix-store", "nix-env", "nix-daemon",
        // System / macOS
        "brew", "launchd", "launchctl",
        // Build systems
        "make", "cmake", "ninja",
        // Go
        "go",
        // Docker
        "docker",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn default_ai_agent_patterns() -> Vec<String> {
    ["codex", "claude", "claude-code"]
        .iter()
        .map(|s| s.to_string())
        .collect()
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
    fn is_protected(&self, target_path: &str) -> bool {
        let in_zone = self.protected_zones.iter().any(|zone| target_path.starts_with(zone));
        if !in_zone {
            return false;
        }

        let is_overridden = self.temporary_overrides.iter().any(|ov| target_path.starts_with(ov));
        if is_overridden {
            return false;
        }

        true
    }

    fn matched_zone(&self, target_path: &str) -> String {
        self.protected_zones
            .iter()
            .find(|zone| target_path.starts_with(zone.as_str()))
            .cloned()
            .unwrap_or_default()
    }

    fn is_trusted_tool(&self, exe_name: &str) -> bool {
        self.trusted_tools.iter().any(|tool| exe_name == tool.as_str())
    }

    fn matches_ai_agent(&self, exe_path: &str) -> bool {
        let exe_name = exe_path.rsplit('/').next().unwrap_or(exe_path);
        self.ai_agent_patterns.iter().any(|pattern| {
            exe_name.contains(pattern.as_str())
        })
    }
}

fn load_policy(policy_path: &str) -> Option<SecurityPolicy> {
    if let Ok(content) = fs::read_to_string(policy_path) {
        serde_json::from_str(&content).ok()
    } else {
        None
    }
}

// Minimal system-level exemptions (no longer need tool-specific paths)
fn is_system_temp(path: &str) -> bool {
    path.contains("/.Trash/") ||
    path.contains("/private/tmp/") ||
    path.contains("/private/var/folders/") ||
    path.ends_with(".DS_Store")
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn log_denial(home: &str, record: &DenialRecord) {
    let dir = format!("{}/.codex/es-guard", home);
    let log_path = format!("{}/denials.jsonl", dir);
    let feedback_path = format!("{}/last_denial.txt", dir);

    if !Path::new(&dir).exists() {
        let _ = fs::create_dir_all(&dir);
    }

    if let Ok(meta) = fs::metadata(&log_path) {
        if meta.len() > 1_000_000 {
            let _ = fs::write(&log_path, "");
        }
    }

    if let Ok(json) = serde_json::to_string(record) {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&log_path) {
            let _ = writeln!(f, "{}", json);
        }
    }

    // Write human-readable feedback for AI agents
    let dest_info = record.dest.as_deref().map(|d| format!("\nDest: {}", d)).unwrap_or_default();
    let feedback = format!(
        "[ES-GUARD DENIED]\n\
         Operation: {}\n\
         Path: {}{}\n\
         Zone: {}\n\
         Process: {} (via {})\n\
         \n\
         To override, run: es-guard-override {}\n\
         Or manually: jq --arg p '{}' '.temporary_overrides += [$p]' ~/.codex/es_policy.json > /tmp/p.json && mv /tmp/p.json ~/.codex/es_policy.json && sleep 2\n\
         Then retry the operation.\n",
        record.op, record.path, dest_info,
        record.zone, record.process, record.ancestor,
        record.path, record.path
    );
    let _ = fs::write(&feedback_path, &feedback);
}

// --- Process tree walking (macOS) ---

fn get_process_path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    let ret = unsafe {
        libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32)
    };
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
        libc::sysctl(mib.as_mut_ptr(), 3, std::ptr::null_mut(), &mut size,
                     std::ptr::null_mut(), 0)
    };
    if ret != 0 || size == 0 { return None; }

    let mut buf = vec![0u8; size];
    let ret = unsafe {
        libc::sysctl(mib.as_mut_ptr(), 3, buf.as_mut_ptr() as *mut libc::c_void,
                     &mut size, std::ptr::null_mut(), 0)
    };
    if ret != 0 || size < 8 { return None; }

    // Layout: argc(i32) + exec_path + \0 + padding(\0s) + argv[0] + \0 + ...
    let mut pos = 4; // skip argc
    // skip exec_path
    while pos < size && buf[pos] != 0 { pos += 1; }
    // skip null padding
    while pos < size && buf[pos] == 0 { pos += 1; }
    // read argv[0]
    let start = pos;
    while pos < size && buf[pos] != 0 { pos += 1; }

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
fn find_ai_ancestor(pid: i32, policy: &SecurityPolicy, cache: &mut HashMap<i32, Option<String>>) -> Option<String> {
    let mut current = pid;
    let mut depth = 0;

    while current > 1 && depth < 30 {
        if let Some(cached) = cache.get(&current) {
            return cached.clone();
        }

        // Check executable path (Mach-O binary name)
        let exe_path = get_process_path(current);
        let exe_match = exe_path.as_ref().map(|p| policy.matches_ai_agent(p)).unwrap_or(false);

        // Check argv[0] (reflects process.title, e.g. Node.js "claude")
        let argv0 = get_process_argv0(current);
        let argv0_match = argv0.as_ref().map(|a| {
            policy.ai_agent_patterns.iter().any(|pat| a.contains(pat.as_str()))
        }).unwrap_or(false);

        if exe_match || argv0_match {
            let label = if argv0_match {
                argv0.unwrap_or_else(|| exe_path.as_ref().map(|p| exe_name(p).to_string()).unwrap_or_default())
            } else {
                exe_path.as_ref().map(|p| exe_name(p).to_string()).unwrap_or_default()
            };
            cache.insert(current, Some(label.clone()));
            return Some(label);
        }

        // Walk up to parent via proc_bsdinfo
        match get_process_info(current).map(|(pp, _)| pp).filter(|&pp| pp > 0) {
            Some(pp) => current = pp,
            None => break,
        }
        depth += 1;
    }

    cache.insert(pid, None);
    None
}

/// Check if the immediate process is a trusted tool.
fn is_trusted_process(pid: i32, policy: &SecurityPolicy) -> bool {
    if let Some(exe_path) = get_process_path(pid) {
        let name = exe_name(&exe_path);
        policy.is_trusted_tool(name)
    } else {
        false
    }
}

/// Core decision: should this operation be denied?
/// Returns Some((process_name, ancestor_name)) if denied, None if allowed.
fn should_deny(
    path: &str,
    pid: i32,
    policy: &SecurityPolicy,
    cache: &mut HashMap<i32, Option<String>>,
) -> Option<(String, String)> {
    // 1. Not in protected zone → ALLOW
    if !policy.is_protected(path) {
        return None;
    }

    // 2. System temp paths → ALLOW
    if is_system_temp(path) {
        return None;
    }

    // 3. Immediate process is a trusted tool → ALLOW
    //    (git managing .git/, cargo managing target/, etc.)
    if is_trusted_process(pid, policy) {
        return None;
    }

    // 4. Not in AI agent process tree → ALLOW (user operation)
    let ai_ancestor = match find_ai_ancestor(pid, policy, cache) {
        Some(name) => name,
        None => return None,
    };

    // 5. In AI agent context, protected path, not trusted tool → DENY
    let process_name = get_process_path(pid)
        .map(|p| exe_name(&p).to_string())
        .unwrap_or_else(|| format!("pid:{}", pid));

    Some((process_name, ai_ancestor))
}

fn main() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let policy_path = format!("{}/.codex/es_policy.json", home);

    let initial_policy = load_policy(&policy_path).unwrap_or_default();
    let global_policy = Arc::new(Mutex::new(initial_policy));

    // Process ancestry cache (cleared on policy reload)
    let ancestor_cache: Arc<Mutex<HashMap<i32, Option<String>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Policy hot-reload thread (1s polling)
    let policy_clone = global_policy.clone();
    let cache_clone = ancestor_cache.clone();
    let path_clone = policy_path.clone();
    thread::spawn(move || {
        let mut last_mtime = SystemTime::UNIX_EPOCH;
        loop {
            if let Ok(metadata) = fs::metadata(&path_clone) {
                if let Ok(mtime) = metadata.modified() {
                    if mtime != last_mtime {
                        if let Some(new_policy) = load_policy(&path_clone) {
                            if let Ok(mut lock) = policy_clone.lock() {
                                *lock = new_policy;
                                // Clear cache on policy change
                                if let Ok(mut c) = cache_clone.lock() {
                                    c.clear();
                                }
                                println!("[policy] reloaded");
                                last_mtime = mtime;
                            }
                        }
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
        let current_policy = safe_policy.0.lock().unwrap().clone();
        let pid = message.process().audit_token().pid();

        match message.event() {
            Some(Event::AuthUnlink(unlink)) => {
                let path = unlink.target().path().to_string_lossy();

                let mut cache = safe_cache.0.lock().unwrap();
                if let Some((proc_name, ancestor)) = should_deny(&path, pid, &current_policy, &mut cache) {
                    let zone = current_policy.matched_zone(&path);
                    println!("[DENY] unlink by {} (via {}): {}", proc_name, ancestor, path);
                    log_denial(&home_for_handler, &DenialRecord {
                        ts: now_ts(),
                        op: "unlink".into(),
                        path: path.to_string(),
                        dest: None,
                        zone,
                        process: proc_name,
                        ancestor,
                    });
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_DENY, false);
                } else {
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                }
            }
            Some(Event::AuthRename(rename)) => {
                let source_path = rename.source().path().to_string_lossy();
                let dest_path_str = match rename.destination() {
                    Some(EventRenameDestinationFile::ExistingFile(file)) => file.path().to_string_lossy().into_owned(),
                    Some(EventRenameDestinationFile::NewPath { directory, filename }) => {
                        format!("{}/{}", directory.path().to_string_lossy(), filename.to_string_lossy())
                    }
                    None => String::new(),
                };

                // For rename: deny if moving OUT of protected zone in AI context
                let mut cache = safe_cache.0.lock().unwrap();
                let deny_reason = if !current_policy.is_protected(&source_path) || is_system_temp(&source_path) {
                    None
                } else if is_trusted_process(pid, &current_policy) {
                    None
                } else if let Some(ai_ancestor) = find_ai_ancestor(pid, &current_policy, &mut cache) {
                    // In AI context: block if destination is outside all protected zones
                    if !current_policy.protected_zones.iter().any(|zone| dest_path_str.starts_with(zone)) {
                        let proc_name = get_process_path(pid)
                            .map(|p| exe_name(&p).to_string())
                            .unwrap_or_else(|| format!("pid:{}", pid));
                        Some((proc_name, ai_ancestor))
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some((proc_name, ancestor)) = deny_reason {
                    let zone = current_policy.matched_zone(&source_path);
                    println!("[DENY] rename by {} (via {}): {} -> {}", proc_name, ancestor, source_path, dest_path_str);
                    log_denial(&home_for_handler, &DenialRecord {
                        ts: now_ts(),
                        op: "rename".into(),
                        path: source_path.to_string(),
                        dest: Some(dest_path_str),
                        zone,
                        process: proc_name,
                        ancestor,
                    });
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_DENY, false);
                } else {
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                }
            }
            _ => {
                let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
            }
        }
    };

    println!("Attempting to create ES Client...");
    let mut client = Client::new(handler).expect("Failed to create Endpoint Security client. Ensure you run as root and have proper entitlements.");

    client.subscribe(&[
        es_event_type_t::ES_EVENT_TYPE_AUTH_UNLINK,
        es_event_type_t::ES_EVENT_TYPE_AUTH_RENAME
    ]).expect("Failed to subscribe");

    println!("Codex-ES-Guard started [process-aware mode]");
    println!("Policy: ~/.codex/es_policy.json");
    println!("Denial log: ~/.codex/es-guard/denials.jsonl");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
