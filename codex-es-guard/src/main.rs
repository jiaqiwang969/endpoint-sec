use endpoint_sec::{Client, Message, Event, EventRenameDestinationFile};
use endpoint_sec::sys::{es_event_type_t, es_auth_result_t};
use serde::{Deserialize, Serialize};
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
}

#[derive(Debug, Serialize)]
struct DenialRecord {
    ts: u64,
    op: String,
    path: String,
    dest: Option<String>,
    zone: String,
}

impl SecurityPolicy {
    fn is_protected(&self, target_path: &str) -> bool {
        let in_zone = self.protected_zones.iter().any(|zone| target_path.starts_with(zone));
        if !in_zone {
            return false;
        }

        let is_overridden = self.temporary_overrides.iter().any(|override_path| target_path.starts_with(override_path));
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
}

fn load_policy(policy_path: &str) -> Option<SecurityPolicy> {
    if let Ok(content) = fs::read_to_string(policy_path) {
        serde_json::from_str(&content).ok()
    } else {
        None
    }
}

fn is_exempted_temp(path: &str) -> bool {
    path.contains("/.Trash/") ||
    path.contains("/tmp/") ||
    path.contains("/private/tmp/") ||
    path.contains("/var/folders/") ||
    path.contains("/private/var/folders/") ||
    path.contains("/.cache/") ||
    path.contains("/target/") ||
    path.contains("/node_modules/") ||
    path.contains("/result/") ||
    path.contains("/.git/")
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

    if !Path::new(&dir).exists() {
        let _ = fs::create_dir_all(&dir);
    }

    // Truncate if > 1MB to prevent unbounded growth
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
}

fn main() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let policy_path = format!("{}/.codex/es_policy.json", home);

    let initial_policy = load_policy(&policy_path).unwrap_or_default();
    let global_policy = Arc::new(Mutex::new(initial_policy));

    // Policy hot-reload thread (1s polling)
    let policy_clone = global_policy.clone();
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
                                println!("[策略热重载] 检测到 es_policy.json 更新，规则已刷新！");
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
    let home_for_handler = home.clone();

    let handler = move |client: &mut Client<'_>, message: Message| {
        let current_policy = safe_policy.0.lock().unwrap().clone();

        match message.event() {
            Some(Event::AuthUnlink(unlink)) => {
                let path = unlink.target().path().to_string_lossy();

                if current_policy.is_protected(&path) && !is_exempted_temp(&path) {
                    let zone = current_policy.matched_zone(&path);
                    println!("[DENY] unlink: {}", path);
                    log_denial(&home_for_handler, &DenialRecord {
                        ts: now_ts(),
                        op: "unlink".into(),
                        path: path.to_string(),
                        dest: None,
                        zone,
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

                if !current_policy.is_protected(&source_path) || is_exempted_temp(&source_path) {
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                }
                else if source_path.contains(".swp") || source_path.ends_with("~") || source_path.contains(".tmp") {
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                }
                else if !current_policy.protected_zones.iter().any(|zone| dest_path_str.starts_with(zone)) {
                    let zone = current_policy.matched_zone(&source_path);
                    println!("[DENY] rename: {} -> {}", source_path, dest_path_str);
                    log_denial(&home_for_handler, &DenialRecord {
                        ts: now_ts(),
                        op: "rename".into(),
                        path: source_path.to_string(),
                        dest: Some(dest_path_str.clone()),
                        zone,
                    });
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_DENY, false);
                }
                else {
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

    println!("Codex-ES-Guard started [default-allow mode]");
    println!("Policy: ~/.codex/es_policy.json");
    println!("Denial log: ~/.codex/es-guard/denials.jsonl");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
