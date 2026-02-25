use endpoint_sec::{Client, Message, Event, EventRenameDestinationFile};
use endpoint_sec::sys::{es_event_type_t, es_auth_result_t};
use serde::Deserialize;
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use std::thread;
use std::panic::AssertUnwindSafe;

#[derive(Debug, Deserialize, Default, Clone)]
struct SecurityPolicy {
    protected_zones: Vec<String>,
    temporary_overrides: Vec<String>,
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
    path.contains("/.git/")                // 核心修复：放行 Git 内部清理操作
}

fn main() {
    let policy_path = format!("{}/.codex/es_policy.json", std::env::var("HOME").unwrap_or_else(|_| "/root".into()));
    
    let initial_policy = load_policy(&policy_path).unwrap_or_default();
    let global_policy = Arc::new(Mutex::new(initial_policy));
    
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
                                println!("🔄 [策略热重载] 检测到 es_policy.json 更新，规则已刷新！");
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

    let handler = move |client: &mut Client<'_>, message: Message| {
        let current_policy = safe_policy.0.lock().unwrap().clone();

        match message.event() {
            Some(Event::AuthUnlink(unlink)) => {
                let path = unlink.target().path().to_string_lossy();
                
                if current_policy.is_protected(&path) && !is_exempted_temp(&path) {
                    println!("🚨 [精准拦截] 阻止删除受保护文件: {}", path);
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
                    println!("🚨 [精准拦截] 阻止移出受保护区域: {} -> {}", source_path, dest_path_str);
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
    
    println!("Codex-ES-Guard 守护者已启动！ [默认放行模式]");
    println!("📖 当前仅保护 es_policy.json 中指定的 protected_zones");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
