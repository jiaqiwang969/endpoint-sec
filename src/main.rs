use endpoint_sec::{Client, Message, Event, EventRenameDestinationFile};
use endpoint_sec::sys::{es_event_type_t, es_auth_result_t};

fn main() {
    // 保护列表：只有这些目录下的文件不允许被物理删除
    let is_protected = |path: &str| -> bool {
        path.starts_with("/Users/jqwang/01-agent/") || 
        path.starts_with("/Users/jqwang/00-nixos-config/")
    };

    // 豁免列表：即使在保护目录下，这些类型的缓存/临时文件依然允许删除
    let is_exempted_temp = |path: &str| -> bool {
        path.contains("/.Trash/") ||           
        path.contains("/tmp/") ||              
        path.contains("/private/tmp/") ||      
        path.contains("/var/folders/") ||      
        path.contains("/private/var/folders/") || 
        path.contains("/.cache/") ||           
        path.contains("/target/") ||           
        path.contains("/node_modules/") ||     
        path.contains("/result/")              
    };

    let handler = |client: &mut Client<'_>, message: Message| {
        match message.event() {
            Some(Event::AuthUnlink(unlink)) => {
                let path = unlink.target().path().to_string_lossy();
                
                // 只有既在保护区，又不是临时文件的，才拦截
                if is_protected(&path) && !is_exempted_temp(&path) {
                    println!("🚨 [内核拦截] 阻止删除受保护文件: {}", path);
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

                // 如果源文件不在保护区，或者是临时文件，直接放行
                if !is_protected(&source_path) || is_exempted_temp(&source_path) {
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                } 
                // 如果是编辑器保存的临时文件重命名，放行
                else if source_path.contains(".swp") || source_path.ends_with("~") || source_path.contains(".tmp") {
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                }
                // 试图移出保护区（比如移入废纸篓，或移到别的目录） -> 拦截
                else if !is_protected(&dest_path_str) {
                    println!("🚨 [内核拦截] 阻止移出受保护区域: {} -> {}", source_path, dest_path_str);
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_DENY, false);
                }
                // 剩下的情况：在保护区内部改名 -> 放行
                else {
                    let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
                }
            }
            Some(_) => {
                let _ = client.respond_auth_result(&message, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false);
            }
            None => {}
        }
    };

    println!("Attempting to create ES Client...");
    let mut client = Client::new(handler).expect("Failed to create Endpoint Security client. Ensure you run as root and have proper entitlements.");

    client.subscribe(&[
        es_event_type_t::ES_EVENT_TYPE_AUTH_UNLINK,
        es_event_type_t::ES_EVENT_TYPE_AUTH_RENAME
    ]).expect("Failed to subscribe");
    
    println!("Codex-ES-Guard 守护者已启动，目前仅保护 01-agent 和 00-nixos-config 目录...");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
