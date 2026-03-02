import Foundation
import UserNotifications

class NotificationService {
    static let shared = NotificationService()
    
    func requestPermission() {
        let quarantineAction = UNNotificationAction(
            identifier: "ACTION_QUARANTINE",
            title: "先隔离到 temp",
            options: [.foreground]
        )

        let overrideAction = UNNotificationAction(
            identifier: "ACTION_OVERRIDE",
            title: "临时放行 (Override)",
            options: [.foreground]
        )
        
        let category = UNNotificationCategory(
            identifier: "ES_GUARD_DENIAL",
            actions: [quarantineAction, overrideAction],
            intentIdentifiers: [],
            options: .customDismissAction
        )
        
        let center = UNUserNotificationCenter.current()
        center.setNotificationCategories([category])
        
        center.requestAuthorization(options: [.alert, .sound]) { granted, error in
            if let error = error {
                print("通知权限请求失败: \(error)")
            }
        }
    }
    
    func sendDenialNotification(for record: DenialRecord) {
        let content = UNMutableNotificationContent()
        content.title = "⚠️ 拦截警告 (ES Guard)"
        let action = record.op == "unlink" ? "删除" : "移动"
        let fileName = URL(fileURLWithPath: record.path).lastPathComponent
        content.body = "已阻止 \(record.ancestor) 试图\(action)文件：\(fileName)。建议先隔离到 temp。"
        content.sound = UNNotificationSound.default
        content.categoryIdentifier = "ES_GUARD_DENIAL"
        content.userInfo = ["path": record.path]
        
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }
    
    func sendAutoRevokeNotification(path: String) {
        let content = UNMutableNotificationContent()
        content.title = "🛡️ ES Guard 安全提醒"
        content.body = "文件 [\(URL(fileURLWithPath: path).lastPathComponent)] 的临时放行已到期取消。"
        
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }
}
