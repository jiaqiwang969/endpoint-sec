import SwiftUI
import UserNotifications

class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    
    var viewModel: ESGuardViewModel?
    
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        NotificationService.shared.requestPermission()
        UNUserNotificationCenter.current().delegate = self
    }
    
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }
    
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
        if response.actionIdentifier == "ACTION_OVERRIDE" {
            if let path = response.notification.request.content.userInfo["path"] as? String {
                Task { @MainActor in
                    self.viewModel?.requestOverride(for: path)
                }
            }
        }
        completionHandler()
    }
}

@main
struct ESGuardMenuBarApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @StateObject private var viewModel = ESGuardViewModel()
    
    var body: some Scene {
        MenuBarExtra("ES Guard", systemImage: getIconName()) {
            DashboardView(viewModel: viewModel)
                .onAppear {
                    appDelegate.viewModel = viewModel
                }
        }
        .menuBarExtraStyle(.window)
        .onChange(of: viewModel.guardRunning) { _ in }
    }
    
    private func getIconName() -> String {
        if viewModel.guardRunning {
            if viewModel.hasUnacknowledgedRecords {
                return "exclamationmark.shield.fill" // 有未读拦截警报
            }
            return "checkmark.shield.fill" // 全部已读，正常守护
        }
        return "xmark.shield.fill"
    }
}
