import SwiftUI
import AppKit

enum ApplePalette {
    static let success = Color(nsColor: .systemGreen)
    static let warning = Color(nsColor: .systemOrange)
    static let danger = Color(nsColor: .systemRed)
    static let info = Color(nsColor: .systemBlue)
    static let accent = Color(nsColor: .controlAccentColor)

    static let panelBackground = Color(nsColor: .controlBackgroundColor)
    static let textBackground = Color(nsColor: .textBackgroundColor)
    static let border = Color(nsColor: .separatorColor).opacity(0.35)
    static let subtleDanger = danger.opacity(0.16)
    static let subtleSuccess = success.opacity(0.16)
    static let subtleWarning = warning.opacity(0.16)
    static let subtleInfo = info.opacity(0.16)
}
