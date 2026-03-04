import Foundation

private let noisySensitiveRootProcesses: Set<String> = [
    "atuin",
    "direnv",
    "git",
    "logd_helper",
    "ls",
]

private func normalizedPathForNoise(_ path: String) -> String {
    if path == "/" { return "/" }
    var normalized = path
    while normalized.hasSuffix("/") {
        normalized.removeLast()
    }
    return normalized.isEmpty ? "/" : normalized
}

func isNoisyDenialRecord(_ record: DenialRecord, homeDir: String) -> Bool {
    let normalizedPath = normalizedPathForNoise(record.path)

    if record.reason == "TAINT_WRITE_OUT" {
        return normalizedPath.hasPrefix("/dev/")
    }

    if record.reason == "SENSITIVE_READ_NON_AI" {
        let sensitiveRoot = normalizedPathForNoise(homeDir + "/.codex")
        if normalizedPath == sensitiveRoot {
            return noisySensitiveRootProcesses.contains(record.process.lowercased())
        }
    }

    return false
}

func isNoisyDaemonLogLine(_ text: String, homeDir: String) -> Bool {
    if text.contains("[DENY] open(write-taint)") && text.contains(": /dev/") {
        return true
    }

    if text.contains("[DENY] open(read)")
        && text.contains("(via none)") {
        let sensitiveRoot = "\(homeDir)/.codex"
        return text.hasSuffix(": \(sensitiveRoot)")
            || text.hasSuffix(": \(sensitiveRoot)/")
    }

    return false
}
