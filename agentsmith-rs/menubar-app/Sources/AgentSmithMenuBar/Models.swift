import Foundation

struct TemporaryOverride: Codable, Identifiable, Hashable {
    let path: String
    let expiresAt: Int?
    let createdAt: Int?
    let createdBy: String?

    var id: String { path }

    var expiresDate: Date? {
        guard let ts = expiresAt else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(ts))
    }

    var isExpired: Bool {
        guard let ts = expiresAt else { return false }
        return ts <= Int(Date().timeIntervalSince1970)
    }

    enum CodingKeys: String, CodingKey {
        case path
        case expiresAt = "expires_at"
        case createdAt = "created_at"
        case createdBy = "created_by"
    }

    init(path: String, expiresAt: Int? = nil, createdAt: Int? = nil, createdBy: String? = nil) {
        self.path = path
        self.expiresAt = expiresAt
        self.createdAt = createdAt
        self.createdBy = createdBy
    }

    init(from decoder: Decoder) throws {
        let single = try decoder.singleValueContainer()
        if let rawPath = try? single.decode(String.self) {
            self.path = rawPath
            self.expiresAt = nil
            self.createdAt = nil
            self.createdBy = "legacy"
            return
        }

        let object = try single.decode(OverrideObject.self)
        self.path = object.path
        self.expiresAt = object.expiresAt
        self.createdAt = object.createdAt
        self.createdBy = object.createdBy
    }

    func encode(to encoder: Encoder) throws {
        var single = encoder.singleValueContainer()
        try single.encode(
            OverrideObject(path: path, expiresAt: expiresAt, createdAt: createdAt, createdBy: createdBy)
        )
    }
}

private struct OverrideObject: Codable {
    let path: String
    let expiresAt: Int?
    let createdAt: Int?
    let createdBy: String?

    enum CodingKeys: String, CodingKey {
        case path
        case expiresAt = "expires_at"
        case createdAt = "created_at"
        case createdBy = "created_by"
    }
}

struct DenialRecord: Codable, Identifiable {
    let ts: Int
    let op: String
    let path: String
    let dest: String?
    let zone: String
    let process: String
    let ancestor: String
    let reason: String

    var id: String { "\(ts)-\(path)" }

    enum CodingKeys: String, CodingKey {
        case ts
        case op
        case path
        case dest
        case zone
        case process
        case ancestor
        case reason
    }

    init(
        ts: Int,
        op: String,
        path: String,
        dest: String?,
        zone: String,
        process: String,
        ancestor: String,
        reason: String
    ) {
        self.ts = ts
        self.op = op
        self.path = path
        self.dest = dest
        self.zone = zone
        self.process = process
        self.ancestor = ancestor
        self.reason = reason
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        ts = try container.decode(Int.self, forKey: .ts)
        op = try container.decode(String.self, forKey: .op)
        path = try container.decode(String.self, forKey: .path)
        dest = try container.decodeIfPresent(String.self, forKey: .dest)
        zone = try container.decode(String.self, forKey: .zone)
        process = try container.decode(String.self, forKey: .process)
        ancestor = try container.decode(String.self, forKey: .ancestor)
        reason = try container.decodeIfPresent(String.self, forKey: .reason) ?? "LEGACY_NO_REASON"
    }
}

struct SecurityPolicy: Codable {
    var protectedZones: [String]
    var temporaryOverrides: [TemporaryOverride]
    var sensitiveZones: [String]
    var sensitiveExportAllowZones: [String]
    var trustedTools: [String]?
    var aiAgentPatterns: [String]?
    var autoProtectHomeDigitChildren: Bool? = nil
    var allowVCSMetadataInAIContext: Bool? = nil
    var allowGitMergePullInAIContext: Bool? = nil
    var allowTrustedToolsInAIContext: Bool? = nil
    var execExfilToolBlocklist: [String]
    var readGateEnabled: Bool
    var transferGateEnabled: Bool
    var execGateEnabled: Bool
    var auditOnlyMode: Bool
    var taintTTLSeconds: Int?
    
    enum CodingKeys: String, CodingKey {
        case protectedZones = "protected_zones"
        case temporaryOverrides = "temporary_overrides"
        case sensitiveZones = "sensitive_zones"
        case sensitiveExportAllowZones = "sensitive_export_allow_zones"
        case trustedTools = "trusted_tools"
        case aiAgentPatterns = "ai_agent_patterns"
        case autoProtectHomeDigitChildren = "auto_protect_home_digit_children"
        case allowVCSMetadataInAIContext = "allow_vcs_metadata_in_ai_context"
        case allowGitMergePullInAIContext = "allow_git_merge_pull_in_ai_context"
        case allowTrustedToolsInAIContext = "allow_trusted_tools_in_ai_context"
        case execExfilToolBlocklist = "exec_exfil_tool_blocklist"
        case readGateEnabled = "read_gate_enabled"
        case transferGateEnabled = "transfer_gate_enabled"
        case execGateEnabled = "exec_gate_enabled"
        case auditOnlyMode = "audit_only_mode"
        case taintTTLSeconds = "taint_ttl_seconds"
    }

    init(
        protectedZones: [String],
        temporaryOverrides: [TemporaryOverride],
        sensitiveZones: [String] = [],
        sensitiveExportAllowZones: [String] = [],
        trustedTools: [String]? = nil,
        aiAgentPatterns: [String]? = nil,
        autoProtectHomeDigitChildren: Bool? = nil,
        allowVCSMetadataInAIContext: Bool? = nil,
        allowGitMergePullInAIContext: Bool? = nil,
        allowTrustedToolsInAIContext: Bool? = nil,
        execExfilToolBlocklist: [String] = SecurityPolicy.defaultExecExfilToolBlocklist,
        readGateEnabled: Bool = true,
        transferGateEnabled: Bool = true,
        execGateEnabled: Bool = true,
        auditOnlyMode: Bool = false,
        taintTTLSeconds: Int? = nil
    ) {
        self.protectedZones = protectedZones
        self.temporaryOverrides = temporaryOverrides
        self.sensitiveZones = sensitiveZones
        self.sensitiveExportAllowZones = sensitiveExportAllowZones
        self.trustedTools = trustedTools
        self.aiAgentPatterns = aiAgentPatterns
        self.autoProtectHomeDigitChildren = autoProtectHomeDigitChildren
        self.allowVCSMetadataInAIContext = allowVCSMetadataInAIContext
        self.allowGitMergePullInAIContext = allowGitMergePullInAIContext
        self.allowTrustedToolsInAIContext = allowTrustedToolsInAIContext
        self.execExfilToolBlocklist = execExfilToolBlocklist
        self.readGateEnabled = readGateEnabled
        self.transferGateEnabled = transferGateEnabled
        self.execGateEnabled = execGateEnabled
        self.auditOnlyMode = auditOnlyMode
        self.taintTTLSeconds = taintTTLSeconds
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        protectedZones = try container.decodeIfPresent([String].self, forKey: .protectedZones) ?? []
        temporaryOverrides = try container.decodeIfPresent([TemporaryOverride].self, forKey: .temporaryOverrides) ?? []
        sensitiveZones = try container.decodeIfPresent([String].self, forKey: .sensitiveZones) ?? []
        sensitiveExportAllowZones = try container.decodeIfPresent([String].self, forKey: .sensitiveExportAllowZones) ?? []
        trustedTools = try container.decodeIfPresent([String].self, forKey: .trustedTools)
        aiAgentPatterns = try container.decodeIfPresent([String].self, forKey: .aiAgentPatterns)
        autoProtectHomeDigitChildren = try container.decodeIfPresent(Bool.self, forKey: .autoProtectHomeDigitChildren)
        allowVCSMetadataInAIContext = try container.decodeIfPresent(Bool.self, forKey: .allowVCSMetadataInAIContext)
        allowGitMergePullInAIContext = try container.decodeIfPresent(Bool.self, forKey: .allowGitMergePullInAIContext)
        allowTrustedToolsInAIContext = try container.decodeIfPresent(Bool.self, forKey: .allowTrustedToolsInAIContext)
        execExfilToolBlocklist = try container.decodeIfPresent([String].self, forKey: .execExfilToolBlocklist)
            ?? SecurityPolicy.defaultExecExfilToolBlocklist
        readGateEnabled = try container.decodeIfPresent(Bool.self, forKey: .readGateEnabled) ?? true
        transferGateEnabled = try container.decodeIfPresent(Bool.self, forKey: .transferGateEnabled) ?? true
        execGateEnabled = try container.decodeIfPresent(Bool.self, forKey: .execGateEnabled) ?? true
        auditOnlyMode = try container.decodeIfPresent(Bool.self, forKey: .auditOnlyMode) ?? false
        taintTTLSeconds = try container.decodeIfPresent(Int.self, forKey: .taintTTLSeconds)
    }

    static let defaultExecExfilToolBlocklist = ["curl", "wget", "scp", "sftp", "rsync", "nc", "ncat", "netcat"]
    static let empty = SecurityPolicy(protectedZones: [], temporaryOverrides: [])
}

struct LogLine: Identifiable {
    let id = UUID()
    let text: String
    let isError: Bool
    let isNoise: Bool
}

struct GuardCacheMetrics: Equatable {
    let ts: Int
    let ancestorCurrent: Int
    let ancestorHigh: Int
    let trustedCurrent: Int
    let trustedHigh: Int
    let taintCurrent: Int
    let taintHigh: Int

    static func parse(from text: String) -> GuardCacheMetrics? {
        let prefix = "[METRIC] cache-watermark "
        guard text.hasPrefix(prefix) else { return nil }

        let payload = text.dropFirst(prefix.count)
        var kv: [Substring: Substring] = [:]
        for token in payload.split(separator: " ") {
            let parts = token.split(separator: "=", maxSplits: 1)
            guard parts.count == 2 else { return nil }
            kv[parts[0]] = parts[1]
        }

        guard let tsText = kv["ts"], let ts = Int(tsText) else { return nil }
        guard let ancestor = parseCurrentHighPair(kv["ancestor"]) else { return nil }
        guard let trusted = parseCurrentHighPair(kv["trusted"]) else { return nil }
        guard let taint = parseCurrentHighPair(kv["taint"]) else { return nil }

        return GuardCacheMetrics(
            ts: ts,
            ancestorCurrent: ancestor.current,
            ancestorHigh: ancestor.high,
            trustedCurrent: trusted.current,
            trustedHigh: trusted.high,
            taintCurrent: taint.current,
            taintHigh: taint.high
        )
    }

    private static func parseCurrentHighPair(_ value: Substring?) -> (current: Int, high: Int)? {
        guard let value else { return nil }
        let parts = value.split(separator: "/", maxSplits: 1)
        guard parts.count == 2, let current = Int(parts[0]), let high = Int(parts[1]) else {
            return nil
        }
        return (current, high)
    }
}
