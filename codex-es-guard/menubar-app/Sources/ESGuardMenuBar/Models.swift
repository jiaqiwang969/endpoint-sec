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
    
    var id: String { "\(ts)-\(path)" }
}

struct SecurityPolicy: Codable {
    var protectedZones: [String]
    var temporaryOverrides: [TemporaryOverride]
    var trustedTools: [String]?
    var aiAgentPatterns: [String]?
    var autoProtectHomeDigitChildren: Bool? = nil
    var allowVCSMetadataInAIContext: Bool? = nil
    var allowTrustedToolsInAIContext: Bool? = nil
    
    enum CodingKeys: String, CodingKey {
        case protectedZones = "protected_zones"
        case temporaryOverrides = "temporary_overrides"
        case trustedTools = "trusted_tools"
        case aiAgentPatterns = "ai_agent_patterns"
        case autoProtectHomeDigitChildren = "auto_protect_home_digit_children"
        case allowVCSMetadataInAIContext = "allow_vcs_metadata_in_ai_context"
        case allowTrustedToolsInAIContext = "allow_trusted_tools_in_ai_context"
    }
    
    static let empty = SecurityPolicy(protectedZones: [], temporaryOverrides: [])
}

struct LogLine: Identifiable {
    let id = UUID()
    let text: String
    let isError: Bool
}

// 图表数据模型
struct AgentStats: Identifiable {
    let id = UUID()
    let agentName: String
    let deleteCount: Int
    let moveCount: Int
    
    var total: Int { deleteCount + moveCount }
}
