import Foundation

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
    var temporaryOverrides: [String]
    var trustedTools: [String]?
    var aiAgentPatterns: [String]?
    
    enum CodingKeys: String, CodingKey {
        case protectedZones = "protected_zones"
        case temporaryOverrides = "temporary_overrides"
        case trustedTools = "trusted_tools"
        case aiAgentPatterns = "ai_agent_patterns"
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
