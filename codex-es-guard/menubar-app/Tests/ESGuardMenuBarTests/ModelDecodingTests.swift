import XCTest
@testable import ESGuardMenuBar

final class ModelDecodingTests: XCTestCase {
    func testPolicyDecodesSensitiveFields() throws {
        let json = """
        {
          "protected_zones": [],
          "temporary_overrides": [],
          "sensitive_zones": ["/Users/jqwang/.codex"],
          "sensitive_export_allow_zones": ["/Users/jqwang/.codex/es-guard/quarantine"],
          "exec_exfil_tool_blocklist": ["curl", "scp"],
          "read_gate_enabled": false,
          "transfer_gate_enabled": true,
          "exec_gate_enabled": false
        }
        """.data(using: .utf8)!

        let policy = try JSONDecoder().decode(SecurityPolicy.self, from: json)
        XCTAssertEqual(policy.sensitiveZones, ["/Users/jqwang/.codex"])
        XCTAssertEqual(policy.sensitiveExportAllowZones, ["/Users/jqwang/.codex/es-guard/quarantine"])
        XCTAssertEqual(policy.execExfilToolBlocklist, ["curl", "scp"])
        XCTAssertFalse(policy.readGateEnabled)
        XCTAssertTrue(policy.transferGateEnabled)
        XCTAssertFalse(policy.execGateEnabled)
    }

    func testDenialRecordDecodesReason() throws {
        let json = """
        {
          "ts": 1730000000,
          "op": "open",
          "path": "/Users/jqwang/.codex/chat/history.jsonl",
          "dest": null,
          "zone": "/Users/jqwang/.codex",
          "process": "cat",
          "ancestor": "Terminal",
          "reason": "SENSITIVE_READ_NON_AI"
        }
        """.data(using: .utf8)!

        let record = try JSONDecoder().decode(DenialRecord.self, from: json)
        XCTAssertEqual(record.reason, "SENSITIVE_READ_NON_AI")
    }

    func testGuardCacheMetricsParsesDaemonMetricLine() {
        let line = "[METRIC] cache-watermark ts=1770000000 ancestor=2/5 trusted=3/7 taint=1/4"
        let metrics = GuardCacheMetrics.parse(from: line)

        XCTAssertNotNil(metrics)
        XCTAssertEqual(metrics?.ts, 1_770_000_000)
        XCTAssertEqual(metrics?.ancestorCurrent, 2)
        XCTAssertEqual(metrics?.ancestorHigh, 5)
        XCTAssertEqual(metrics?.trustedCurrent, 3)
        XCTAssertEqual(metrics?.trustedHigh, 7)
        XCTAssertEqual(metrics?.taintCurrent, 1)
        XCTAssertEqual(metrics?.taintHigh, 4)
    }

    func testGuardCacheMetricsRejectsInvalidLine() {
        let invalid = "[METRIC] cache-watermark ts=x ancestor=2/5 trusted=3/7"
        XCTAssertNil(GuardCacheMetrics.parse(from: invalid))
    }
}
