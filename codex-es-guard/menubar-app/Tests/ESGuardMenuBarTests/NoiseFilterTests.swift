import XCTest
@testable import ESGuardMenuBar

final class NoiseFilterTests: XCTestCase {
    func testTaintWriteToDevIsNoisy() {
        let record = DenialRecord(
            ts: 1,
            op: "open",
            path: "/dev/tty",
            dest: nil,
            zone: "taint",
            process: "bash",
            ancestor: "tainted",
            reason: "TAINT_WRITE_OUT"
        )

        XCTAssertTrue(isNoisyDenialRecord(record, homeDir: "/Users/jqwang"))
    }

    func testSensitiveRootReadByGitIsNoisy() {
        let record = DenialRecord(
            ts: 1,
            op: "open",
            path: "/Users/jqwang/.codex",
            dest: nil,
            zone: "/Users/jqwang/.codex",
            process: "git",
            ancestor: "none",
            reason: "SENSITIVE_READ_NON_AI"
        )

        XCTAssertTrue(isNoisyDenialRecord(record, homeDir: "/Users/jqwang"))
    }

    func testSensitiveSubpathReadByGitIsNotNoisy() {
        let record = DenialRecord(
            ts: 1,
            op: "open",
            path: "/Users/jqwang/.codex/secrets/key.txt",
            dest: nil,
            zone: "/Users/jqwang/.codex",
            process: "git",
            ancestor: "none",
            reason: "SENSITIVE_READ_NON_AI"
        )

        XCTAssertFalse(isNoisyDenialRecord(record, homeDir: "/Users/jqwang"))
    }

    func testNoisyDaemonLogLineDetection() {
        let noisyRead = "[DENY] open(read) by git (via none): /Users/jqwang/.codex"
        XCTAssertTrue(isNoisyDaemonLogLine(noisyRead, homeDir: "/Users/jqwang"))

        let noisyTaint = "[DENY] open(write-taint) by bash: /dev/tty"
        XCTAssertTrue(isNoisyDaemonLogLine(noisyTaint, homeDir: "/Users/jqwang"))

        let important = "[DENY] create(taint) by Python: /private/tmp/leak.txt"
        XCTAssertFalse(isNoisyDaemonLogLine(important, homeDir: "/Users/jqwang"))
    }
}
