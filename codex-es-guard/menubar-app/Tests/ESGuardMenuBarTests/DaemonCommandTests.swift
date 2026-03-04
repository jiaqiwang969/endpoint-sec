import Foundation
import XCTest
@testable import ESGuardMenuBar

final class DaemonCommandTests: XCTestCase {
    private let target = "system/dev.codex-es-guard"
    private let plist = "/Library/LaunchDaemons/dev.codex-es-guard.plist"

    private func assertBashSyntaxIsValid(_ command: String, file: StaticString = #filePath, line: UInt = #line) {
        let task = Process()
        task.launchPath = "/bin/bash"
        task.arguments = ["-n", "-c", command]
        let stderrPipe = Pipe()
        task.standardError = stderrPipe
        do {
            try task.run()
            task.waitUntilExit()
        } catch {
            XCTFail("bash failed to run: \(error.localizedDescription)", file: file, line: line)
            return
        }

        if task.terminationStatus != 0 {
            let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
            let stderr = String(data: stderrData, encoding: .utf8) ?? ""
            XCTFail("invalid bash syntax: \(stderr)", file: file, line: line)
        }
    }

    func testStopDaemonCommandHasValidShellSyntax() {
        let command = buildStopDaemonCommand(serviceTarget: target, plistPath: plist)
        XCTAssertFalse(command.contains("then;"))
        assertBashSyntaxIsValid(command)
    }

    func testStartDaemonCommandHasValidShellSyntax() {
        let command = buildStartDaemonCommand(serviceTarget: target, plistPath: plist)
        XCTAssertFalse(command.contains("then;"))
        assertBashSyntaxIsValid(command)
    }

    func testRestartDaemonCommandHasValidShellSyntax() {
        let command = buildRestartDaemonCommand(serviceTarget: target, plistPath: plist)
        XCTAssertFalse(command.contains("then;"))
        assertBashSyntaxIsValid(command)
    }

    func testDaemonCommandsDoNotSilenceLaunchctlErrors() {
        let start = buildStartDaemonCommand(serviceTarget: target, plistPath: plist)
        let stop = buildStopDaemonCommand(serviceTarget: target, plistPath: plist)
        let restart = buildRestartDaemonCommand(serviceTarget: target, plistPath: plist)

        XCTAssertFalse(start.contains("bootstrap system '\(plist)' >/dev/null 2>&1"))
        XCTAssertFalse(start.contains("enable '\(target)' >/dev/null 2>&1"))
        XCTAssertFalse(start.contains("kickstart -k '\(target)' >/dev/null 2>&1"))

        XCTAssertFalse(stop.contains("disable '\(target)' >/dev/null 2>&1"))
        XCTAssertFalse(stop.contains("bootout '\(target)' >/dev/null 2>&1"))
        XCTAssertFalse(stop.contains("bootout system '\(plist)' >/dev/null 2>&1"))

        XCTAssertFalse(restart.contains("bootstrap system '\(plist)' >/dev/null 2>&1"))
        XCTAssertFalse(restart.contains("enable '\(target)' >/dev/null 2>&1"))
        XCTAssertFalse(restart.contains("kickstart -k '\(target)' >/dev/null 2>&1"))
    }

    func testPrivilegeRetryDecisionCoversStatusAndDetail() {
        XCTAssertTrue(shouldRetryPrivileged(status: 1, detail: ""))
        XCTAssertTrue(shouldRetryPrivileged(status: 0, detail: "Operation not permitted"))
        XCTAssertFalse(shouldRetryPrivileged(status: 0, detail: ""))
    }
}
