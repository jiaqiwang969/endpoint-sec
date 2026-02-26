import Foundation

class LogTailService {
    private var logFileHandle: FileHandle?
    private var lastOffset: UInt64 = 0
    private let queue = DispatchQueue(label: "dev.codex-es-guard.logtail")
    
    func startTailing(path: String, onNewLines: @escaping ([LogLine]) -> Void) {
        guard FileManager.default.fileExists(atPath: path) else { return }
        
        do {
            let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
            handle.seekToEndOfFile()
            self.lastOffset = handle.offsetInFile
            self.logFileHandle = handle
            
            handle.readabilityHandler = { fileHandle in
                let data = fileHandle.availableData
                guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
                
                let cleanText = text.replacingOccurrences(of: "\u{001B}\\[[0-9;]*[a-zA-Z]", with: "", options: .regularExpression)
                
                let newLines = cleanText.split(separator: "\n").map { line in
                    let lineStr = String(line)
                    let isErr = lineStr.contains("[DENY]") || lineStr.contains("ERROR") || lineStr.contains("panic")
                    return LogLine(text: lineStr, isError: isErr)
                }
                
                onNewLines(newLines)
            }
        } catch {
            print("LogTailService: Failed to setup tailing - \(error)")
        }
    }
    
    func stopTailing() {
        logFileHandle?.readabilityHandler = nil
        logFileHandle?.closeFile()
    }
}
