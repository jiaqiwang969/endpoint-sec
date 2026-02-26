import Foundation

class FileMonitorService {
    private let queue = DispatchQueue(label: "dev.codex-es-guard.filewatcher", attributes: .concurrent)
    private var sources: [String: DispatchSourceFileSystemObject] = [:]
    
    // Watch a specific file path. When it changes (written to), fire the callback.
    func watch(path: String, onChange: @escaping () -> Void) {
        let fd = open(path, O_EVTONLY)
        guard fd != -1 else {
            print("FileMonitor: Failed to open \(path)")
            return
        }
        
        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .delete, .rename, .extend, .attrib, .link, .revoke],
            queue: queue
        )
        
        source.setEventHandler { [weak self] in
            let events = source.data
            // If the file was replaced/deleted, the descriptor becomes invalid.
            // We need to re-establish the watch.
            if events.contains(.delete) || events.contains(.rename) {
                source.cancel()
                DispatchQueue.global().asyncAfter(deadline: .now() + 0.5) {
                    self?.watch(path: path, onChange: onChange)
                }
            }
            onChange()
        }
        
        source.setCancelHandler {
            close(fd)
        }
        
        sources[path] = source
        source.resume()
    }
    
    func stopWatching(path: String) {
        sources[path]?.cancel()
        sources.removeValue(forKey: path)
    }
    
    func stopAll() {
        for source in sources.values {
            source.cancel()
        }
        sources.removeAll()
    }
}
