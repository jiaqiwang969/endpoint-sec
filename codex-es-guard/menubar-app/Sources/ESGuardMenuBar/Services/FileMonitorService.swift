import Foundation

class FileMonitorService {
    private let queue = DispatchQueue(label: "dev.codex-es-guard.filewatcher")
    private var sources: [String: DispatchSourceFileSystemObject] = [:]
    private var retryItems: [String: DispatchWorkItem] = [:]
    
    // Watch a specific file path. When it changes (written to), fire the callback.
    func watch(path: String, onChange: @escaping () -> Void) {
        queue.async { [weak self] in
            guard let self = self else { return }
            self.cancelWatcher(for: path)
            self.attachWatcher(path: path, onChange: onChange)
        }
    }
    
    func stopWatching(path: String) {
        queue.async { [weak self] in
            self?.cancelWatcher(for: path)
        }
    }
    
    func stopAll() {
        queue.async { [weak self] in
            guard let self = self else { return }
            for source in self.sources.values {
                source.cancel()
            }
            self.sources.removeAll()
            for item in self.retryItems.values {
                item.cancel()
            }
            self.retryItems.removeAll()
        }
    }

    private func cancelWatcher(for path: String) {
        if let source = sources.removeValue(forKey: path) {
            source.cancel()
        }
        if let item = retryItems.removeValue(forKey: path) {
            item.cancel()
        }
    }

    private func scheduleRetry(path: String, onChange: @escaping () -> Void, after delay: TimeInterval) {
        retryItems[path]?.cancel()
        let item = DispatchWorkItem { [weak self] in
            self?.attachWatcher(path: path, onChange: onChange)
        }
        retryItems[path] = item
        queue.asyncAfter(deadline: .now() + delay, execute: item)
    }

    private func attachWatcher(path: String, onChange: @escaping () -> Void) {
        let fd = open(path, O_EVTONLY)
        guard fd != -1 else {
            // The target file may not exist yet (for example first run). Retry in background.
            scheduleRetry(path: path, onChange: onChange, after: 1.0)
            return
        }

        retryItems[path]?.cancel()
        retryItems.removeValue(forKey: path)

        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .delete, .rename, .extend, .attrib, .link, .revoke],
            queue: queue
        )

        source.setEventHandler { [weak self] in
            guard let self = self else { return }
            let events = source.data
            if events.contains(.delete) || events.contains(.rename) || events.contains(.revoke) {
                self.cancelWatcher(for: path)
                self.scheduleRetry(path: path, onChange: onChange, after: 0.3)
            }
            onChange()
        }

        source.setCancelHandler {
            close(fd)
        }

        sources[path] = source
        source.resume()
    }
}
