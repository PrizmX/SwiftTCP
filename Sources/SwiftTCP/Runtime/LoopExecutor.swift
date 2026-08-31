import Dispatch

/// Pinned serial executor (NIO EventLoop analogue). All TCB mutations for
/// flows hashed onto this loop run without locks.
final class LoopExecutor: SerialExecutor, @unchecked Sendable {
    private static let key = DispatchSpecificKey<ObjectIdentifier>()

    let queue: DispatchQueue

    init(label: String) {
        self.queue = DispatchQueue(label: label, qos: .userInitiated)
        self.queue.setSpecific(key: Self.key, value: ObjectIdentifier(self))
    }

    func enqueue(_ job: consuming ExecutorJob) {
        let unowned = UnownedJob(job)
        queue.async {
            unowned.runSynchronously(on: self.asUnownedSerialExecutor())
        }
    }

    func asUnownedSerialExecutor() -> UnownedSerialExecutor {
        UnownedSerialExecutor(ordinary: self)
    }

    func isIsolatingCurrentContext() -> Bool {
        DispatchQueue.getSpecific(key: Self.key) == ObjectIdentifier(self)
    }
}
