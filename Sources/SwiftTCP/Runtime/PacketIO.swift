import Foundation

public protocol PacketSink: Sendable {
    func write(bytes: Data, protocolFamily: UInt8)
    func writeBatch(_ items: [(Data, UInt8)])
}

extension PacketSink {
    public func writeBatch(_ items: [(Data, UInt8)]) {
        for item in items {
            write(bytes: item.0, protocolFamily: item.1)
        }
    }
}

public protocol TCPStreamHandler: Sendable {
    func onEstablished(flow: FlowKey)
    func onData(flow: FlowKey, data: Data)
    func onClosed(flow: FlowKey)
}

public struct NoopStreamHandler: TCPStreamHandler {
    public init() {}
    public func onEstablished(flow: FlowKey) {}
    public func onData(flow: FlowKey, data: Data) {}
    public func onClosed(flow: FlowKey) {}
}

/// Datagram side of a UDP 5-tuple. `SwiftStack` calls these; the handler replies via `UDPReplyPath`.
public protocol UDPDatagramHandler: Sendable {
    func onDatagram(flow: FlowKey, payload: Data)
    func onClosed(flow: FlowKey)
}

public struct NoopUDPHandler: UDPDatagramHandler {
    public init() {}
    public func onDatagram(flow: FlowKey, payload: Data) {}
    public func onClosed(flow: FlowKey) {}
}

/// Byte-stream side of a terminated TCP flow. Facades conform so integration
/// (NW forwarder / mux) is not wired to a single type.
public protocol TCPByteStream: Sendable {
    /// Enqueue bytes. Returns how many were accepted (waits for send-buffer space).
    @discardableResult
    func send(flow: FlowKey, data: Data) async -> Int
    func close(flow: FlowKey) async
    /// Hop onto the flow's event loop without creating a `Task` when the send buffer can take `data`.
    /// Otherwise falls back to `send` and invokes `completion` with the accepted byte count.
    func sendDetached(flow: FlowKey, data: Data, completion: @escaping @Sendable (Int) -> Void)
}

extension TCPByteStream {
    public func sendBatch(_ items: [(FlowKey, Data)]) async {
        for item in items {
            _ = await send(flow: item.0, data: item.1)
        }
    }

    public func sendDetached(flow: FlowKey, data: Data, completion: @escaping @Sendable (Int) -> Void) {
        Task {
            let accepted = await send(flow: flow, data: data)
            completion(accepted)
        }
    }
}

/// In-memory sink for unit and stress tests. Not used on the TUN path.
final class RecordingSink: PacketSink, @unchecked Sendable {
    private let lock = NSLock()
    private var packets: [Data] = []

    init() {}

    func write(bytes: Data, protocolFamily: UInt8) {
        _ = protocolFamily
        lock.lock()
        packets.append(bytes)
        lock.unlock()
    }

    func snapshot() -> [Data] {
        lock.lock()
        defer { lock.unlock() }
        return packets
    }

    func removeAll() {
        lock.lock()
        packets.removeAll(keepingCapacity: true)
        lock.unlock()
    }
}

/// Counts packets/bytes without retaining payloads. Optional short capture for handshake.
final class MetricsSink: PacketSink, @unchecked Sendable {
    private let lock = NSLock()
    private var packets: UInt64 = 0
    private var bytes: UInt64 = 0
    private var captured: [Data] = []
    private var captureLimit = 0

    init() {}

    func write(bytes: Data, protocolFamily: UInt8) {
        _ = protocolFamily
        lock.lock()
        packets &+= 1
        self.bytes &+= UInt64(bytes.count)
        if captured.count < captureLimit {
            captured.append(bytes)
        }
        lock.unlock()
    }

    func writeBatch(_ items: [(Data, UInt8)]) {
        guard !items.isEmpty else { return }
        lock.lock()
        for item in items {
            packets &+= 1
            bytes &+= UInt64(item.0.count)
            if captured.count < captureLimit {
                captured.append(item.0)
            }
        }
        lock.unlock()
    }

    func snapshot() -> (packets: UInt64, bytes: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        return (packets, bytes)
    }

    func beginCapture(_ limit: Int) {
        lock.lock()
        captureLimit = limit
        captured.removeAll(keepingCapacity: true)
        lock.unlock()
    }

    func endCapture() -> [Data] {
        lock.lock()
        captureLimit = 0
        let out = captured
        captured.removeAll(keepingCapacity: true)
        lock.unlock()
        return out
    }

    func reset() {
        lock.lock()
        packets = 0
        bytes = 0
        captured.removeAll(keepingCapacity: true)
        captureLimit = 0
        lock.unlock()
    }
}

/// Counts delivered bytes / lifecycle events and drops the payload.
final class DiscardStreamHandler: TCPStreamHandler, @unchecked Sendable {
    private let lock = NSLock()
    private var established: UInt64 = 0
    private var closed: UInt64 = 0
    private var bytes: UInt64 = 0

    init() {}

    func onEstablished(flow: FlowKey) {
        _ = flow
        lock.lock()
        established &+= 1
        lock.unlock()
    }

    func onData(flow: FlowKey, data: Data) {
        _ = flow
        lock.lock()
        bytes &+= UInt64(data.count)
        lock.unlock()
    }

    func onClosed(flow: FlowKey) {
        _ = flow
        lock.lock()
        closed &+= 1
        lock.unlock()
    }

    func snapshot() -> (established: UInt64, closed: UInt64, bytes: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        return (established, closed, bytes)
    }

    func reset() {
        lock.lock()
        established = 0
        closed = 0
        bytes = 0
        lock.unlock()
    }
}
