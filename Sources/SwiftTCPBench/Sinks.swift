import Foundation
import SwiftTCP

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
