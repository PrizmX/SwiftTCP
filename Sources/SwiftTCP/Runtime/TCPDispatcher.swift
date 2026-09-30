import Foundation
import os

/// Stack-wide PCB count shared by all loops so `maxConnections` is a global cap.
final class ConnectionBudget: Sendable {
    let limit: Int
    private let used = OSAllocatedUnfairLock(initialState: 0)

    init(limit: Int) { self.limit = max(0, limit) }

    func tryAcquire() -> Bool {
        used.withLock { n in
            guard n < limit else { return false }
            n += 1
            return true
        }
    }

    func release() {
        used.withLock { n in n = max(0, n - 1) }
    }

    var inUse: Int { used.withLock { $0 } }
}

/// Hashes each 4-tuple onto a fixed EventLoop for the life of the connection.
/// `ingestBatch` / `send` are `nonisolated` so callers hop once — onto the loop —
/// instead of SwiftStack → Demuxer → Dispatcher → loop.
actor TCPDispatcher: TCPByteStream {
    nonisolated let loops: [TCPEventLoop]
    nonisolated let config: TCPStackConfig

    init(config: TCPStackConfig, sink: any PacketSink, streams: any TCPStreamHandler) {
        self.config = config
        let budget = ConnectionBudget(limit: config.maxConnections)
        self.loops = (0..<config.loopCount).map { id in
            TCPEventLoop(id: id, config: config, sink: sink, streams: streams, budget: budget)
        }
    }

    func connectionCount() async -> Int {
        var total = 0
        for loop in loops {
            total += await loop.connectionCount()
        }
        return total
    }

    nonisolated func ingestBatch(_ packets: [InboundTCPPacket]) async {
        let loopCount = loops.count
        if loopCount == 1 {
            await loops[0].ingestBatch(packets)
            return
        }
        var buckets = Array(repeating: [InboundTCPPacket](), count: loopCount)
        for packet in packets {
            buckets[packet.flow.eventLoopIndex(loopCount: loopCount)].append(packet)
        }
        await withTaskGroup(of: Void.self) { group in
            for (index, bucket) in buckets.enumerated() where !bucket.isEmpty {
                let loop = loops[index]
                group.addTask {
                    await loop.ingestBatch(bucket)
                }
            }
        }
    }

    /// `[Data]` convenience for the TCP-only facade: parse once, then delegate
    /// to the already-parsed ingest path.
    nonisolated func ingestBatch(_ packets: [Data], protocols: [NSNumber] = []) async {
        _ = protocols
        var parsed: [InboundTCPPacket] = []
        parsed.reserveCapacity(packets.count)
        for data in packets {
            guard let full = try? IPPacket.peekFull(data) else { continue }
            parsed.append(
                InboundTCPPacket(flow: full.segment.flow, segment: full.segment, data: data)
            )
        }
        await ingestBatch(parsed)
    }

    @discardableResult
    nonisolated func send(flow: FlowKey, data: Data) async -> Int {
        let index = flow.eventLoopIndex(loopCount: loops.count)
        return await loops[index].send(flow: flow, data: data)
    }

    nonisolated func applyPMTU(flow: FlowKey, mtu: Int) async {
        let index = flow.eventLoopIndex(loopCount: loops.count)
        await loops[index].applyPMTU(flow: flow, mtu: mtu)
    }

    nonisolated func sendBatch(_ items: [(FlowKey, Data)]) async {
        guard !items.isEmpty else { return }
        let loopCount = loops.count
        var buckets = Array(repeating: [(FlowKey, Data)](), count: loopCount)
        for item in items {
            buckets[item.0.eventLoopIndex(loopCount: loopCount)].append(item)
        }
        await withTaskGroup(of: Void.self) { group in
            for (index, bucket) in buckets.enumerated() where !bucket.isEmpty {
                let loop = loops[index]
                group.addTask {
                    await loop.sendBatch(bucket)
                }
            }
        }
    }

    nonisolated func close(flow: FlowKey) async {
        let index = flow.eventLoopIndex(loopCount: loops.count)
        await loops[index].close(flow: flow)
    }

    nonisolated func creditAppReceive(flow: FlowKey, bytes: Int) async {
        let index = flow.eventLoopIndex(loopCount: loops.count)
        await loops[index].creditAppReceive(flow: flow, bytes: bytes)
    }

    nonisolated func connect(flow: FlowKey) async {
        let index = flow.eventLoopIndex(loopCount: loops.count)
        await loops[index].connect(flow: flow)
    }

    func shutdown() async {
        await withTaskGroup(of: Void.self) { group in
            for loop in loops {
                group.addTask { await loop.shutdown() }
            }
        }
    }
}
