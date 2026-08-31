import Foundation

/// Hashes each 4-tuple onto a fixed EventLoop for the life of the connection.
/// `ingestBatch` / `send` are `nonisolated` so callers hop once — onto the loop —
/// instead of SwiftStack → Demuxer → Dispatcher → loop.
actor TCPDispatcher: TCPByteStream {
    nonisolated let loops: [TCPEventLoop]
    nonisolated let config: TCPStackConfig

    init(config: TCPStackConfig, sink: any PacketSink, streams: any TCPStreamHandler) {
        self.config = config
        self.loops = (0..<config.loopCount).map { id in
            TCPEventLoop(id: id, config: config, sink: sink, streams: streams)
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
