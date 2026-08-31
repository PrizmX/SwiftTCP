import Foundation
import SwiftTCP

func runTCPDuplex(config: BenchConfig) async throws -> BenchResult {
    let sink = MetricsSink()
    let streams = DiscardStreamHandler()
    let stack = makeStack(config: config, sink: sink, streams: streams)

    var peers: [FlowPeer] = []
    peers.reserveCapacity(config.connections)
    for i in 0..<config.connections {
        peers.append(try await handshakePeer(stack: stack, sink: sink, srcPort: 21_000 + UInt16(i)))
    }

    let txChunk = Data(repeating: 0x62, count: config.payload)
    let rxChunk = Data(repeating: 0x61, count: config.payload)
    var seqs = peers.map(\.clientSeq)
    let acks = peers.map { $0.serverISS &+ 1 }

    func round() async {
        sink.beginCapture(max(4_096, config.batch))
        await stack.sendBatch(sendItems(peers: peers, chunk: txChunk, batch: config.batch))
        let tx = sink.endCapture()
        var batch = ackPackets(for: tx, peers: peers)
        for i in 0..<config.batch {
            let idx = i % peers.count
            batch.append(
                tcpPacket(
                    flow: peers[idx].flow,
                    seq: seqs[idx],
                    ack: acks[idx],
                    flags: [.ack, .psh],
                    payload: rxChunk
                )
            )
            seqs[idx] &+= UInt32(config.payload)
        }
        if !batch.isEmpty {
            await stack.ingestBatch(batch)
        }
    }

    await sampleUntil(config.warmup) { await round() }
    sink.reset()
    streams.reset()

    let measured = await timed {
        await sampleUntil(config.duration) { await round() }
    }

    let out = sink.snapshot()
    let app = streams.snapshot()
    let delivered = app.bytes
    let rxSegs = config.payload > 0 ? delivered / UInt64(config.payload) : 0
    let l3In = rxSegs * UInt64(40 + config.payload)
    return BenchResult.make(
        scenario: "tcp-duplex",
        config: config,
        wall: measured.1,
        packetsIn: rxSegs,
        bytesIn: l3In,
        packetsOut: out.packets,
        bytesOut: out.bytes,
        deliveredBytes: delivered,
        established: UInt64(config.connections),
        cpuUser: measured.2,
        cpuSys: measured.3,
        rssBefore: measured.4,
        rssAfter: measured.5,
        footBefore: measured.6,
        footAfter: measured.7,
        notes: "full duplex: sendBatch(batch) + client ACK + inbound PSH; appGbps=RX, packetsOut=TX"
    )
}

func runTCPActive(config: BenchConfig) async throws -> BenchResult {
    var cfg = config
    cfg.connections = config.activeConnections
    return try await runTCPRx(
        config: cfg,
        options: RxOptions(
            payload: config.payload,
            name: "tcp-active",
            sampleIngest: true,
            connectionOverride: config.activeConnections,
            notes: "\(config.activeConnections) live flows transferring; RSS Δ is under traffic not idle hold"
        )
    )
}

func runTCPRps(config: BenchConfig) async throws -> BenchResult {
    let sink = MetricsSink()
    let streams = DiscardStreamHandler()
    let stack = makeStack(config: config, sink: sink, streams: streams, shortWait: true)

    actor PortGen {
        var next: UInt32 = 30_000
        func take() -> UInt16 {
            let p = UInt16(truncatingIfNeeded: next)
            next &+= 1
            if next > 60_000 { next = 30_000 }
            return p
        }
    }
    let ports = PortGen()
    let total = config.rpsBytes
    let mss = max(1, min(config.payload, 1460))
    var handshakeSamples = SampleBuf()

    func oneConnection() async throws -> Double {
        let port = await ports.take()
        let (peer, hsUs) = try await handshake(stack: stack, sink: sink, srcPort: port)
        var seq = peer.clientSeq
        let ack = peer.serverISS &+ 1
        var remaining = total
        var batch: [Data] = []
        while remaining > 0 {
            let n = min(mss, remaining)
            batch.append(
                tcpPacket(
                    flow: peer.flow,
                    seq: seq,
                    ack: ack,
                    flags: [.ack, .psh],
                    payload: Data(repeating: 0x63, count: n)
                )
            )
            seq &+= UInt32(n)
            remaining -= n
        }
        batch.append(tcpPacket(flow: peer.flow, seq: seq, ack: ack, flags: [.ack, .fin]))
        sink.beginCapture(16)
        await stack.ingestBatch(batch)
        await stack.close(flow: peer.flow)
        let tx = sink.endCapture()
        var replies: [Data] = []
        for data in tx {
            guard let seg = try? parseSegment(data) else { continue }
            if seg.hasFIN {
                replies.append(
                    tcpPacket(
                        flow: peer.flow,
                        seq: seq &+ 1,
                        ack: seg.seq &+ 1,
                        flags: .ack
                    )
                )
            }
        }
        if !replies.isEmpty {
            await stack.ingestBatch(replies)
        }
        return hsUs
    }

    try await sampleUntil(config.warmup) {
        _ = try await oneConnection()
    }
    sink.reset()
    streams.reset()
    handshakeSamples = SampleBuf()

    var completed: UInt64 = 0
    let measured = try await timed {
        try await sampleUntil(config.duration) {
            handshakeSamples.add(try await oneConnection())
            completed &+= 1
        }
    }

    let out = sink.snapshot()
    let app = streams.snapshot()
    let hs = handshakeSamples.pair()
    let seconds = max(durationSeconds(measured.1), 1e-9)
    return BenchResult.make(
        scenario: "tcp-rps",
        config: config,
        wall: measured.1,
        packetsIn: completed * UInt64((total + mss - 1) / mss + 3),
        bytesIn: completed * UInt64(total + 3 * 52),
        packetsOut: out.packets,
        bytesOut: out.bytes,
        deliveredBytes: app.bytes,
        established: app.established,
        cpuUser: measured.2,
        cpuSys: measured.3,
        rssBefore: measured.4,
        rssAfter: measured.5,
        footBefore: measured.6,
        footAfter: measured.7,
        notes: "handshake + \(total)B + FIN; rps = completed short connections / s",
        extra: ExtraMetrics(
            rps: Double(completed) / seconds,
            handshakeP50Us: hs.p50,
            handshakeP99Us: hs.p99
        )
    )
}

func runTCPLatency(config: BenchConfig) async throws -> BenchResult {
    let sink = MetricsSink()
    let streams = DiscardStreamHandler()
    let stack = makeStack(config: config, sink: sink, streams: streams, shortWait: true)

    var handshakeSamples = SampleBuf()
    var firstByteSamples = SampleBuf()
    var ingestSamples = SampleBuf()
    var port: UInt32 = 40_000

    func nextPort() -> UInt16 {
        let p = UInt16(truncatingIfNeeded: port)
        port &+= 1
        if port > 60_000 { port = 40_000 }
        return p
    }

    // Handshake RTT samples (SYN → ACK complete), then RST to free the PCB.
    for _ in 0..<256 {
        let (peer, us) = try await handshake(stack: stack, sink: sink, srcPort: nextPort())
        handshakeSamples.add(us)
        await stack.ingest(rst(peer: peer))
    }

    // First-byte: established → one PSH, wait until onData fires.
    for _ in 0..<64 {
        let peer = try await handshakePeer(stack: stack, sink: sink, srcPort: nextPort())
        let before = streams.snapshot().bytes
        let chunk = Data(repeating: 0x64, count: 64)
        let t0 = ContinuousClock().now
        await stack.ingest(
            tcpPacket(
                flow: peer.flow,
                seq: peer.clientSeq,
                ack: peer.serverISS &+ 1,
                flags: [.ack, .psh],
                payload: chunk
            )
        )
        let deadline = t0.advanced(by: .milliseconds(50))
        while ContinuousClock().now < deadline {
            if streams.snapshot().bytes > before { break }
            await Task.yield()
        }
        firstByteSamples.add(durationMicroseconds(t0.duration(to: ContinuousClock().now)))
        await stack.ingest(rst(peer: peer))
    }

    // ingestBatch hop tax on a few live flows.
    var peers: [FlowPeer] = []
    for i in 0..<config.connections {
        peers.append(try await handshakePeer(stack: stack, sink: sink, srcPort: 11_000 + UInt16(i)))
    }
    let chunk = Data(repeating: 0x61, count: config.payload)
    var seqs = peers.map(\.clientSeq)
    let acks = peers.map { $0.serverISS &+ 1 }
    sink.reset()
    streams.reset()

    let measured = await timed {
        await sampleUntil(config.duration) {
            var batch: [Data] = []
            batch.reserveCapacity(config.batch)
            for i in 0..<config.batch {
                let idx = i % peers.count
                batch.append(
                    tcpPacket(
                        flow: peers[idx].flow,
                        seq: seqs[idx],
                        ack: acks[idx],
                        flags: [.ack, .psh],
                        payload: chunk
                    )
                )
                seqs[idx] &+= UInt32(config.payload)
            }
            let t0 = ContinuousClock().now
            await stack.ingestBatch(batch)
            ingestSamples.add(durationMicroseconds(t0.duration(to: ContinuousClock().now)))
        }
    }

    let out = sink.snapshot()
    let app = streams.snapshot()
    let hs = handshakeSamples.pair()
    let fb = firstByteSamples.pair()
    let ing = ingestSamples.pair()
    let segments = config.payload > 0 ? app.bytes / UInt64(config.payload) : 0
    return BenchResult.make(
        scenario: "tcp-latency",
        config: config,
        wall: measured.1,
        packetsIn: segments,
        bytesIn: segments * UInt64(40 + config.payload),
        packetsOut: out.packets,
        bytesOut: out.bytes,
        deliveredBytes: app.bytes,
        established: UInt64(config.connections),
        cpuUser: measured.2,
        cpuSys: measured.3,
        rssBefore: measured.4,
        rssAfter: measured.5,
        footBefore: measured.6,
        footAfter: measured.7,
        notes: "handshake / first-byte / ingestBatch p50+p99 (µs); pps is the timed RX window",
        extra: ExtraMetrics(
            ingestP50Us: ing.p50,
            ingestP99Us: ing.p99,
            handshakeP50Us: hs.p50,
            handshakeP99Us: hs.p99,
            firstByteP50Us: fb.p50,
            firstByteP99Us: fb.p99
        )
    )
}
