import Foundation
import SwiftTCP

let benchClient = IPAddress.v4(octets: (10, 0, 0, 1))
let benchServer = IPAddress.v4(octets: (10, 0, 0, 2))
let benchClient6 = IPAddress(v6High: 0x2001_0db8_0000_0000, v6Low: 1)
let benchServer6 = IPAddress(v6High: 0x2001_0db8_0000_0000, v6Low: 2)

struct FlowPeer: Sendable {
    var flow: FlowKey
    var clientSeq: UInt32
    var serverISS: UInt32
}

let synOptions = TCPOptions(mss: 1460, windowScale: 7, sackPermitted: true, tfoCookie: nil)

func flowKey(srcPort: UInt16, dstPort: UInt16 = 80, version: IPVersion = .v4) -> FlowKey {
    switch version {
    case .v4:
        FlowKey(src: benchClient, srcPort: srcPort, dst: benchServer, dstPort: dstPort)
    case .v6:
        FlowKey(src: benchClient6, srcPort: srcPort, dst: benchServer6, dstPort: dstPort)
    }
}

func tcpPacket(
    flow: FlowKey,
    seq: UInt32,
    ack: UInt32,
    flags: TCPFlags,
    payload: Data = Data(),
    options: TCPOptions = .empty,
    window: UInt16 = 65_535
) -> Data {
    PacketBuilder.tcp(
        flow: flow,
        seq: seq,
        ack: ack,
        flags: flags,
        window: window,
        options: options,
        payload: payload
    ).asSharedData()
}

func parseSegment(_ data: Data) throws -> TCPSegment {
    let packet = try IPPacket.parse(PacketBuffer(wrapping: data))
    return packet.segment
}

func makeStack(
    config: BenchConfig,
    sink: any PacketSink,
    streams: any TCPStreamHandler,
    shortWait: Bool = false
) -> SwiftStack {
    let wait: Duration = shortWait ? .milliseconds(20) : .seconds(2)
    let tcp = TCPStackConfig(
        loopCount: config.loops,
        algorithm: config.algorithm,
        receiveWindow: config.window,
        tfo: false,
        timers: TCPTimerConfig(
            timeWait: wait,
            delayedAck: .zero,
            handshakeTimeout: .seconds(10),
            closeWaitTimeout: shortWait ? .milliseconds(200) : .seconds(30)
        ),
        maxConnections: max(config.holdConnections, config.activeConnections, config.connections, 16_384)
    )
    return SwiftStack(
        config: SwiftStackConfig(tcp: tcp, mtu: 1500),
        sink: sink,
        streams: streams
    )
}

func handshake(
    stack: SwiftStack,
    sink: MetricsSink,
    srcPort: UInt16,
    iss: UInt32 = 1_000,
    version: IPVersion = .v4
) async throws -> (FlowPeer, Double) {
    let flow = flowKey(srcPort: srcPort, version: version)
    let t0 = ContinuousClock().now
    sink.beginCapture(8)
    await stack.ingest(tcpPacket(flow: flow, seq: iss, ack: 0, flags: .syn, options: synOptions))
    let tx = sink.endCapture()
    guard let synAckData = tx.first else {
        throw BenchError.handshake("no SYN-ACK for port \(srcPort)")
    }
    let synAck = try parseSegment(synAckData)
    guard synAck.hasSYN, synAck.hasACK else {
        throw BenchError.handshake("first TX is not SYN-ACK for port \(srcPort)")
    }
    let clientSeq = iss &+ 1
    let ack = tcpPacket(flow: flow, seq: clientSeq, ack: synAck.seq &+ 1, flags: .ack)
    await stack.ingest(ack)
    let us = durationMicroseconds(t0.duration(to: ContinuousClock().now))
    return (FlowPeer(flow: flow, clientSeq: clientSeq, serverISS: synAck.seq), us)
}

func handshakePeer(
    stack: SwiftStack,
    sink: MetricsSink,
    srcPort: UInt16,
    iss: UInt32 = 1_000,
    version: IPVersion = .v4
) async throws -> FlowPeer {
    try await handshake(stack: stack, sink: sink, srcPort: srcPort, iss: iss, version: version).0
}

func sendItems(peers: [FlowPeer], chunk: Data, batch: Int) -> [(FlowKey, Data)] {
    var items: [(FlowKey, Data)] = []
    items.reserveCapacity(batch)
    for i in 0..<batch {
        items.append((peers[i % peers.count].flow, chunk))
    }
    return items
}

func ackPackets(for tx: [Data], peers: [FlowPeer]) -> [Data] {
    var byReversed: [FlowKey: FlowPeer] = [:]
    byReversed.reserveCapacity(peers.count)
    for peer in peers {
        byReversed[peer.flow.reversed] = peer
    }
    var out: [Data] = []
    out.reserveCapacity(tx.count)
    for data in tx {
        guard let seg = try? parseSegment(data), seg.payloadLength > 0 else { continue }
        guard let peer = byReversed[seg.flow] else { continue }
        out.append(
            tcpPacket(
                flow: peer.flow,
                seq: peer.clientSeq,
                ack: seg.seq &+ UInt32(seg.payloadLength),
                flags: .ack
            )
        )
    }
    return out
}

func rst(peer: FlowPeer) -> Data {
    tcpPacket(
        flow: peer.flow,
        seq: peer.clientSeq,
        ack: peer.serverISS &+ 1,
        flags: .rst.union(.ack)
    )
}

/// SplitMix64 — deterministic loss/reorder, same sequence on every stack.
struct SplitMix64: RandomNumberGenerator {
    var state: UInt64
    mutating func next() -> UInt64 {
        state &+= 0x9e37_79b9_7f4a_7c15
        var z = state
        z = (z ^ (z >> 30)) &* 0xbf58_476d_1ce4_e5b9
        z = (z ^ (z >> 27)) &* 0x94d0_49bb_1331_11eb
        return z ^ (z >> 31)
    }
}

enum BenchError: Error, CustomStringConvertible {
    case handshake(String)
    case unknownScenario(String)

    var description: String {
        switch self {
        case .handshake(let s), .unknownScenario(let s): s
        }
    }
}

func timed<T>(
    _ body: () async throws -> T
) async rethrows -> (T, Duration, Double, Double, UInt64, UInt64, UInt64, UInt64) {
    let rss0 = ProcessMetrics.rssBytes()
    let foot0 = ProcessMetrics.footprintBytes()
    let cpu0 = ProcessMetrics.cpuSeconds()
    let t0 = ContinuousClock().now
    let value = try await body()
    let wall = t0.duration(to: ContinuousClock().now)
    let cpu1 = ProcessMetrics.cpuSeconds()
    let rss1 = ProcessMetrics.rssBytes()
    let foot1 = ProcessMetrics.footprintBytes()
    return (value, wall, cpu1.user - cpu0.user, cpu1.system - cpu0.system, rss0, rss1, foot0, foot1)
}

func sampleUntil(_ duration: Duration, _ body: () async throws -> Void) async rethrows {
    let deadline = ContinuousClock().now.advanced(by: duration)
    while ContinuousClock().now < deadline {
        try await body()
    }
}

// MARK: - Scenarios

struct RxOptions {
    var payload: Int
    var name: String
    var version: IPVersion = .v4
    var lossPct: Double = 0
    var reorder: Bool = false
    var sampleIngest: Bool = false
    var connectionOverride: Int? = nil
    var notes: String? = nil
}

func runTCPRx(config: BenchConfig, options: RxOptions) async throws -> BenchResult {
    let sink = MetricsSink()
    let streams = DiscardStreamHandler()
    let stack = makeStack(config: config, sink: sink, streams: streams)
    var cfg = config
    let payload: Int
    if options.version == .v6 {
        // IPv6 + TCP = 60 B; keep total ≤ MTU 1500 or demuxer emits Packet Too Big.
        payload = min(options.payload, 1440)
    } else {
        payload = options.payload
    }
    cfg.payload = payload
    let conns = options.connectionOverride ?? cfg.connections
    cfg.connections = conns

    var peers: [FlowPeer] = []
    peers.reserveCapacity(conns)
    for i in 0..<conns {
        peers.append(
            try await handshakePeer(
                stack: stack,
                sink: sink,
                srcPort: 10_000 + UInt16(i),
                version: options.version
            )
        )
    }

    let chunk = Data(repeating: 0x61, count: payload)
    var seqs = peers.map(\.clientSeq)
    let acks = peers.map { $0.serverISS &+ 1 }
    var rng = SplitMix64(state: 0xC0FF_EE42)
    var delayed: [Data] = []
    var ingestSamples = SampleBuf()
    var batchIndex = 0
    let ipHdr = options.version == .v6 ? 60 : 40

    func inject(batches: Int, record: Bool) async {
        for _ in 0..<batches {
            var batch: [Data] = []
            batch.reserveCapacity(cfg.batch + delayed.count)
            if !delayed.isEmpty {
                batch.append(contentsOf: delayed)
                delayed.removeAll(keepingCapacity: true)
            }
            for i in 0..<cfg.batch {
                let idx = i % peers.count
                let pkt = tcpPacket(
                    flow: peers[idx].flow,
                    seq: seqs[idx],
                    ack: acks[idx],
                    flags: [.ack, .psh],
                    payload: chunk
                )
                seqs[idx] &+= UInt32(payload)
                if options.lossPct > 0 {
                    let roll = Double(rng.next() % 10_000) / 100.0
                    if roll < options.lossPct {
                        delayed.append(pkt)
                        continue
                    }
                }
                batch.append(pkt)
            }
            batchIndex &+= 1
            if options.reorder, batch.count >= 2, batchIndex % 5 == 0 {
                batch.reverse()
            }
            if record, options.sampleIngest {
                let t0 = ContinuousClock().now
                await stack.ingestBatch(batch)
                ingestSamples.add(durationMicroseconds(t0.duration(to: ContinuousClock().now)))
            } else {
                await stack.ingestBatch(batch)
            }
        }
    }

    await sampleUntil(cfg.warmup) { await inject(batches: 1, record: false) }
    sink.reset()
    streams.reset()

    let measured = await timed {
        await sampleUntil(cfg.duration) {
            await inject(batches: 1, record: true)
        }
    }

    let out = sink.snapshot()
    let app = streams.snapshot()
    let delivered = app.bytes
    let segments = payload > 0 ? delivered / UInt64(payload) : 0
    let l3 = segments * UInt64(ipHdr + payload)
    let ingest = ingestSamples.pair()
    let defaultNotes: String
    if options.version == .v6 {
        defaultNotes = "IPv6 RX bulk; payload capped at 1440 so 60B header fits MTU 1500"
    } else if options.lossPct > 0 {
        defaultNotes = String(
            format: "RX with %.1f%% drop (retransmit next batch) + reverse every 5th batch",
            options.lossPct
        )
    } else if options.sampleIngest {
        defaultNotes = "RX bulk with ingestBatch latency samples"
    } else {
        defaultNotes = "RX bulk; L3 includes 40B IPv4+TCP header per segment"
    }

    return BenchResult.make(
        scenario: options.name,
        config: cfg,
        wall: measured.1,
        packetsIn: segments,
        bytesIn: l3,
        packetsOut: out.packets,
        bytesOut: out.bytes,
        deliveredBytes: delivered,
        established: UInt64(conns),
        cpuUser: measured.2,
        cpuSys: measured.3,
        rssBefore: measured.4,
        rssAfter: measured.5,
        footBefore: measured.6,
        footAfter: measured.7,
        notes: options.notes ?? defaultNotes,
        extra: ExtraMetrics(
            ingestP50Us: ingest.p50,
            ingestP99Us: ingest.p99,
            lossPct: options.lossPct
        )
    )
}

func runTCPTx(config: BenchConfig) async throws -> BenchResult {
    let sink = MetricsSink()
    let streams = DiscardStreamHandler()
    let stack = makeStack(config: config, sink: sink, streams: streams)

    var peers: [FlowPeer] = []
    for i in 0..<config.connections {
        peers.append(try await handshakePeer(stack: stack, sink: sink, srcPort: 20_000 + UInt16(i)))
    }

    let chunk = Data(repeating: 0x62, count: config.payload)

    func round() async {
        sink.beginCapture(max(4_096, config.batch))
        await stack.sendBatch(sendItems(peers: peers, chunk: chunk, batch: config.batch))
        let tx = sink.endCapture()
        let generated = ackPackets(for: tx, peers: peers)
        if !generated.isEmpty {
            await stack.ingestBatch(generated)
        }
    }

    await sampleUntil(config.warmup) { await round() }
    sink.reset()
    streams.reset()

    let measured = await timed {
        await sampleUntil(config.duration) {
            await round()
        }
    }

    let out = sink.snapshot()
    return BenchResult.make(
        scenario: "tcp-tx",
        config: config,
        wall: measured.1,
        packetsIn: out.packets,
        bytesIn: out.bytes,
        packetsOut: out.packets,
        bytesOut: out.bytes,
        deliveredBytes: out.bytes > 40 ? out.bytes : 0,
        established: UInt64(config.connections),
        cpuUser: measured.2,
        cpuSys: measured.3,
        rssBefore: measured.4,
        rssAfter: measured.5,
        footBefore: measured.6,
        footAfter: measured.7,
        notes: "TX: sendBatch(batch segments) + client ACK; pps/Gbps are payload packets"
    )
}

func runTCPCps(config: BenchConfig) async throws -> BenchResult {
    let sink = MetricsSink()
    let streams = DiscardStreamHandler()
    let stack = makeStack(config: config, sink: sink, streams: streams)

    actor PortGen {
        var next: UInt32 = 30_000
        func take(_ n: Int) -> [UInt16] {
            var ports: [UInt16] = []
            ports.reserveCapacity(n)
            for _ in 0..<n {
                ports.append(UInt16(truncatingIfNeeded: next))
                next &+= 1
                if next > 60_000 { next = 30_000 }
            }
            return ports
        }
    }
    let ports = PortGen()

    func churn(_ n: Int) async throws {
        let batch = await ports.take(n)
        for port in batch {
            let peer = try await handshakePeer(stack: stack, sink: sink, srcPort: port)
            await stack.ingest(rst(peer: peer))
        }
    }

    try await sampleUntil(config.warmup) { try await churn(config.batch) }
    sink.reset()
    streams.reset()

    var established: UInt64 = 0
    let measured = try await timed {
        try await sampleUntil(config.duration) {
            try await churn(config.batch)
            established &+= UInt64(config.batch)
        }
    }

    let out = sink.snapshot()
    let app = streams.snapshot()
    return BenchResult.make(
        scenario: "tcp-cps",
        config: config,
        wall: measured.1,
        packetsIn: established * 3,
        bytesIn: established * 3 * 52,
        packetsOut: out.packets,
        bytesOut: out.bytes,
        deliveredBytes: 0,
        established: app.established,
        cpuUser: measured.2,
        cpuSys: measured.3,
        rssBefore: measured.4,
        rssAfter: measured.5,
        footBefore: measured.6,
        footAfter: measured.7,
        notes: "handshake + RST churn; pps = 3 segments/conn (SYN, ACK, RST)"
    )
}

func runTCPHold(config: BenchConfig) async throws -> BenchResult {
    let sink = MetricsSink()
    let streams = DiscardStreamHandler()
    var cfg = config
    cfg.connections = config.holdConnections
    let stack = makeStack(config: cfg, sink: sink, streams: streams)

    let rssBefore = ProcessMetrics.rssBytes()
    let footBefore = ProcessMetrics.footprintBytes()
    let cpu0 = ProcessMetrics.cpuSeconds()
    let t0 = ContinuousClock().now

    for i in 0..<cfg.holdConnections {
        _ = try await handshakePeer(stack: stack, sink: sink, srcPort: 10_000 &+ UInt16(truncatingIfNeeded: i))
    }

    // Let actor hops settle; memory should now be PCB + two ring buffers / conn.
    try await Task.sleep(for: .milliseconds(200))
    let wall = t0.duration(to: ContinuousClock().now)
    let cpu1 = ProcessMetrics.cpuSeconds()
    let live = await stack.connectionCount()

    return BenchResult.make(
        scenario: "tcp-hold",
        config: cfg,
        wall: wall,
        packetsIn: UInt64(cfg.holdConnections * 2),
        bytesIn: UInt64(cfg.holdConnections * 2 * 52),
        packetsOut: (sink.snapshot()).packets,
        bytesOut: (sink.snapshot()).bytes,
        deliveredBytes: 0,
        established: UInt64(live),
        cpuUser: cpu1.user - cpu0.user,
        cpuSys: cpu1.system - cpu0.system,
        rssBefore: rssBefore,
        rssAfter: ProcessMetrics.rssBytes(),
        footBefore: footBefore,
        footAfter: ProcessMetrics.footprintBytes(),
        notes: "idle ESTABLISHED PCBs; B/conn ≈ RSS Δ / established"
    )
}

func runICMPEcho(config: BenchConfig) async throws -> BenchResult {
    let sink = MetricsSink()
    let streams = DiscardStreamHandler()
    let stack = makeStack(config: config, sink: sink, streams: streams)
    let payload = Data(repeating: 0x70, count: max(config.payload, 8))
    let request = ICMPHandler.icmpv4(
        src: benchClient,
        dst: benchServer,
        type: ICMPv4Type.echoRequest,
        code: 0,
        rest: 0x0001_0001,
        payload: payload
    ).asSharedData()

    let batch = Array(repeating: request, count: config.batch)

    func inject() async {
        await stack.ingestBatch(batch)
    }

    await sampleUntil(config.warmup) { await inject() }
    sink.reset()

    var packetsIn: UInt64 = 0
    let measured = await timed {
        await sampleUntil(config.duration) {
            await inject()
            packetsIn &+= UInt64(config.batch)
        }
    }

    let out = sink.snapshot()
    return BenchResult.make(
        scenario: "icmp-echo",
        config: config,
        wall: measured.1,
        packetsIn: packetsIn,
        bytesIn: packetsIn * UInt64(request.count),
        packetsOut: out.packets,
        bytesOut: out.bytes,
        deliveredBytes: out.bytes,
        established: 0,
        cpuUser: measured.2,
        cpuSys: measured.3,
        rssBefore: measured.4,
        rssAfter: measured.5,
        footBefore: measured.6,
        footAfter: measured.7,
        notes: "stateless echo; same request Data reused (no per-packet alloc on TX template)"
    )
}

func runScenario(_ name: String, config: BenchConfig) async throws -> BenchResult {
    switch name {
    case "tcp-rx":
        return try await runTCPRx(
            config: config,
            options: RxOptions(payload: config.payload, name: "tcp-rx", sampleIngest: true)
        )
    case "tcp-rx-small":
        return try await runTCPRx(config: config, options: RxOptions(payload: 64, name: "tcp-rx-small"))
    case "tcp-tx":
        return try await runTCPTx(config: config)
    case "tcp-duplex":
        return try await runTCPDuplex(config: config)
    case "tcp-active":
        return try await runTCPActive(config: config)
    case "tcp-rps":
        return try await runTCPRps(config: config)
    case "tcp-latency":
        return try await runTCPLatency(config: config)
    case "tcp-loss":
        return try await runTCPRx(
            config: config,
            options: RxOptions(
                payload: config.payload,
                name: "tcp-loss",
                lossPct: config.lossPct,
                reorder: true,
                sampleIngest: true
            )
        )
    case "tcp-rx6":
        return try await runTCPRx(
            config: config,
            options: RxOptions(payload: config.payload, name: "tcp-rx6", version: .v6, sampleIngest: true)
        )
    case "tcp-scale":
        return try await runTCPRx(
            config: config,
            options: RxOptions(
                payload: config.payload,
                name: "tcp-scale",
                sampleIngest: true,
                notes: "RX bulk at loops=\(config.loops)"
            )
        )
    case "tcp-cps":
        return try await runTCPCps(config: config)
    case "tcp-hold":
        return try await runTCPHold(config: config)
    case "icmp-echo":
        return try await runICMPEcho(config: config)
    default:
        throw BenchError.unknownScenario(name)
    }
}

let allScenarios = [
    "tcp-rx", "tcp-tx", "tcp-duplex", "tcp-active", "tcp-rps",
    "tcp-latency", "tcp-loss", "tcp-rx6", "tcp-scale", "tcp-hold",
]
