import Foundation

public struct SwiftStackConfig: Sendable {
    public var tcp: TCPStackConfig
    public var mtu: Int
    public var udpIdle: Duration
    public var dnsIdle: Duration
    public var udpMaxLifetime: Duration

    public var udpMaxSessions: Int

    public init(
        tcp: TCPStackConfig = .init(),
        mtu: Int = 1400,
        udpIdle: Duration = .seconds(120),
        dnsIdle: Duration = .seconds(15),
        udpMaxLifetime: Duration = .seconds(24 * 60 * 60),
        udpMaxSessions: Int = 8_192
    ) {
        self.mtu = mtu
        self.udpIdle = udpIdle
        self.dnsIdle = dnsIdle
        self.udpMaxLifetime = udpMaxLifetime
        self.udpMaxSessions = max(1, udpMaxSessions)
        var tcp = tcp
        let overhead = 60
        let derived = UInt16(clamping: max(536, mtu - overhead))
        if tcp.maxMss > derived { tcp.maxMss = derived }
        self.tcp = tcp
    }
}

/// Unified userspace IP stack: TCP + UDP + ICMP over a single TUN ingest path.
public actor SwiftStack: TCPByteStream {
    public let config: SwiftStackConfig
    nonisolated let tcp: TCPDispatcher
    nonisolated let udp: UDPHandler
    nonisolated let demuxer: IPDemuxer

    public init(
        config: SwiftStackConfig = .init(),
        sink: any PacketSink,
        streams: any TCPStreamHandler = NoopStreamHandler(),
        datagrams: (any UDPDatagramHandler)? = nil
    ) {
        self.config = config
        let tcp = TCPDispatcher(config: config.tcp, sink: sink, streams: streams)
        let udp = UDPHandler(
            sink: sink,
            idle: config.udpIdle,
            dnsIdle: config.dnsIdle,
            maxLifetime: config.udpMaxLifetime,
            maxSessions: config.udpMaxSessions
        )
        self.tcp = tcp
        self.udp = udp
        self.demuxer = IPDemuxer(tcp: tcp, udp: udp, sink: sink, mtu: config.mtu)
        if let datagrams {
            udp.setUpstream(datagrams)
        } else {
            #if canImport(Network)
            udp.setUpstream(NWUDPForwarder(replies: udp))
            #else
            udp.setUpstream(NoopUDPHandler())
            #endif
        }
    }

    nonisolated public func ingest(_ data: Data) async {
        await demuxer.ingestBatch([data])
    }

    nonisolated public func ingestBatch(_ packets: [Data], protocols: [NSNumber] = []) async {
        await demuxer.ingestBatch(packets, protocols: protocols)
    }

    @discardableResult
    nonisolated public func send(flow: FlowKey, data: Data) async -> Int {
        await tcp.send(flow: flow, data: data)
    }

    nonisolated public func sendBatch(_ items: [(FlowKey, Data)]) async {
        await tcp.sendBatch(items)
    }

    nonisolated public func close(flow: FlowKey) async {
        await tcp.close(flow: flow)
    }

    nonisolated public func creditAppReceive(flow: FlowKey, bytes: Int) async {
        await tcp.creditAppReceive(flow: flow, bytes: bytes)
    }

    nonisolated public func connect(flow: FlowKey) async {
        await tcp.connect(flow: flow)
    }

    /// Encapsulate a UDP reply toward the TUN client for an ingested flow.
    nonisolated public func sendDatagram(flow: FlowKey, payload: Data) async {
        await udp.sendReply(flow: flow, payload: payload)
    }

    nonisolated public func shutdown() async {
        await udp.closeAll()
        await tcp.shutdown()
    }

    public func connectionCount() async -> Int {
        await tcp.connectionCount()
    }

    public func metrics() async -> StackMetrics {
        var snapshot = demuxer.metricsSnapshot()
        snapshot.droppedUDPLimit = await udp.droppedAtCap
        return snapshot
    }
}
