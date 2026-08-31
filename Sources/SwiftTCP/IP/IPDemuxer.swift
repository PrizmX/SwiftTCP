import Foundation

enum IPRoute: Sendable, Equatable {
    case tcp
    case udp
    case icmp
    case icmpv6
    case unknown(UInt8)
}

public struct StackMetrics: Sendable, Equatable {
    public var inboundTCP: UInt64 = 0
    public var inboundUDP: UInt64 = 0
    public var inboundICMP: UInt64 = 0
    public var droppedUnknown: UInt64 = 0
    public var droppedFragment: UInt64 = 0
    public var droppedTruncated: UInt64 = 0
    public var pmtuMessages: UInt64 = 0
    public var pmtuUpdates: UInt64 = 0
    public var echoReplies: UInt64 = 0
    public var droppedUDPLimit: UInt64 = 0

    public init() {}
}

/// L3 match dispatcher. Peeks IPv4/IPv6 headers by borrowing TUN bytes, then
/// routes to TCP / UDP / ICMP without copying the payload.
actor IPDemuxer {
    nonisolated let mtu: Int
    nonisolated let tcp: TCPDispatcher
    nonisolated let udp: UDPHandler
    nonisolated let sink: any PacketSink
    private let metricsBox = MetricsBox()

    init(tcp: TCPDispatcher, udp: UDPHandler, sink: any PacketSink, mtu: Int) {
        self.tcp = tcp
        self.udp = udp
        self.sink = sink
        self.mtu = mtu
    }

    static func classify(_ header: IPHeader) -> IPRoute {
        switch header.nextHeader {
        case IPProtocolNumber.tcp.rawValue: .tcp
        case IPProtocolNumber.udp.rawValue: .udp
        case IPProtocolNumber.icmp.rawValue: .icmp
        case IPProtocolNumber.icmpv6.rawValue: .icmpv6
        default: .unknown(header.nextHeader)
        }
    }

    nonisolated func metricsSnapshot() -> StackMetrics {
        metricsBox.snapshot()
    }

    nonisolated func ingestBatch(_ packets: [Data], protocols: [NSNumber] = []) async {
        let demuxed = demux(packets, protocols: protocols)
        if !demuxed.tcp.isEmpty {
            await tcp.ingestBatch(demuxed.tcp)
        }
        if !demuxed.udp.isEmpty {
            await udp.ingestBatch(demuxed.udp)
        }
        for item in demuxed.pmtu {
            await tcp.applyPMTU(flow: item.0, mtu: item.1)
        }
    }

    private struct Demuxed: Sendable {
        var tcp: [InboundTCPPacket] = []
        var udp: [(IPHeader, Data)] = []
        var pmtu: [(FlowKey, Int)] = []
    }

    nonisolated private func demux(_ packets: [Data], protocols: [NSNumber]) -> Demuxed {
        _ = protocols
        var result = Demuxed()
        var outbound: [(Data, UInt8)] = []
        result.tcp.reserveCapacity(packets.count)

        for data in packets {
            // TCP hot path: parse IP+TCP headers exactly once here. The demuxer,
            // dispatcher and event loop previously each re-parsed these headers
            // (three parses per packet).
            if let full = try? IPPacket.peekFull(data) {
                let header = full.header
                if Self.shouldEmitPacketTooBig(header, mtu: mtu) {
                    let icmp = ICMPHandler.packetTooBig(header: header, original: data, mtu: mtu)
                    outbound.append((icmp.asSharedData(), header.protocolFamily))
                    result.pmtu.append((full.segment.flow, mtu))
                    metricsBox.add { $0.pmtuMessages &+= 1 }
                    continue
                }
                metricsBox.add { $0.inboundTCP &+= 1 }
                result.tcp.append(
                    InboundTCPPacket(flow: full.segment.flow, segment: full.segment, data: data)
                )
                continue
            }

            // Non-TCP (or a truncated/malformed TCP segment): route on IP only.
            let header: IPHeader
            do {
                header = try IPHeader.peek(data)
            } catch PacketParseError.fragment {
                metricsBox.add { $0.droppedFragment &+= 1 }
                continue
            } catch {
                metricsBox.add { $0.droppedTruncated &+= 1 }
                continue
            }

            if Self.shouldEmitPacketTooBig(header, mtu: mtu) {
                let icmp = ICMPHandler.packetTooBig(header: header, original: data, mtu: mtu)
                outbound.append((icmp.asSharedData(), header.protocolFamily))
                metricsBox.add { $0.pmtuMessages &+= 1 }
                continue
            }

            switch Self.classify(header) {
            case .tcp:
                metricsBox.add { $0.droppedTruncated &+= 1 }
            case .udp:
                metricsBox.add { $0.inboundUDP &+= 1 }
                result.udp.append((header, data))
            case .icmp, .icmpv6:
                metricsBox.add { $0.inboundICMP &+= 1 }
                if let reply = ICMPHandler.echoReply(header: header, original: data) {
                    outbound.append((reply.asSharedData(), header.protocolFamily))
                    metricsBox.add { $0.echoReplies &+= 1 }
                } else if let nextHop = ICMPHandler.pathMTU(header: header, original: data),
                          let quoted = ICMPHandler.quotedTCPFlow(header: header, original: data)
                {
                    result.pmtu.append((quoted.reversed, nextHop))
                    metricsBox.add { $0.pmtuUpdates &+= 1 }
                }
            case .unknown:
                metricsBox.add { $0.droppedUnknown &+= 1 }
            }
        }

        if !outbound.isEmpty {
            sink.writeBatch(outbound)
        }
        return result
    }

    /// IPv4 DF (and all IPv6) datagrams larger than the tunnel MTU must not be
    /// forwarded — emit ICMP so the sender shrinks, avoiding a PMTU black hole.
    private static func shouldEmitPacketTooBig(_ header: IPHeader, mtu: Int) -> Bool {
        guard header.totalLength > mtu else { return false }
        switch header.nextHeader {
        case IPProtocolNumber.tcp.rawValue, IPProtocolNumber.udp.rawValue:
            return header.dontFragment
        default:
            return false
        }
    }
}

private final class MetricsBox: @unchecked Sendable {
    private var value = StackMetrics()
    private let lock = NSLock()

    func add(_ body: (inout StackMetrics) -> Void) {
        lock.lock()
        body(&value)
        lock.unlock()
    }

    func snapshot() -> StackMetrics {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}
