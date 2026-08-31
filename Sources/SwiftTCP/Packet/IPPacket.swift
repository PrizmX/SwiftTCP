import Foundation

/// Parsed IP/TCP view over a uniquely owned `PacketBuffer`.
/// Header fields are copied into registers; payload remains a slice of `buffer`.
public struct IPPacket: ~Copyable, Sendable {
    public var buffer: PacketBuffer
    public var segment: TCPSegment

    public static func parse(_ buffer: consuming PacketBuffer) throws -> IPPacket {
        let segment = try buffer.withUnsafeBytes { bytes -> TCPSegment in
            try parseSegment(bytes: bytes)
        }
        return IPPacket(buffer: buffer, segment: segment)
    }

    /// Peek the 4-tuple without taking ownership — used by the dispatcher
    /// to pick an EventLoop before hopping.
    public static func peekFlowKey(_ data: Data) throws -> FlowKey {
        try data.withUnsafeBytes { try parseSegment(bytes: $0).flow }
    }

    /// Parse the IP and TCP headers once and return both. The RX hot path uses
    /// this so the demuxer/dispatcher/event-loop don't each re-parse the same
    /// headers (previously three parses per packet).
    public static func peekFull(_ data: Data) throws -> (header: IPHeader, segment: TCPSegment) {
        try data.withUnsafeBytes { bytes in
            let header = try IPHeader.parse(bytes: bytes)
            guard header.nextHeader == IPProtocolNumber.tcp.rawValue else {
                throw PacketParseError.notTCP
            }
            guard let base = bytes.baseAddress else { throw PacketParseError.truncated }
            let segment = try parseTCP(
                base: base,
                ipHeaderLength: header.headerLength,
                packetLength: header.totalLength,
                flowSrc: header.src,
                flowDst: header.dst,
                version: header.version
            )
            return (header, segment)
        }
    }

    public borrowing func retainedPayload() -> Data {
        buffer.retainedPayload(offset: segment.payloadOffset, length: segment.payloadLength)
    }

    public static func parseSegment(bytes: UnsafeRawBufferPointer) throws -> TCPSegment {
        let ip = try IPHeader.parse(bytes: bytes)
        guard ip.nextHeader == IPProtocolNumber.tcp.rawValue else {
            throw PacketParseError.notTCP
        }
        guard let base = bytes.baseAddress else { throw PacketParseError.truncated }
        return try parseTCP(
            base: base,
            ipHeaderLength: ip.headerLength,
            packetLength: ip.totalLength,
            flowSrc: ip.src,
            flowDst: ip.dst,
            version: ip.version
        )
    }

    /// Parse TCP headers. Ingress checksums are not verified: TUN packets are
    /// locally originated and already checksummed by the kernel stack.
    private static func parseTCP(
        base: UnsafeRawPointer,
        ipHeaderLength: Int,
        packetLength: Int,
        flowSrc: IPAddress,
        flowDst: IPAddress,
        version: IPVersion
    ) throws -> TCPSegment {
        guard ipHeaderLength + 20 <= packetLength else {
            throw PacketParseError.truncated
        }
        let tcp = base.advanced(by: ipHeaderLength)
        let srcPort = UInt16(bigEndian: tcp.loadUnaligned(as: UInt16.self))
        let dstPort = UInt16(bigEndian: tcp.loadUnaligned(fromByteOffset: 2, as: UInt16.self))
        let seq = UInt32(bigEndian: tcp.loadUnaligned(fromByteOffset: 4, as: UInt32.self))
        let ack = UInt32(bigEndian: tcp.loadUnaligned(fromByteOffset: 8, as: UInt32.self))
        let offsetFlags = UInt16(bigEndian: tcp.loadUnaligned(fromByteOffset: 12, as: UInt16.self))
        let dataOffset = Int(offsetFlags >> 12) * 4
        guard dataOffset >= 20, ipHeaderLength + dataOffset <= packetLength else {
            throw PacketParseError.badHeaderLength
        }
        let flags = TCPFlags(rawValue: UInt8(truncatingIfNeeded: offsetFlags))
        let window = UInt16(bigEndian: tcp.loadUnaligned(fromByteOffset: 14, as: UInt16.self))
        let optionBytes = UnsafeRawBufferPointer(start: tcp.advanced(by: 20), count: dataOffset - 20)
        let payloadOffset = ipHeaderLength + dataOffset
        let payloadLength = packetLength - payloadOffset
        return TCPSegment(
            flow: FlowKey(src: flowSrc, srcPort: srcPort, dst: flowDst, dstPort: dstPort),
            seq: seq,
            ack: ack,
            flags: flags,
            window: window,
            dataOffset: dataOffset,
            payloadOffset: payloadOffset,
            payloadLength: payloadLength,
            options: TCPOptions.parse(bytes: optionBytes),
            ipHeaderLength: ipHeaderLength,
            version: version
        )
    }
}

/// TX packet assembler. Writes into a pre-allocated `PacketBuffer`.
public enum PacketBuilder: Sendable {
    public static func tcpIPv4(
        flow: FlowKey,
        seq: UInt32,
        ack: UInt32,
        flags: TCPFlags,
        window: UInt16,
        options: TCPOptions = .empty,
        payload: Data = Data(),
        ttl: UInt8 = 64,
        pool: TXBufferPool? = nil
    ) -> PacketBuffer {
        tcpIPv4(
            flow: flow, seq: seq, ack: ack, flags: flags, window: window,
            options: options,
            payloadCount: payload.count,
            writePayload: { buffer in
                payload.withUnsafeBytes { bytes in
                    if bytes.count > 0 { buffer.append(bytes) }
                }
            },
            ttl: ttl,
            pool: pool
        )
    }

    public static func tcpIPv6(
        flow: FlowKey,
        seq: UInt32,
        ack: UInt32,
        flags: TCPFlags,
        window: UInt16,
        options: TCPOptions = .empty,
        payload: Data = Data(),
        hopLimit: UInt8 = 64,
        pool: TXBufferPool? = nil
    ) -> PacketBuffer {
        tcpIPv6(
            flow: flow, seq: seq, ack: ack, flags: flags, window: window,
            options: options,
            payloadCount: payload.count,
            writePayload: { buffer in
                payload.withUnsafeBytes { bytes in
                    if bytes.count > 0 { buffer.append(bytes) }
                }
            },
            hopLimit: hopLimit,
            pool: pool
        )
    }

    public static func tcp(
        flow: FlowKey,
        seq: UInt32,
        ack: UInt32,
        flags: TCPFlags,
        window: UInt16,
        options: TCPOptions = .empty,
        payload: Data = Data(),
        pool: TXBufferPool? = nil
    ) -> PacketBuffer {
        switch flow.src.version {
        case .v4:
            tcpIPv4(
                flow: flow, seq: seq, ack: ack, flags: flags, window: window,
                options: options, payload: payload, pool: pool
            )
        case .v6:
            tcpIPv6(
                flow: flow, seq: seq, ack: ack, flags: flags, window: window,
                options: options, payload: payload, pool: pool
            )
        }
    }

    /// Build a segment copying payload from a send ring (one or two physical spans).
    public static func tcp(
        flow: FlowKey,
        seq: UInt32,
        ack: UInt32,
        flags: TCPFlags,
        window: UInt16,
        options: TCPOptions = .empty,
        payloadFrom ring: ByteRingBuffer,
        offset: Int, count: Int,
        pool: TXBufferPool? = nil
    ) -> PacketBuffer {
        let start = min(max(offset, 0), ring.count)
        let n = min(count, ring.count - start)
        switch flow.src.version {
        case .v4:
            return tcpIPv4(
                flow: flow, seq: seq, ack: ack, flags: flags, window: window,
                options: options,
                payloadCount: n,
                writePayload: { buffer in
                    ring.withUnsafeRegions(offset: start, maxCount: n) { a, b in
                        if a.count > 0 { buffer.append(a) }
                        if b.count > 0 { buffer.append(b) }
                    }
                },
                pool: pool
            )
        case .v6:
            return tcpIPv6(
                flow: flow, seq: seq, ack: ack, flags: flags, window: window,
                options: options,
                payloadCount: n,
                writePayload: { buffer in
                    ring.withUnsafeRegions(offset: start, maxCount: n) { a, b in
                        if a.count > 0 { buffer.append(a) }
                        if b.count > 0 { buffer.append(b) }
                    }
                },
                pool: pool
            )
        }
    }

    public static func tcpIPv4(
        flow: FlowKey,
        seq: UInt32,
        ack: UInt32,
        flags: TCPFlags,
        window: UInt16,
        options: TCPOptions = .empty,
        payloadA: UnsafeRawBufferPointer,
        payloadB: UnsafeRawBufferPointer,
        ttl: UInt8 = 64,
        pool: TXBufferPool? = nil
    ) -> PacketBuffer {
        guard case .v4(let src) = flow.src.kind, case .v4(let dst) = flow.dst.kind else {
            preconditionFailure("tcpIPv4 requires IPv4 FlowKey")
        }
        let optionBytes = options.encoded()
        let tcpHeader = 20 + optionBytes.count
        let payloadCount = payloadA.count + payloadB.count
        let total = 20 + tcpHeader + payloadCount
        var buffer = makeBuffer(minimumCapacity: max(total, 64), pool: pool)

        buffer.append(networkOrder: UInt8(0x45))
        buffer.append(networkOrder: UInt8(0))
        buffer.append(networkOrder: UInt16(total))
        buffer.append(networkOrder: UInt16(0))
        buffer.append(networkOrder: UInt16(0x4000)) // DF
        buffer.append(networkOrder: ttl)
        buffer.append(networkOrder: IPProtocolNumber.tcp.rawValue)
        buffer.append(networkOrder: UInt16(0))
        buffer.append(networkOrder: src)
        buffer.append(networkOrder: dst)

        buffer.append(networkOrder: flow.srcPort)
        buffer.append(networkOrder: flow.dstPort)
        buffer.append(networkOrder: seq)
        buffer.append(networkOrder: ack)
        let offsetFlags = UInt16((tcpHeader / 4) << 12) | UInt16(flags.rawValue)
        buffer.append(networkOrder: offsetFlags)
        buffer.append(networkOrder: window)
        buffer.append(networkOrder: UInt16(0))
        buffer.append(networkOrder: UInt16(0))
        optionBytes.withUnsafeBytes { buffer.append($0) }
        if payloadA.count > 0 { buffer.append(payloadA) }
        if payloadB.count > 0 { buffer.append(payloadB) }

        fillChecksumsIPv4(&buffer, src: src, dst: dst, tcpLength: tcpHeader + payloadCount)
        return buffer
    }

    private static func tcpIPv4(
        flow: FlowKey,
        seq: UInt32,
        ack: UInt32,
        flags: TCPFlags,
        window: UInt16,
        options: TCPOptions,
        payloadCount: Int,
        writePayload: (inout PacketBuffer) -> Void,
        ttl: UInt8 = 64,
        pool: TXBufferPool? = nil
    ) -> PacketBuffer {
        guard case .v4(let src) = flow.src.kind, case .v4(let dst) = flow.dst.kind else {
            preconditionFailure("tcpIPv4 requires IPv4 FlowKey")
        }
        let optionBytes = options.encoded()
        let tcpHeader = 20 + optionBytes.count
        let total = 20 + tcpHeader + payloadCount
        var buffer = makeBuffer(minimumCapacity: max(total, 64), pool: pool)

        buffer.append(networkOrder: UInt8(0x45))
        buffer.append(networkOrder: UInt8(0))
        buffer.append(networkOrder: UInt16(total))
        buffer.append(networkOrder: UInt16(0))
        buffer.append(networkOrder: UInt16(0x4000))
        buffer.append(networkOrder: ttl)
        buffer.append(networkOrder: IPProtocolNumber.tcp.rawValue)
        buffer.append(networkOrder: UInt16(0))
        buffer.append(networkOrder: src)
        buffer.append(networkOrder: dst)

        buffer.append(networkOrder: flow.srcPort)
        buffer.append(networkOrder: flow.dstPort)
        buffer.append(networkOrder: seq)
        buffer.append(networkOrder: ack)
        let offsetFlags = UInt16((tcpHeader / 4) << 12) | UInt16(flags.rawValue)
        buffer.append(networkOrder: offsetFlags)
        buffer.append(networkOrder: window)
        buffer.append(networkOrder: UInt16(0))
        buffer.append(networkOrder: UInt16(0))
        optionBytes.withUnsafeBytes { buffer.append($0) }
        writePayload(&buffer)

        fillChecksumsIPv4(&buffer, src: src, dst: dst, tcpLength: tcpHeader + payloadCount)
        return buffer
    }

    public static func tcpIPv6(
        flow: FlowKey,
        seq: UInt32,
        ack: UInt32,
        flags: TCPFlags,
        window: UInt16,
        options: TCPOptions = .empty,
        payloadA: UnsafeRawBufferPointer,
        payloadB: UnsafeRawBufferPointer,
        hopLimit: UInt8 = 64,
        pool: TXBufferPool? = nil
    ) -> PacketBuffer {
        guard case .v6(let srcHigh, let srcLow) = flow.src.kind, case .v6(let dstHigh, let dstLow) = flow.dst.kind else {
            preconditionFailure("tcpIPv6 requires IPv6 FlowKey")
        }
        let optionBytes = options.encoded()
        let tcpHeader = 20 + optionBytes.count
        let payloadCount = payloadA.count + payloadB.count
        let payloadLen = tcpHeader + payloadCount
        let total = 40 + payloadLen
        var buffer = makeBuffer(minimumCapacity: max(total, 80), pool: pool)

        buffer.append(networkOrder: UInt8(0x60))
        buffer.append(networkOrder: UInt8(0))
        buffer.append(networkOrder: UInt16(0))
        buffer.append(networkOrder: UInt16(payloadLen))
        buffer.append(networkOrder: IPProtocolNumber.tcp.rawValue)
        buffer.append(networkOrder: hopLimit)
        var srcHighBE = srcHigh.bigEndian
        var srcLowBE = srcLow.bigEndian
        var dstHighBE = dstHigh.bigEndian
        var dstLowBE = dstLow.bigEndian
        withUnsafeBytes(of: &srcHighBE) { buffer.append(UnsafeRawBufferPointer($0)) }
        withUnsafeBytes(of: &srcLowBE) { buffer.append(UnsafeRawBufferPointer($0)) }
        withUnsafeBytes(of: &dstHighBE) { buffer.append(UnsafeRawBufferPointer($0)) }
        withUnsafeBytes(of: &dstLowBE) { buffer.append(UnsafeRawBufferPointer($0)) }

        buffer.append(networkOrder: flow.srcPort)
        buffer.append(networkOrder: flow.dstPort)
        buffer.append(networkOrder: seq)
        buffer.append(networkOrder: ack)
        let offsetFlags = UInt16((tcpHeader / 4) << 12) | UInt16(flags.rawValue)
        buffer.append(networkOrder: offsetFlags)
        buffer.append(networkOrder: window)
        buffer.append(networkOrder: UInt16(0))
        buffer.append(networkOrder: UInt16(0))
        optionBytes.withUnsafeBytes { buffer.append($0) }
        if payloadA.count > 0 { buffer.append(payloadA) }
        if payloadB.count > 0 { buffer.append(payloadB) }

        fillChecksumsIPv6(
            &buffer,
            srcHigh: srcHigh, srcLow: srcLow,
            dstHigh: dstHigh, dstLow: dstLow,
            tcpLength: payloadLen
        )
        return buffer
    }

    private static func tcpIPv6(
        flow: FlowKey,
        seq: UInt32,
        ack: UInt32,
        flags: TCPFlags,
        window: UInt16,
        options: TCPOptions,
        payloadCount: Int,
        writePayload: (inout PacketBuffer) -> Void,
        hopLimit: UInt8 = 64,
        pool: TXBufferPool? = nil
    ) -> PacketBuffer {
        guard case .v6(let srcHigh, let srcLow) = flow.src.kind, case .v6(let dstHigh, let dstLow) = flow.dst.kind else {
            preconditionFailure("tcpIPv6 requires IPv6 FlowKey")
        }
        let optionBytes = options.encoded()
        let tcpHeader = 20 + optionBytes.count
        let payloadLen = tcpHeader + payloadCount
        let total = 40 + payloadLen
        var buffer = makeBuffer(minimumCapacity: max(total, 80), pool: pool)

        buffer.append(networkOrder: UInt8(0x60))
        buffer.append(networkOrder: UInt8(0))
        buffer.append(networkOrder: UInt16(0))
        buffer.append(networkOrder: UInt16(payloadLen))
        buffer.append(networkOrder: IPProtocolNumber.tcp.rawValue)
        buffer.append(networkOrder: hopLimit)
        var srcHighBE = srcHigh.bigEndian
        var srcLowBE = srcLow.bigEndian
        var dstHighBE = dstHigh.bigEndian
        var dstLowBE = dstLow.bigEndian
        withUnsafeBytes(of: &srcHighBE) { buffer.append(UnsafeRawBufferPointer($0)) }
        withUnsafeBytes(of: &srcLowBE) { buffer.append(UnsafeRawBufferPointer($0)) }
        withUnsafeBytes(of: &dstHighBE) { buffer.append(UnsafeRawBufferPointer($0)) }
        withUnsafeBytes(of: &dstLowBE) { buffer.append(UnsafeRawBufferPointer($0)) }

        buffer.append(networkOrder: flow.srcPort)
        buffer.append(networkOrder: flow.dstPort)
        buffer.append(networkOrder: seq)
        buffer.append(networkOrder: ack)
        let offsetFlags = UInt16((tcpHeader / 4) << 12) | UInt16(flags.rawValue)
        buffer.append(networkOrder: offsetFlags)
        buffer.append(networkOrder: window)
        buffer.append(networkOrder: UInt16(0))
        buffer.append(networkOrder: UInt16(0))
        optionBytes.withUnsafeBytes { buffer.append($0) }
        writePayload(&buffer)

        fillChecksumsIPv6(
            &buffer,
            srcHigh: srcHigh, srcLow: srcLow,
            dstHigh: dstHigh, dstLow: dstLow,
            tcpLength: payloadLen
        )
        return buffer
    }

    private static func makeBuffer(minimumCapacity: Int, pool: TXBufferPool?) -> PacketBuffer {
        if let pool {
            return PacketBuffer(storage: pool.take(minimumCapacity: minimumCapacity))
        }
        return PacketBuffer(capacity: minimumCapacity)
    }

    private static func fillChecksumsIPv4(_ buffer: inout PacketBuffer, src: UInt32, dst: UInt32, tcpLength: Int) {
        buffer.withUnsafeMutableBytes { raw in
            let ipSum = InternetChecksum.compute(bytes: UnsafeRawBufferPointer(start: raw.baseAddress, count: 20))
            raw.storeBytes(of: ipSum.bigEndian, toByteOffset: 10, as: UInt16.self)
            let tcpBytes = UnsafeRawBufferPointer(start: raw.baseAddress!.advanced(by: 20), count: tcpLength)
            let tcpSum = InternetChecksum.tcpIPv4(src: src, dst: dst, tcpLength: tcpLength, headerAndPayload: tcpBytes)
            raw.storeBytes(of: tcpSum.bigEndian, toByteOffset: 36, as: UInt16.self)
        }
    }

    private static func fillChecksumsIPv6(
        _ buffer: inout PacketBuffer,
        srcHigh: UInt64, srcLow: UInt64,
        dstHigh: UInt64, dstLow: UInt64,
        tcpLength: Int
    ) {
        buffer.withUnsafeMutableBytes { raw in
            let tcpBytes = UnsafeRawBufferPointer(start: raw.baseAddress!.advanced(by: 40), count: tcpLength)
            let tcpSum = InternetChecksum.tcpIPv6(
                srcHigh: srcHigh, srcLow: srcLow,
                dstHigh: dstHigh, dstLow: dstLow,
                tcpLength: tcpLength,
                headerAndPayload: tcpBytes
            )
            raw.storeBytes(of: tcpSum.bigEndian, toByteOffset: 56, as: UInt16.self)
        }
    }
}

/// A TCP packet whose IP+TCP headers have already been parsed exactly once.
/// Carried from the demuxer to the dispatcher (routing by 4-tuple) and on to the
/// event loop (no re-parse), keeping the RX hot path to a single header parse.
public struct InboundTCPPacket: Sendable {
    public var flow: FlowKey
    public var segment: TCPSegment
    public var data: Data

    public init(flow: FlowKey, segment: TCPSegment, data: Data) {
        self.flow = flow
        self.segment = segment
        self.data = data
    }
}
