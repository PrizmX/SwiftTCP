import Foundation

public enum ICMPv4Type: Sendable {
    public static let echoReply: UInt8 = 0
    public static let destinationUnreachable: UInt8 = 3
    public static let echoRequest: UInt8 = 8
    public static let fragmentationNeeded: UInt8 = 4
}

public enum ICMPv6Type: Sendable {
    public static let destinationUnreachable: UInt8 = 1
    public static let packetTooBig: UInt8 = 2
    public static let echoRequest: UInt8 = 128
    public static let echoReply: UInt8 = 129
}

public struct ICMPMessage: Sendable, Equatable {
    public var type: UInt8
    public var code: UInt8
    public var rest: UInt32
    public var payloadOffset: Int
    public var payloadLength: Int

    public static func parse(packet: Data, ip: IPHeader) throws -> ICMPMessage {
        let off = ip.headerLength
        guard packet.count >= off + 8 else { throw PacketParseError.truncated }
        return packet.withUnsafeBytes { bytes in
            let base = bytes.baseAddress!.advanced(by: off)
            let type = base.load(as: UInt8.self)
            let code = base.load(fromByteOffset: 1, as: UInt8.self)
            let rest = UInt32(bigEndian: base.loadUnaligned(fromByteOffset: 4, as: UInt32.self))
            return ICMPMessage(
                type: type,
                code: code,
                rest: rest,
                payloadOffset: off + 8,
                payloadLength: packet.count - off - 8
            )
        }
    }
}

/// Echo replies and PMTU protection. Stateless: every call borrows the original
/// packet and emits a uniquely owned TX `PacketBuffer`.
public enum ICMPHandler: Sendable {
    /// ICMPv4 Echo Request (8) → Echo Reply (0);
    /// ICMPv6 Echo Request (128) → Echo Reply (129).
    /// Identifier, sequence and echo body are copied from the request.
    public static func echoReply(header: IPHeader, original: Data) -> PacketBuffer? {
        guard let message = try? ICMPMessage.parse(packet: original, ip: header) else { return nil }
        switch (header.version, message.type) {
        case (.v4, ICMPv4Type.echoRequest):
            return icmpv4(
                src: header.dst,
                dst: header.src,
                type: ICMPv4Type.echoReply,
                code: 0,
                rest: message.rest,
                payload: body(original, message)
            )
        case (.v6, ICMPv6Type.echoRequest):
            return icmpv6(
                src: header.dst,
                dst: header.src,
                type: ICMPv6Type.echoReply,
                code: 0,
                rest: message.rest,
                payload: body(original, message)
            )
        default:
            return nil
        }
    }

    /// IPv4 Type 3 Code 4 (Fragmentation Needed) / IPv6 Type 2 Code 0 (Packet Too Big).
    /// Payload is the original IP header plus the first 8 bytes of its payload.
    public static func packetTooBig(header: IPHeader, original: Data, mtu: Int) -> PacketBuffer {
        let quote = quotedOriginal(original, header: header)
        switch header.version {
        case .v4:
            let rest = UInt32(UInt16(clamping: mtu))
            return icmpv4(
                src: header.dst,
                dst: header.src,
                type: ICMPv4Type.destinationUnreachable,
                code: ICMPv4Type.fragmentationNeeded,
                rest: rest,
                payload: quote
            )
        case .v6:
            return icmpv6(
                src: header.dst,
                dst: header.src,
                type: ICMPv6Type.packetTooBig,
                code: 0,
                rest: UInt32(clamping: mtu),
                payload: quote
            )
        }
    }

    public static func icmpv4(
        src: IPAddress,
        dst: IPAddress,
        type: UInt8,
        code: UInt8,
        rest: UInt32,
        payload: Data,
        ttl: UInt8 = 64
    ) -> PacketBuffer {
        let srcV = IPWire.v4(src)
        let dstV = IPWire.v4(dst)
        let icmpLen = 8 + payload.count
        let total = 20 + icmpLen
        var buffer = PacketBuffer(capacity: max(total, 64))
        IPWire.appendIPv4(&buffer, src: srcV, dst: dstV, total: total, proto: IPProtocolNumber.icmp.rawValue, ttl: ttl)
        buffer.append(networkOrder: type)
        buffer.append(networkOrder: code)
        buffer.append(networkOrder: UInt16(0))
        buffer.append(networkOrder: rest)
        payload.withUnsafeBytes { buffer.append($0) }
        buffer.withUnsafeMutableBytes { raw in
            let icmpBytes = UnsafeRawBufferPointer(start: raw.baseAddress!.advanced(by: 20), count: icmpLen)
            let sum = InternetChecksum.compute(bytes: icmpBytes)
            raw.storeBytes(of: sum.bigEndian, toByteOffset: 22, as: UInt16.self)
        }
        IPWire.fillIPv4HeaderChecksum(&buffer)
        return buffer
    }

    public static func icmpv6(
        src: IPAddress,
        dst: IPAddress,
        type: UInt8,
        code: UInt8,
        rest: UInt32,
        payload: Data,
        hopLimit: UInt8 = 64
    ) -> PacketBuffer {
        let s = IPWire.v6(src)
        let d = IPWire.v6(dst)
        let icmpLen = 8 + payload.count
        var buffer = PacketBuffer(capacity: max(40 + icmpLen, 80))
        IPWire.appendIPv6(
            &buffer,
            srcHigh: s.0, srcLow: s.1,
            dstHigh: d.0, dstLow: d.1,
            payloadLen: icmpLen,
            nextHeader: IPProtocolNumber.icmpv6.rawValue,
            hopLimit: hopLimit
        )
        buffer.append(networkOrder: type)
        buffer.append(networkOrder: code)
        buffer.append(networkOrder: UInt16(0))
        buffer.append(networkOrder: rest)
        payload.withUnsafeBytes { buffer.append($0) }
        buffer.withUnsafeMutableBytes { raw in
            let icmpBytes = UnsafeRawBufferPointer(start: raw.baseAddress!.advanced(by: 40), count: icmpLen)
            let sum = InternetChecksum.transportIPv6(
                srcHigh: s.0, srcLow: s.1,
                dstHigh: d.0, dstLow: d.1,
                proto: IPProtocolNumber.icmpv6.rawValue,
                length: icmpLen,
                headerAndPayload: icmpBytes
            )
            raw.storeBytes(of: sum.bigEndian, toByteOffset: 42, as: UInt16.self)
        }
        return buffer
    }

    /// RFC 792 / RFC 4443: original IP header + first 8 bytes of the L4 header
    /// (enough for TCP/UDP ports so the sender can match the flow).
    public static func quotedOriginal(_ original: Data, header: IPHeader) -> Data {
        let n = min(header.headerLength + 8, original.count)
        return Data(original.prefix(n))
    }

    /// IPv4 Type 3 Code 4 / IPv6 Type 2: next-hop MTU from the ICMP rest field.
    public static func pathMTU(header: IPHeader, original: Data) -> Int? {
        guard let message = try? ICMPMessage.parse(packet: original, ip: header) else { return nil }
        switch (header.version, message.type, message.code) {
        case (.v4, ICMPv4Type.destinationUnreachable, ICMPv4Type.fragmentationNeeded):
            let value = Int(UInt16(truncatingIfNeeded: message.rest))
            return value > 0 ? value : nil
        case (.v6, ICMPv6Type.packetTooBig, 0):
            let value = Int(message.rest)
            return value > 0 ? value : nil
        default:
            return nil
        }
    }

    /// 4-tuple of the quoted TCP header (original IP + first 8 bytes of L4).
    public static func quotedTCPFlow(header: IPHeader, original: Data) -> FlowKey? {
        guard let message = try? ICMPMessage.parse(packet: original, ip: header) else { return nil }
        let end = original.count
        guard message.payloadOffset < end else { return nil }
        let quote = original.subdata(in: message.payloadOffset..<end)
        guard let inner = try? IPHeader.peek(quote), inner.protocol == .tcp else { return nil }
        guard quote.count >= inner.headerLength + 4 else { return nil }
        return quote.withUnsafeBytes { bytes -> FlowKey? in
            guard let base = bytes.baseAddress else { return nil }
            let tcp = base.advanced(by: inner.headerLength)
            let srcPort = UInt16(bigEndian: tcp.loadUnaligned(as: UInt16.self))
            let dstPort = UInt16(bigEndian: tcp.loadUnaligned(fromByteOffset: 2, as: UInt16.self))
            return FlowKey(src: inner.src, srcPort: srcPort, dst: inner.dst, dstPort: dstPort)
        }
    }

    private static func body(_ original: Data, _ message: ICMPMessage) -> Data {
        guard message.payloadLength > 0, original.count >= message.payloadOffset + message.payloadLength else {
            return Data()
        }
        return original.subdata(in: message.payloadOffset..<(message.payloadOffset + message.payloadLength))
    }
}
