import Foundation

/// 8-byte UDP header parsed by borrowing the TUN packet. Payload is a shared `Data` slice.
public struct UDPDatagram: Sendable, Equatable {
    public var flow: FlowKey
    public var length: UInt16
    public var checksum: UInt16
    public var payloadOffset: Int
    public var payloadLength: Int

    public static func parse(packet: Data, ip: IPHeader) throws -> UDPDatagram {
        let off = ip.headerLength
        guard packet.count >= off + 8 else { throw PacketParseError.truncated }
        return try packet.withUnsafeBytes { bytes in
            let base = bytes.baseAddress!.advanced(by: off)
            let srcPort = UInt16(bigEndian: base.loadUnaligned(as: UInt16.self))
            let dstPort = UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 2, as: UInt16.self))
            let length = UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 4, as: UInt16.self))
            let checksum = UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 6, as: UInt16.self))
            let declared = Int(length)
            guard declared >= 8 else { throw PacketParseError.badHeaderLength }
            let payloadLength = min(declared - 8, packet.count - off - 8)
            return UDPDatagram(
                flow: FlowKey(src: ip.src, srcPort: srcPort, dst: ip.dst, dstPort: dstPort),
                length: length,
                checksum: checksum,
                payloadOffset: off + 8,
                payloadLength: payloadLength
            )
        }
    }
}

public enum UDPPacket: Sendable {
    public static func encapsulate(flow: FlowKey, payload: Data, ttl: UInt8 = 64) -> PacketBuffer {
        switch flow.src.version {
        case .v4: ipv4(flow: flow, payload: payload, ttl: ttl)
        case .v6: ipv6(flow: flow, payload: payload, hopLimit: ttl)
        }
    }

    public static func ipv4(flow: FlowKey, payload: Data, ttl: UInt8 = 64) -> PacketBuffer {
        let src = IPWire.v4(flow.src)
        let dst = IPWire.v4(flow.dst)
        let udpLen = 8 + payload.count
        let total = 20 + udpLen
        var buffer = PacketBuffer(capacity: max(total, 64))
        IPWire.appendIPv4(&buffer, src: src, dst: dst, total: total, proto: IPProtocolNumber.udp.rawValue, ttl: ttl)
        buffer.append(networkOrder: flow.srcPort)
        buffer.append(networkOrder: flow.dstPort)
        buffer.append(networkOrder: UInt16(udpLen))
        buffer.append(networkOrder: UInt16(0))
        payload.withUnsafeBytes { buffer.append($0) }
        fillChecksumIPv4(&buffer, src: src, dst: dst, udpLength: udpLen)
        return buffer
    }

    public static func ipv6(flow: FlowKey, payload: Data, hopLimit: UInt8 = 64) -> PacketBuffer {
        let src = IPWire.v6(flow.src)
        let dst = IPWire.v6(flow.dst)
        let udpLen = 8 + payload.count
        var buffer = PacketBuffer(capacity: max(40 + udpLen, 80))
        IPWire.appendIPv6(
            &buffer,
            srcHigh: src.0, srcLow: src.1,
            dstHigh: dst.0, dstLow: dst.1,
            payloadLen: udpLen,
            nextHeader: IPProtocolNumber.udp.rawValue,
            hopLimit: hopLimit
        )
        buffer.append(networkOrder: flow.srcPort)
        buffer.append(networkOrder: flow.dstPort)
        buffer.append(networkOrder: UInt16(udpLen))
        buffer.append(networkOrder: UInt16(0))
        payload.withUnsafeBytes { buffer.append($0) }
        fillChecksumIPv6(&buffer, src: src, dst: dst, udpLength: udpLen)
        return buffer
    }

    private static func fillChecksumIPv4(_ buffer: inout PacketBuffer, src: UInt32, dst: UInt32, udpLength: Int) {
        buffer.withUnsafeMutableBytes { raw in
            let udpBytes = UnsafeRawBufferPointer(start: raw.baseAddress!.advanced(by: 20), count: udpLength)
            let sum = InternetChecksum.transportIPv4(
                src: src, dst: dst,
                proto: IPProtocolNumber.udp.rawValue,
                length: udpLength,
                headerAndPayload: udpBytes
            )
            raw.storeBytes(of: sum.bigEndian, toByteOffset: 26, as: UInt16.self)
        }
        IPWire.fillIPv4HeaderChecksum(&buffer)
    }

    private static func fillChecksumIPv6(
        _ buffer: inout PacketBuffer,
        src: (UInt64, UInt64),
        dst: (UInt64, UInt64),
        udpLength: Int
    ) {
        buffer.withUnsafeMutableBytes { raw in
            let udpBytes = UnsafeRawBufferPointer(start: raw.baseAddress!.advanced(by: 40), count: udpLength)
            let sum = InternetChecksum.transportIPv6(
                srcHigh: src.0, srcLow: src.1,
                dstHigh: dst.0, dstLow: dst.1,
                proto: IPProtocolNumber.udp.rawValue,
                length: udpLength,
                headerAndPayload: udpBytes
            )
            raw.storeBytes(of: sum.bigEndian, toByteOffset: 46, as: UInt16.self)
        }
    }
}
