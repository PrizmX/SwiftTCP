import Foundation

/// Copyable L3 view. Header fields sit in registers; the payload stays a slice
/// of the original TUN `Data` (no memcpy).
public struct IPHeader: Sendable, Equatable {
    public var version: IPVersion
    public var src: IPAddress
    public var dst: IPAddress
    public var nextHeader: UInt8
    public var headerLength: Int
    public var totalLength: Int
    public var hopLimit: UInt8
    public var dontFragment: Bool
    public var identification: UInt16

    public var payloadOffset: Int { headerLength }
    public var payloadLength: Int { max(0, totalLength - headerLength) }
    public var protocolFamily: UInt8 { AddressFamily.of(version) }

    public var `protocol`: IPProtocolNumber? {
        IPProtocolNumber(rawValue: nextHeader)
    }

    public static func peek(_ data: Data) throws -> IPHeader {
        try data.withUnsafeBytes { try parse(bytes: $0) }
    }

    public static func parse(bytes: UnsafeRawBufferPointer) throws -> IPHeader {
        guard let base = bytes.baseAddress, bytes.count >= 20 else {
            throw PacketParseError.truncated
        }
        switch bytes[0] >> 4 {
        case 4:
            return try parseIPv4(base: base, count: bytes.count)
        case 6:
            return try parseIPv6(base: base, count: bytes.count)
        default:
            throw PacketParseError.unsupportedVersion
        }
    }

    private static func parseIPv4(base: UnsafeRawPointer, count: Int) throws -> IPHeader {
        let ihl = Int(base.load(fromByteOffset: 0, as: UInt8.self) & 0x0f) * 4
        guard ihl >= 20, count >= ihl else { throw PacketParseError.truncated }
        let total = Int(UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 2, as: UInt16.self)))
        let length = total == 0 ? count : min(total, count)
        guard length >= ihl else { throw PacketParseError.truncated }

        let frag = UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 6, as: UInt16.self))
        // Offset != 0 or MF: first fragment with MF=1 is also incomplete.
        if frag & 0x3fff != 0 { throw PacketParseError.fragment }

        let src = UInt32(bigEndian: base.loadUnaligned(fromByteOffset: 12, as: UInt32.self))
        let dst = UInt32(bigEndian: base.loadUnaligned(fromByteOffset: 16, as: UInt32.self))
        return IPHeader(
            version: .v4,
            src: IPAddress(v4: src),
            dst: IPAddress(v4: dst),
            nextHeader: base.load(fromByteOffset: 9, as: UInt8.self),
            headerLength: ihl,
            totalLength: length,
            hopLimit: base.load(fromByteOffset: 8, as: UInt8.self),
            dontFragment: frag & 0x4000 != 0,
            identification: UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 4, as: UInt16.self))
        )
    }

    private static func parseIPv6(base: UnsafeRawPointer, count: Int) throws -> IPHeader {
        guard count >= 40 else { throw PacketParseError.truncated }
        let payloadLen = Int(UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 4, as: UInt16.self)))
        let total = payloadLen == 0 ? count : min(40 + payloadLen, count)
        let srcHigh = UInt64(bigEndian: base.loadUnaligned(fromByteOffset: 8, as: UInt64.self))
        let srcLow = UInt64(bigEndian: base.loadUnaligned(fromByteOffset: 16, as: UInt64.self))
        let dstHigh = UInt64(bigEndian: base.loadUnaligned(fromByteOffset: 24, as: UInt64.self))
        let dstLow = UInt64(bigEndian: base.loadUnaligned(fromByteOffset: 32, as: UInt64.self))

        var next = base.load(fromByteOffset: 6, as: UInt8.self)
        var offset = 40
        for _ in 0..<8 {
            switch next {
            case IPProtocolNumber.tcp.rawValue,
                 IPProtocolNumber.udp.rawValue,
                 IPProtocolNumber.icmpv6.rawValue,
                 IPProtocolNumber.icmp.rawValue:
                return IPHeader(
                    version: .v6,
                    src: IPAddress(v6High: srcHigh, v6Low: srcLow),
                    dst: IPAddress(v6High: dstHigh, v6Low: dstLow),
                    nextHeader: next,
                    headerLength: offset,
                    totalLength: total,
                    hopLimit: base.load(fromByteOffset: 7, as: UInt8.self),
                    dontFragment: true,
                    identification: 0
                )
            case 44:
                throw PacketParseError.fragment
            case 0, 43, 60:
                guard count >= offset + 2 else { throw PacketParseError.truncated }
                next = base.load(fromByteOffset: offset, as: UInt8.self)
                let extLen = Int(base.load(fromByteOffset: offset + 1, as: UInt8.self))
                offset += (extLen + 1) * 8
            case 51:
                guard count >= offset + 2 else { throw PacketParseError.truncated }
                next = base.load(fromByteOffset: offset, as: UInt8.self)
                let extLen = Int(base.load(fromByteOffset: offset + 1, as: UInt8.self))
                offset += (extLen + 2) * 4
            default:
                return IPHeader(
                    version: .v6,
                    src: IPAddress(v6High: srcHigh, v6Low: srcLow),
                    dst: IPAddress(v6High: dstHigh, v6Low: dstLow),
                    nextHeader: next,
                    headerLength: offset,
                    totalLength: total,
                    hopLimit: base.load(fromByteOffset: 7, as: UInt8.self),
                    dontFragment: true,
                    identification: 0
                )
            }
            guard offset <= total else { throw PacketParseError.truncated }
        }
        return IPHeader(
            version: .v6,
            src: IPAddress(v6High: srcHigh, v6Low: srcLow),
            dst: IPAddress(v6High: dstHigh, v6Low: dstLow),
            nextHeader: next,
            headerLength: offset,
            totalLength: total,
            hopLimit: base.load(fromByteOffset: 7, as: UInt8.self),
            dontFragment: true,
            identification: 0
        )
    }
}
