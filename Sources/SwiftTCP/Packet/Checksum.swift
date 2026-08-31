/// RFC 1071 internet checksum. Operates on borrowed bytes; no allocation.
public enum InternetChecksum: Sendable {
    public static func sum(bytes: UnsafeRawBufferPointer) -> UInt32 {
        var acc: UInt32 = 0
        var i = 0
        let n = bytes.count
        while i + 1 < n {
            acc += UInt32(bytes[i]) << 8 | UInt32(bytes[i + 1])
            i += 2
        }
        if i < n {
            acc += UInt32(bytes[i]) << 8
        }
        return acc
    }

    public static func fold(_ acc: UInt32) -> UInt16 {
        var x = acc
        while x > 0xffff {
            x = (x >> 16) + (x & 0xffff)
        }
        return ~UInt16(truncatingIfNeeded: x)
    }

    public static func compute(bytes: UnsafeRawBufferPointer) -> UInt16 {
        fold(sum(bytes: bytes))
    }

    /// Transport checksum (TCP / UDP / ICMPv6) with IPv4 pseudo-header.
    public static func transportIPv4(
        src: UInt32,
        dst: UInt32,
        proto: UInt8,
        length: Int,
        headerAndPayload: UnsafeRawBufferPointer
    ) -> UInt16 {
        var acc: UInt32 = 0
        acc += src >> 16
        acc += src & 0xffff
        acc += dst >> 16
        acc += dst & 0xffff
        acc += UInt32(proto)
        acc += UInt32(length)
        acc += sum(bytes: headerAndPayload)
        let folded = fold(acc)
        return folded == 0 && proto == IPProtocolNumber.udp.rawValue ? 0xffff : folded
    }

    /// Transport checksum with IPv6 pseudo-header (RFC 2460).
    public static func transportIPv6(
        srcHigh: UInt64,
        srcLow: UInt64,
        dstHigh: UInt64,
        dstLow: UInt64,
        proto: UInt8,
        length: Int,
        headerAndPayload: UnsafeRawBufferPointer
    ) -> UInt16 {
        var acc: UInt32 = 0
        func add64(_ v: UInt64) {
            acc += UInt32(truncatingIfNeeded: v >> 48)
            acc += UInt32(truncatingIfNeeded: v >> 32) & 0xffff
            acc += UInt32(truncatingIfNeeded: v >> 16) & 0xffff
            acc += UInt32(truncatingIfNeeded: v) & 0xffff
        }
        add64(srcHigh)
        add64(srcLow)
        add64(dstHigh)
        add64(dstLow)
        acc += UInt32(length) >> 16
        acc += UInt32(length) & 0xffff
        acc += UInt32(proto)
        acc += sum(bytes: headerAndPayload)
        let folded = fold(acc)
        return folded == 0 && proto == IPProtocolNumber.udp.rawValue ? 0xffff : folded
    }

    public static func tcpIPv4(
        src: UInt32,
        dst: UInt32,
        tcpLength: Int,
        headerAndPayload: UnsafeRawBufferPointer
    ) -> UInt16 {
        transportIPv4(src: src, dst: dst, proto: IPProtocolNumber.tcp.rawValue, length: tcpLength, headerAndPayload: headerAndPayload)
    }

    public static func tcpIPv6(
        srcHigh: UInt64,
        srcLow: UInt64,
        dstHigh: UInt64,
        dstLow: UInt64,
        tcpLength: Int,
        headerAndPayload: UnsafeRawBufferPointer
    ) -> UInt16 {
        transportIPv6(
            srcHigh: srcHigh, srcLow: srcLow,
            dstHigh: dstHigh, dstLow: dstLow,
            proto: IPProtocolNumber.tcp.rawValue,
            length: tcpLength,
            headerAndPayload: headerAndPayload
        )
    }
}
