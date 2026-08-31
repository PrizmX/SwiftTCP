import Foundation

/// Shared IPv4/IPv6 header writer used by UDP and ICMP TX paths.
enum IPWire {
    static func appendIPv4(
        _ buffer: inout PacketBuffer,
        src: UInt32,
        dst: UInt32,
        total: Int,
        proto: UInt8,
        ttl: UInt8 = 64,
        df: Bool = true,
        id: UInt16 = 0
    ) {
        buffer.append(networkOrder: UInt8(0x45))
        buffer.append(networkOrder: UInt8(0))
        buffer.append(networkOrder: UInt16(total))
        buffer.append(networkOrder: id)
        buffer.append(networkOrder: UInt16(df ? 0x4000 : 0))
        buffer.append(networkOrder: ttl)
        buffer.append(networkOrder: proto)
        buffer.append(networkOrder: UInt16(0))
        buffer.append(networkOrder: src)
        buffer.append(networkOrder: dst)
    }

    static func appendIPv6(
        _ buffer: inout PacketBuffer,
        srcHigh: UInt64, srcLow: UInt64,
        dstHigh: UInt64, dstLow: UInt64,
        payloadLen: Int,
        nextHeader: UInt8,
        hopLimit: UInt8 = 64
    ) {
        buffer.append(networkOrder: UInt8(0x60))
        buffer.append(networkOrder: UInt8(0))
        buffer.append(networkOrder: UInt16(0))
        buffer.append(networkOrder: UInt16(payloadLen))
        buffer.append(networkOrder: nextHeader)
        buffer.append(networkOrder: hopLimit)
        var srcHighBE = srcHigh.bigEndian
        var srcLowBE = srcLow.bigEndian
        var dstHighBE = dstHigh.bigEndian
        var dstLowBE = dstLow.bigEndian
        withUnsafeBytes(of: &srcHighBE) { buffer.append(UnsafeRawBufferPointer($0)) }
        withUnsafeBytes(of: &srcLowBE) { buffer.append(UnsafeRawBufferPointer($0)) }
        withUnsafeBytes(of: &dstHighBE) { buffer.append(UnsafeRawBufferPointer($0)) }
        withUnsafeBytes(of: &dstLowBE) { buffer.append(UnsafeRawBufferPointer($0)) }
    }

    static func fillIPv4HeaderChecksum(_ buffer: inout PacketBuffer) {
        buffer.withUnsafeMutableBytes { raw in
            raw.storeBytes(of: UInt16(0).bigEndian, toByteOffset: 10, as: UInt16.self)
            let sum = InternetChecksum.compute(bytes: UnsafeRawBufferPointer(start: raw.baseAddress, count: 20))
            raw.storeBytes(of: sum.bigEndian, toByteOffset: 10, as: UInt16.self)
        }
    }

    static func v4(_ address: IPAddress) -> UInt32 {
        guard case .v4(let v) = address.kind else {
            preconditionFailure("IPv4 address required")
        }
        return v
    }

    static func v6(_ address: IPAddress) -> (UInt64, UInt64) {
        guard case .v6(let high, let low) = address.kind else {
            preconditionFailure("IPv6 address required")
        }
        return (high, low)
    }
}
