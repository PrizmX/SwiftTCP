import Foundation

public enum IPVersion: UInt8, Sendable {
    case v4 = 4
    case v6 = 6
}

public enum IPProtocolNumber: UInt8, Sendable {
    case icmp = 1
    case tcp = 6
    case udp = 17
    case icmpv6 = 58
}

/// Darwin `sa_family_t` values used by `NEPacketTunnelFlow.writePackets`.
public enum AddressFamily: Sendable {
    public static let inet: UInt8 = 2
    public static let inet6: UInt8 = 30

    public static func of(_ version: IPVersion) -> UInt8 {
        version == .v4 ? inet : inet6
    }
}

/// Compact 4-tuple used as the connection identity and EventLoop affinity key.
public struct FlowKey: Hashable, Sendable, CustomStringConvertible {
    public var src: IPAddress
    public var dst: IPAddress
    public var srcPort: UInt16
    public var dstPort: UInt16

    public init(src: IPAddress, srcPort: UInt16, dst: IPAddress, dstPort: UInt16) {
        self.src = src
        self.dst = dst
        self.srcPort = srcPort
        self.dstPort = dstPort
    }

    public var reversed: FlowKey {
        FlowKey(src: dst, srcPort: dstPort, dst: src, dstPort: srcPort)
    }

    /// Stable FNV-1a (not `Hasher`, which is randomized per process).
    public var affinityHash: UInt64 {
        var hash: UInt64 = 0xcbf2_9ce4_8422_2325
        func mix(_ byte: UInt8) {
            hash ^= UInt64(byte)
            hash &*= 0x100_0000_01b3
        }
        src.withBytes { ptr, n in
            for i in 0..<n { mix(ptr[i]) }
        }
        dst.withBytes { ptr, n in
            for i in 0..<n { mix(ptr[i]) }
        }
        mix(UInt8(truncatingIfNeeded: srcPort >> 8))
        mix(UInt8(truncatingIfNeeded: srcPort))
        mix(UInt8(truncatingIfNeeded: dstPort >> 8))
        mix(UInt8(truncatingIfNeeded: dstPort))
        return hash
    }

    public func eventLoopIndex(loopCount: Int) -> Int {
        Int(affinityHash % UInt64(loopCount))
    }

    public var description: String {
        "\(src):\(srcPort) → \(dst):\(dstPort)"
    }
}

public struct IPAddress: Hashable, Sendable, CustomStringConvertible {
    public enum Kind: Sendable, Hashable {
        case v4(UInt32)
        case v6(high: UInt64, low: UInt64)
    }

    public var kind: Kind

    public init(v4: UInt32) {
        self.kind = .v4(v4)
    }

    public init(v6High: UInt64, v6Low: UInt64) {
        self.kind = .v6(high: v6High, low: v6Low)
    }

    public static func v4(octets: (UInt8, UInt8, UInt8, UInt8)) -> IPAddress {
        let v = (UInt32(octets.0) << 24) | (UInt32(octets.1) << 16) | (UInt32(octets.2) << 8) | UInt32(octets.3)
        return IPAddress(v4: v)
    }

    public var version: IPVersion {
        switch kind {
        case .v4: .v4
        case .v6: .v6
        }
    }

    public var description: String {
        switch kind {
        case .v4(let v):
            return "\(v >> 24 & 0xff).\(v >> 16 & 0xff).\(v >> 8 & 0xff).\(v & 0xff)"
        case .v6(let high, let low):
            func hex(_ x: UInt64, shift: Int) -> String {
                String(format: "%04x", UInt16(truncatingIfNeeded: x >> shift))
            }
            return [
                hex(high, shift: 48), hex(high, shift: 32),
                hex(high, shift: 16), hex(high, shift: 0),
                hex(low, shift: 48), hex(low, shift: 32),
                hex(low, shift: 16), hex(low, shift: 0),
            ].joined(separator: ":")
        }
    }

    public func withBytes(_ body: (UnsafePointer<UInt8>, Int) -> Void) {
        switch kind {
        case .v4(let v):
            var be = v.bigEndian
            withUnsafeBytes(of: &be) { raw in
                body(raw.bindMemory(to: UInt8.self).baseAddress!, 4)
            }
        case .v6(let high, let low):
            var words = (high.bigEndian, low.bigEndian)
            withUnsafeBytes(of: &words) { raw in
                body(raw.bindMemory(to: UInt8.self).baseAddress!, 16)
            }
        }
    }

    public func write(to pointer: UnsafeMutableRawPointer) {
        withBytes { src, n in
            pointer.copyMemory(from: src, byteCount: n)
        }
    }
}

