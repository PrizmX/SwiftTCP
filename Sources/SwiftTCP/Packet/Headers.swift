import Foundation

public struct TCPFlags: OptionSet, Sendable, Hashable, CustomStringConvertible {
    public let rawValue: UInt8

    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let fin = TCPFlags(rawValue: 1 << 0)
    public static let syn = TCPFlags(rawValue: 1 << 1)
    public static let rst = TCPFlags(rawValue: 1 << 2)
    public static let psh = TCPFlags(rawValue: 1 << 3)
    public static let ack = TCPFlags(rawValue: 1 << 4)
    public static let urg = TCPFlags(rawValue: 1 << 5)
    public static let ece = TCPFlags(rawValue: 1 << 6)
    public static let cwr = TCPFlags(rawValue: 1 << 7)

    public var description: String {
        var parts: [String] = []
        if contains(.fin) { parts.append("FIN") }
        if contains(.syn) { parts.append("SYN") }
        if contains(.rst) { parts.append("RST") }
        if contains(.psh) { parts.append("PSH") }
        if contains(.ack) { parts.append("ACK") }
        if contains(.urg) { parts.append("URG") }
        return parts.isEmpty ? "-" : parts.joined(separator: "|")
    }
}

public struct SACKBlock: Sendable, Equatable {
    public var left: UInt32
    public var right: UInt32

    public init(left: UInt32, right: UInt32) {
        self.left = left
        self.right = right
    }
}

public struct TCPOptions: Sendable, Equatable {
    public var mss: UInt16?
    public var windowScale: UInt8?
    public var sackPermitted: Bool
    public var tfoCookie: Data?
    public var sackBlocks: [SACKBlock]

    public static let empty = TCPOptions(mss: nil, windowScale: nil, sackPermitted: false, tfoCookie: nil)

    public init(
        mss: UInt16?,
        windowScale: UInt8?,
        sackPermitted: Bool,
        tfoCookie: Data?,
        sackBlocks: [SACKBlock] = []
    ) {
        self.mss = mss
        self.windowScale = windowScale
        self.sackPermitted = sackPermitted
        self.tfoCookie = tfoCookie
        self.sackBlocks = sackBlocks
    }

    /// Parse TCP options without allocating a buffer for unknown kinds.
    public static func parse(bytes: UnsafeRawBufferPointer) -> TCPOptions {
        var mss: UInt16?
        var windowScale: UInt8?
        var sackPermitted = false
        var tfoCookie: Data?
        var sackBlocks: [SACKBlock] = []
        var i = 0
        while i < bytes.count {
            let kind = bytes[i]
            switch kind {
            case 0: // EOL
                i = bytes.count
            case 1: // NOP
                i += 1
            default:
                guard i + 1 < bytes.count else {
                    return TCPOptions(mss: mss, windowScale: windowScale, sackPermitted: sackPermitted, tfoCookie: tfoCookie, sackBlocks: sackBlocks)
                }
                let len = Int(bytes[i + 1])
                guard len >= 2, i + len <= bytes.count else {
                    return TCPOptions(mss: mss, windowScale: windowScale, sackPermitted: sackPermitted, tfoCookie: tfoCookie, sackBlocks: sackBlocks)
                }
                switch kind {
                case 2 where len == 4:
                    mss = UInt16(bytes[i + 2]) << 8 | UInt16(bytes[i + 3])
                case 3 where len == 3:
                    windowScale = min(bytes[i + 2], 14)
                case 4 where len == 2:
                    sackPermitted = true
                case 5 where len >= 2 && (len - 2).isMultiple(of: 8):
                    var blocks: [SACKBlock] = []
                    var o = i + 2
                    while o + 8 <= i + len, blocks.count < 4 {
                        blocks.append(SACKBlock(left: loadBE32(bytes, at: o), right: loadBE32(bytes, at: o + 4)))
                        o += 8
                    }
                    sackBlocks = blocks
                case 34 where len >= 2:
                    tfoCookie = Data(bytes[i + 2..<i + len])
                default:
                    break
                }
                i += len
            }
        }
        return TCPOptions(mss: mss, windowScale: windowScale, sackPermitted: sackPermitted, tfoCookie: tfoCookie, sackBlocks: sackBlocks)
    }

    public func encoded() -> Data {
        var out = Data()
        if let mss {
            out.append(contentsOf: [2, 4, UInt8(mss >> 8), UInt8(truncatingIfNeeded: mss)])
        }
        if let windowScale {
            out.append(contentsOf: [3, 3, windowScale])
        }
        if sackPermitted {
            out.append(contentsOf: [4, 2])
        }
        let nSACK = min(4, sackBlocks.count)
        if nSACK > 0 {
            out.append(5)
            out.append(UInt8(2 + nSACK * 8))
            for block in sackBlocks.prefix(nSACK) {
                appendBE32(block.left, to: &out)
                appendBE32(block.right, to: &out)
            }
        }
        if let tfoCookie {
            out.append(34)
            out.append(UInt8(2 + tfoCookie.count))
            out.append(tfoCookie)
        }
        while out.count % 4 != 0 {
            out.append(1) // NOP pad
        }
        return out
    }
}

private func loadBE32(_ bytes: UnsafeRawBufferPointer, at offset: Int) -> UInt32 {
    UInt32(bytes[offset]) << 24
        | UInt32(bytes[offset + 1]) << 16
        | UInt32(bytes[offset + 2]) << 8
        | UInt32(bytes[offset + 3])
}

private func appendBE32(_ value: UInt32, to data: inout Data) {
    var be = value.bigEndian
    Swift.withUnsafeBytes(of: &be) { data.append(contentsOf: $0) }
}

public struct TCPSegment: Sendable {
    public var flow: FlowKey
    public var seq: UInt32
    public var ack: UInt32
    public var flags: TCPFlags
    public var window: UInt16
    public var dataOffset: Int
    public var payloadOffset: Int
    public var payloadLength: Int
    public var options: TCPOptions
    public var ipHeaderLength: Int
    public var version: IPVersion

    public var hasSYN: Bool { flags.contains(.syn) }
    public var hasACK: Bool { flags.contains(.ack) }
    public var hasFIN: Bool { flags.contains(.fin) }
    public var hasRST: Bool { flags.contains(.rst) }
    public var hasTFO: Bool { options.tfoCookie != nil || (hasSYN && payloadLength > 0) }

    public var endSeq: UInt32 {
        var n = UInt32(payloadLength)
        if hasSYN { n += 1 }
        if hasFIN { n += 1 }
        return seq &+ n
    }
}

public enum PacketParseError: Error, Sendable {
    case truncated
    case unsupportedVersion
    case notTCP
    case badHeaderLength
    case fragment
}
