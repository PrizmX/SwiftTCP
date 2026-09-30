import Foundation
import os

/// IPv4 fragment reassembly (RFC 791) for the demuxer.
///
/// Bounded on every axis a sender controls: datagrams in flight, bytes held,
/// and time. Overlapping fragments drop the whole datagram (the RFC 5722
/// policy, applied to IPv4) so crafted overlaps cannot rewrite bytes that
/// were already accepted.
final class IPv4Reassembler: Sendable {
    enum Outcome: Sendable, Equatable {
        /// Buffered; the datagram is not complete yet.
        case pending
        /// The reassembled datagram (fragment fields cleared, checksum fixed).
        case complete(Data)
        /// Fragments discarded: malformed, overlapping, over a limit, or
        /// expired in-flight datagrams.
        case dropped(Int)
    }

    struct Limits: Sendable {
        var maxDatagrams = 64
        var maxBytes = 1 << 20
        var timeout: Duration = .seconds(30)
    }

    private struct Key: Hashable, Sendable {
        var src: UInt32
        var dst: UInt32
        var proto: UInt8
        var id: UInt16
    }

    private struct Piece: Sendable {
        var offset: Int
        var data: Data
        var end: Int { offset + data.count }
    }

    private struct Datagram: Sendable {
        var created: ContinuousClock.Instant
        var header: Data?
        var pieces: [Piece] = []
        var received = 0
        /// Payload length, known once the last fragment (MF = 0) arrives.
        var total: Int?
    }

    private struct State: Sendable {
        var datagrams: [Key: Datagram] = [:]
        var bytes = 0
    }

    private let limits: Limits
    private let clock: @Sendable () -> ContinuousClock.Instant
    private let state = OSAllocatedUnfairLock(initialState: State())

    init(
        limits: Limits = Limits(),
        clock: @escaping @Sendable () -> ContinuousClock.Instant = { ContinuousClock.now }
    ) {
        self.limits = limits
        self.clock = clock
    }

    var inFlight: Int {
        state.withLock { $0.datagrams.count }
    }

    /// Feeds one IPv4 fragment (offset != 0 or MF set).
    func add(_ packet: Data) -> Outcome {
        guard let fragment = Self.parse(packet) else { return .dropped(1) }
        let now = clock()
        return state.withLock { state -> Outcome in
            var dropped = expire(&state, now: now)
            let key = fragment.key
            var datagram: Datagram
            if let existing = state.datagrams[key] {
                datagram = existing
            } else {
                if state.datagrams.count >= limits.maxDatagrams {
                    dropped += evictOldest(&state)
                }
                datagram = Datagram(created: now)
            }

            let piece = Piece(offset: fragment.offset, data: fragment.payload)
            if let duplicate = datagram.pieces.first(where: { $0.offset == piece.offset }),
               duplicate.data == piece.data
            {
                return dropped > 0 ? .dropped(dropped) : .pending
            }
            let overlaps = datagram.pieces.contains { $0.offset < piece.end && piece.offset < $0.end }
            let pastEnd = datagram.total.map { piece.end > $0 } ?? false
            let conflictingEnd = !fragment.moreFragments
                && (datagram.total.map { $0 != piece.end } ?? false
                    || datagram.pieces.contains { $0.end > piece.end })
            if overlaps || pastEnd || conflictingEnd
                || state.bytes + piece.data.count > limits.maxBytes
            {
                return .dropped(dropped + discard(key, from: &state) + 1)
            }

            if !fragment.moreFragments { datagram.total = piece.end }
            if piece.offset == 0 { datagram.header = fragment.header }
            let index = datagram.pieces.firstIndex { $0.offset > piece.offset } ?? datagram.pieces.count
            datagram.pieces.insert(piece, at: index)
            datagram.received += piece.data.count
            state.bytes += piece.data.count

            // No overlaps are ever stored, so byte count == coverage.
            if let total = datagram.total, let header = datagram.header, datagram.received == total {
                state.datagrams[key] = nil
                state.bytes -= datagram.received
                return .complete(Self.assemble(header: header, pieces: datagram.pieces, total: total))
            }
            state.datagrams[key] = datagram
            return dropped > 0 ? .dropped(dropped) : .pending
        }
    }

    // MARK: - Internals

    private struct Fragment {
        var key: Key
        var header: Data
        var offset: Int
        var moreFragments: Bool
        var payload: Data
    }

    private static func parse(_ packet: Data) -> Fragment? {
        packet.withUnsafeBytes { raw -> Fragment? in
            guard raw.count >= 20, raw[0] >> 4 == 4 else { return nil }
            let ihl = Int(raw[0] & 0x0f) * 4
            guard ihl >= 20, raw.count >= ihl else { return nil }
            let total = Int(raw[2]) << 8 | Int(raw[3])
            let length = total == 0 ? raw.count : min(total, raw.count)
            guard length > ihl else { return nil }
            let field = UInt16(raw[6]) << 8 | UInt16(raw[7])
            let offset = Int(field & 0x1fff) * 8
            let more = field & 0x2000 != 0
            let payloadCount = length - ihl
            // Non-final fragments carry multiples of 8 bytes; the datagram
            // (header included) must fit the 16-bit total length.
            guard !more || payloadCount % 8 == 0, ihl + offset + payloadCount <= 0xffff else {
                return nil
            }
            func word(_ at: Int) -> UInt32 {
                UInt32(raw[at]) << 24 | UInt32(raw[at + 1]) << 16 | UInt32(raw[at + 2]) << 8 | UInt32(raw[at + 3])
            }
            let key = Key(
                src: word(12),
                dst: word(16),
                proto: raw[9],
                id: UInt16(raw[4]) << 8 | UInt16(raw[5])
            )
            return Fragment(
                key: key,
                header: Data(raw[0..<ihl]),
                offset: offset,
                moreFragments: more,
                // Own copy: a held fragment must not pin the TUN read buffer.
                payload: Data(raw[ihl..<length])
            )
        }
    }

    private static func assemble(header: Data, pieces: [Piece], total: Int) -> Data {
        var bytes = [UInt8](header)
        let length = bytes.count + total
        bytes[2] = UInt8(length >> 8)
        bytes[3] = UInt8(length & 0xff)
        bytes[6] = 0
        bytes[7] = 0
        bytes[10] = 0
        bytes[11] = 0
        var sum: UInt32 = 0
        for index in stride(from: 0, to: bytes.count, by: 2) {
            sum &+= UInt32(bytes[index]) << 8 | UInt32(bytes[index + 1])
        }
        while sum >> 16 != 0 { sum = (sum & 0xffff) &+ (sum >> 16) }
        let checksum = ~UInt16(sum)
        bytes[10] = UInt8(checksum >> 8)
        bytes[11] = UInt8(checksum & 0xff)
        var out = Data(capacity: length)
        out.append(contentsOf: bytes)
        for piece in pieces { out.append(piece.data) }
        return out
    }

    private func expire(_ state: inout State, now: ContinuousClock.Instant) -> Int {
        let stale = state.datagrams.filter { now - $0.value.created >= limits.timeout }.map(\.key)
        return stale.reduce(0) { $0 + discard($1, from: &state) }
    }

    private func evictOldest(_ state: inout State) -> Int {
        guard let oldest = state.datagrams.min(by: { $0.value.created < $1.value.created })?.key else {
            return 0
        }
        return discard(oldest, from: &state)
    }

    /// Removes a datagram; returns how many fragments it held.
    private func discard(_ key: Key, from state: inout State) -> Int {
        guard let datagram = state.datagrams.removeValue(forKey: key) else { return 0 }
        state.bytes -= datagram.received
        return datagram.pieces.count
    }
}
