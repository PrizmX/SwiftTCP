import Foundation

/// Copyable RX slice. Bytes stay in `PacketStorage`; trim is pointer arithmetic.
public struct TCPSlice: Sendable {
    public var storage: PacketStorage
    public var start: Int
    public var count: Int

    @inlinable
    public var isEmpty: Bool { count == 0 }

    public init(wrapping data: Data) {
        self.storage = PacketStorage(wrapping: data)
        self.start = 0
        self.count = data.count
    }

    @inlinable
    public mutating func trimLeft(_ n: Int) {
        let k = min(max(n, 0), count)
        start += k
        count -= k
    }

    @inlinable
    public mutating func trimRight(_ n: Int) {
        count -= min(max(n, 0), count)
    }

    @inlinable
    public borrowing func withUnsafeBytes<R>(
        _ body: (UnsafeRawBufferPointer) throws -> R
    ) rethrows -> R {
        try body(UnsafeRawBufferPointer(start: storage.pointer.advanced(by: start), count: count))
    }

    public borrowing func asSharedData() -> Data {
        let base = storage.pointer.advanced(by: start)
        let n = count
        let storage = self.storage
        return Data(bytesNoCopy: base, count: n, deallocator: .custom { [storage] _, _ in
            _ = storage
        })
    }
}

/// Out-of-order receive queue. Segments are clipped to `[rcvNxt, rcvNxt+rcvWnd)`,
/// overlaps are trimmed in place (new bytes win), and both hole-count and byte
/// caps bound memory without coalescing copies.
public struct TCPReassembly: Sendable {
    public struct Hole: Sendable {
        public var seq: UInt32
        public var slice: TCPSlice

        public var end: UInt32 { seq &+ UInt32(slice.count) }

        public var data: Data { slice.asSharedData() }

        public init(seq: UInt32, slice: TCPSlice) {
            self.seq = seq
            self.slice = slice
        }
    }

    public static let defaultMaxBytes = 256 * 1024

    public private(set) var holes: [Hole] = []
    public private(set) var pendingFin: UInt32?
    /// Most recently queued segment; RFC 2018 first SACK block prefers this region.
    public private(set) var lastSACK: SACKBlock?
    public private(set) var storedBytes: Int = 0

    public let maxHoles: Int
    public let maxBytes: Int

    public init(maxHoles: Int = 32, maxBytes: Int = TCPReassembly.defaultMaxBytes) {
        self.maxHoles = max(1, maxHoles)
        self.maxBytes = max(1, maxBytes)
    }

    public var holeCount: Int { holes.count }

    /// Number of discontiguous filled regions (SACK blocks / `maxHoles` unit).
    public var regionCount: Int {
        guard !holes.isEmpty else { return 0 }
        var n = 1
        for i in 1..<holes.count {
            if holes[i].seq != holes[i - 1].end { n += 1 }
        }
        return n
    }

    public var isEmpty: Bool { holes.isEmpty && pendingFin == nil }

    public mutating func clear() {
        holes.removeAll(keepingCapacity: true)
        pendingFin = nil
        lastSACK = nil
        storedBytes = 0
    }

    /// RFC 2018: first block is the most recent contiguous region, then others, max 4.
    public func sackBlocks(limit: Int = 4) -> [SACKBlock] {
        var regions: [SACKBlock] = []
        for h in holes {
            if var last = regions.last, last.right == h.seq {
                last.right = h.end
                regions[regions.count - 1] = last
            } else {
                regions.append(SACKBlock(left: h.seq, right: h.end))
            }
        }
        guard !regions.isEmpty else { return [] }
        var out: [SACKBlock] = []
        out.reserveCapacity(min(limit, regions.count))
        if let lastSACK {
            if let recent = regions.first(where: {
                Seq.leq($0.left, lastSACK.left) && Seq.lt(lastSACK.left, $0.right)
            }) {
                out.append(recent)
            }
        }
        for region in regions where out.count < limit {
            if out.contains(region) { continue }
            out.append(region)
        }
        return out
    }

    /// Queue payload. Bytes left of `rcvNxt` or right of the window are trimmed.
    /// Incoming data overwrites overlaps. Returns whether any bytes were kept as OOO.
    @discardableResult
    public mutating func insert(seq: UInt32, data: Data, rcvNxt: UInt32, rcvWnd: UInt32) -> Bool {
        discardStale(before: rcvNxt)
        guard let incoming = clipped(seq: seq, data: data, rcvNxt: rcvNxt, rcvWnd: rcvWnd) else {
            return false
        }
        let added = incoming.slice.count - overlapBytes(incoming)
        if storedBytes + max(0, added) > maxBytes {
            return false
        }
        let joins = holes.contains { overlapsOrAdjacent($0, incoming) }
        if !joins, regionCount >= maxHoles {
            return false
        }
        subtractOverlaps(incoming)
        storedBytes += incoming.slice.count
        lastSACK = SACKBlock(left: incoming.seq, right: incoming.end)
        let idx = holes.firstIndex { Seq.lt(incoming.seq, $0.seq) } ?? holes.count
        holes.insert(incoming, at: idx)
        return true
    }

    /// Pop up to `maxBytes` of contiguous data starting at `rcvNxt`.
    public mutating func take(from rcvNxt: UInt32, maxBytes: Int) -> Data {
        guard maxBytes > 0 else { return Data() }
        var out = Data()
        out.reserveCapacity(min(maxBytes, storedBytes))
        _ = take(from: rcvNxt, maxBytes: maxBytes) { bytes in
            let n = min(bytes.count, maxBytes - out.count)
            if n > 0, let base = bytes.baseAddress {
                out.append(base.assumingMemoryBound(to: UInt8.self), count: n)
            }
            return n
        }
        return out
    }

    /// Copy contiguous bytes into `dest`. Partial writes leave the remainder queued.
    @discardableResult
    public mutating func take(from rcvNxt: UInt32, maxBytes: Int, into dest: ByteRingBuffer) -> Int {
        take(from: rcvNxt, maxBytes: maxBytes) { dest.write($0) }
    }

    public mutating func offerFIN(_ seq: UInt32, rcvNxt: UInt32, rcvWnd: UInt32) {
        if Seq.lt(seq, rcvNxt) { return }
        if rcvWnd == 0 {
            guard seq == rcvNxt else { return }
        } else if !Seq.leq(rcvNxt, seq) || !Seq.lt(seq, rcvNxt &+ rcvWnd) {
            return
        }
        if pendingFin == nil {
            pendingFin = seq
        }
    }

    public mutating func takeFIN(rcvNxt: UInt32) -> Bool {
        guard pendingFin == rcvNxt else { return false }
        pendingFin = nil
        return true
    }

    @discardableResult
    mutating func take(
        from rcvNxt: UInt32,
        maxBytes: Int,
        write: (UnsafeRawBufferPointer) -> Int
    ) -> Int {
        var nxt = rcvNxt
        var copied = 0
        while copied < maxBytes {
            discardStale(before: nxt)
            guard var first = holes.first else { break }
            if Seq.lt(first.seq, nxt) {
                let skip = Int(nxt &- first.seq)
                let trimmed = min(skip, first.slice.count)
                storedBytes -= trimmed
                first.slice.trimLeft(skip)
                first.seq = nxt
                if first.slice.isEmpty {
                    holes.removeFirst()
                    continue
                }
                holes[0] = first
            }
            guard holes[0].seq == nxt else { break }
            first = holes[0]
            let nWant = min(maxBytes - copied, first.slice.count)
            let written = first.slice.withUnsafeBytes { raw in
                let slice = UnsafeRawBufferPointer(start: raw.baseAddress, count: nWant)
                return write(slice)
            }
            let n = min(max(written, 0), nWant)
            storedBytes -= n
            copied += n
            nxt &+= UInt32(n)
            if n == first.slice.count {
                holes.removeFirst()
            } else {
                first.slice.trimLeft(n)
                first.seq = nxt
                holes[0] = first
                break
            }
        }
        return copied
    }

    private mutating func discardStale(before nxt: UInt32) {
        while let first = holes.first, Seq.leq(first.end, nxt) {
            storedBytes -= first.slice.count
            holes.removeFirst()
        }
    }

    private mutating func subtractOverlaps(_ incoming: Hole) {
        var i = 0
        while i < holes.count {
            var existing = holes[i]
            if Seq.leq(existing.end, incoming.seq) || Seq.leq(incoming.end, existing.seq) {
                i += 1
                continue
            }
            let leftRemains = Seq.lt(existing.seq, incoming.seq)
            let rightRemains = Seq.lt(incoming.end, existing.end)
            if leftRemains && rightRemains {
                let leftLen = Int(incoming.seq &- existing.seq)
                var right = existing
                right.slice.trimLeft(Int(incoming.end &- existing.seq))
                right.seq = incoming.end
                storedBytes -= existing.slice.count - leftLen - right.slice.count
                existing.slice.trimRight(existing.slice.count - leftLen)
                holes[i] = existing
                if !right.slice.isEmpty {
                    holes.insert(right, at: i + 1)
                    i += 2
                } else {
                    i += 1
                }
                continue
            }
            if leftRemains {
                let keep = Int(incoming.seq &- existing.seq)
                storedBytes -= existing.slice.count - keep
                existing.slice.trimRight(existing.slice.count - keep)
                if existing.slice.isEmpty {
                    holes.remove(at: i)
                } else {
                    holes[i] = existing
                    i += 1
                }
                continue
            }
            if rightRemains {
                let skip = Int(incoming.end &- existing.seq)
                storedBytes -= skip
                existing.slice.trimLeft(skip)
                existing.seq = incoming.end
                if existing.slice.isEmpty {
                    holes.remove(at: i)
                } else {
                    holes[i] = existing
                    i += 1
                }
                continue
            }
            storedBytes -= existing.slice.count
            holes.remove(at: i)
        }
    }

    private func overlapBytes(_ hole: Hole) -> Int {
        var n = 0
        for existing in holes {
            let left = Seq.lt(existing.seq, hole.seq) ? hole.seq : existing.seq
            let right = Seq.lt(existing.end, hole.end) ? existing.end : hole.end
            if Seq.lt(left, right) {
                n += Int(right &- left)
            }
        }
        return n
    }

    private func overlapsOrAdjacent(_ a: Hole, _ b: Hole) -> Bool {
        !Seq.lt(a.end, b.seq) && !Seq.lt(b.end, a.seq)
    }

    private func clipped(seq: UInt32, data: Data, rcvNxt: UInt32, rcvWnd: UInt32) -> Hole? {
        guard !data.isEmpty, rcvWnd > 0 else { return nil }
        var slice = TCPSlice(wrapping: data)
        var start = seq
        if Seq.lt(start, rcvNxt) {
            let skip = Int(rcvNxt &- start)
            if skip >= slice.count { return nil }
            slice.trimLeft(skip)
            start = rcvNxt
        }
        let wndEnd = rcvNxt &+ rcvWnd
        if !Seq.lt(start, wndEnd) { return nil }
        let maxLen = Int(wndEnd &- start)
        if slice.count > maxLen {
            slice.trimRight(slice.count - maxLen)
        }
        guard !slice.isEmpty else { return nil }
        return Hole(seq: start, slice: slice)
    }
}
