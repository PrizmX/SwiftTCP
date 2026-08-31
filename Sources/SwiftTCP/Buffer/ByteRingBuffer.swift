import Foundation

/// Isolated to a single EventLoop; not shared across threads.
///
/// Capacity is a power of two. Storage is **not** zero-filled: only `stored`
/// bytes are ever read, so skipping `memset` keeps idle pages off RSS.
public final class ByteRingBuffer: @unchecked Sendable {
    @usableFromInline
    var storage: UnsafeMutableRawBufferPointer

    @usableFromInline
    var head: Int = 0

    @usableFromInline
    var stored: Int = 0

    public private(set) var capacity: Int

    public init(capacity: Int) {
        precondition(capacity > 0 && capacity.nonzeroBitCount == 1, "capacity must be a power of two")
        self.capacity = capacity
        self.storage = UnsafeMutableRawBufferPointer.allocate(
            byteCount: capacity,
            alignment: MemoryLayout<UInt64>.alignment
        )
    }

    deinit {
        storage.deallocate()
    }

    @inlinable
    public var count: Int { stored }

    @inlinable
    public var available: Int { capacity - stored }

    @inlinable
    public var isEmpty: Bool { stored == 0 }

    /// Copy in-use bytes into a larger ring. `head` resets to 0.
    public func grow(to newCapacity: Int) {
        precondition(newCapacity > 0 && newCapacity.nonzeroBitCount == 1, "capacity must be a power of two")
        guard newCapacity > capacity else { return }
        let grown = UnsafeMutableRawBufferPointer.allocate(
            byteCount: newCapacity,
            alignment: MemoryLayout<UInt64>.alignment
        )
        if stored > 0, let dst = grown.baseAddress, let src = storage.baseAddress {
            let first = min(stored, capacity - head)
            dst.copyMemory(from: src.advanced(by: head), byteCount: first)
            if stored > first {
                dst.advanced(by: first).copyMemory(from: src, byteCount: stored - first)
            }
        }
        storage.deallocate()
        storage = grown
        capacity = newCapacity
        head = 0
    }

    @discardableResult
    public func write(_ bytes: UnsafeRawBufferPointer) -> Int {
        let n = min(bytes.count, available)
        guard n > 0, let src = bytes.baseAddress else { return 0 }
        let tail = (head + stored) & (capacity - 1)
        let first = min(n, capacity - tail)
        storage.baseAddress!.advanced(by: tail).copyMemory(from: src, byteCount: first)
        if n > first {
            storage.baseAddress!.copyMemory(from: src.advanced(by: first), byteCount: n - first)
        }
        stored += n
        return n
    }

    @discardableResult
    public func write(_ data: Data) -> Int {
        data.withUnsafeBytes { write($0) }
    }

    @discardableResult
    public func read(into dest: UnsafeMutableRawBufferPointer) -> Int {
        let n = min(dest.count, stored)
        guard n > 0, let dst = dest.baseAddress else { return 0 }
        let first = min(n, capacity - head)
        dst.copyMemory(from: storage.baseAddress!.advanced(by: head), byteCount: first)
        if n > first {
            dst.advanced(by: first).copyMemory(from: storage.baseAddress!, byteCount: n - first)
        }
        head = (head + n) & (capacity - 1)
        stored -= n
        return n
    }

    public func peek(_ maxCount: Int) -> Data {
        peek(offset: 0, maxCount: maxCount)
    }

    /// Peek `maxCount` bytes starting `offset` bytes from the unread head.
    public func peek(offset: Int, maxCount: Int) -> Data {
        let start = min(max(offset, 0), stored)
        let n = min(maxCount, stored - start)
        guard n > 0 else { return Data() }
        var out = Data(count: n)
        withUnsafeRegions(offset: start, maxCount: n) { a, b in
            out.withUnsafeMutableBytes { dest in
                dest.copyMemory(from: a)
                if b.count > 0 {
                    dest.baseAddress!.advanced(by: a.count).copyMemory(from: b.baseAddress!, byteCount: b.count)
                }
            }
        }
        return out
    }

    /// Two contiguous physical spans covering `offset..<offset+n` (second may be empty).
    @inlinable
    public func withUnsafeRegions<R>(
        offset: Int,
        maxCount: Int,
        _ body: (UnsafeRawBufferPointer, UnsafeRawBufferPointer) throws -> R
    ) rethrows -> R {
        let start = min(max(offset, 0), stored)
        let n = min(maxCount, stored - start)
        let empty = UnsafeRawBufferPointer(start: nil, count: 0)
        guard n > 0, let base = storage.baseAddress else {
            return try body(empty, empty)
        }
        let physical = (head + start) & (capacity - 1)
        let first = min(n, capacity - physical)
        let a = UnsafeRawBufferPointer(start: base.advanced(by: physical), count: first)
        let b = n > first
            ? UnsafeRawBufferPointer(start: base, count: n - first)
            : empty
        return try body(a, b)
    }

    public func consume(_ n: Int) {
        let k = min(n, stored)
        head = (head + k) & (capacity - 1)
        stored -= k
    }

    public func clear() {
        head = 0
        stored = 0
    }
}

extension Int {
    var nextPowerOfTwo: Int {
        guard self > 1 else { return 2 }
        return 1 << (Int.bitWidth - (self - 1).leadingZeroBitCount)
    }
}
