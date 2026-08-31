import Foundation

/// Shared backing store. Slices retain this object (ARC on the handle only);
/// packet bytes are never copied.
public final class PacketStorage: @unchecked Sendable {
    @usableFromInline
    let pointer: UnsafeMutableRawPointer

    @usableFromInline
    let capacity: Int

    @usableFromInline
    let kind: Kind

    @usableFromInline
    enum Kind: @unchecked Sendable {
        case malloc
        case nsdata(NSData)
        case pooled(TXBufferPool)
    }

    public init(capacity: Int) {
        precondition(capacity > 0)
        self.pointer = UnsafeMutableRawPointer.allocate(
            byteCount: capacity,
            alignment: MemoryLayout<UInt64>.alignment
        )
        self.capacity = capacity
        self.kind = .malloc
    }

    public init(wrapping data: Data) {
        let ns = data as NSData
        self.pointer = UnsafeMutableRawPointer(mutating: ns.bytes)
        self.capacity = ns.length
        self.kind = .nsdata(ns)
    }

    init(pooled pointer: UnsafeMutableRawPointer, capacity: Int, pool: TXBufferPool) {
        self.pointer = pointer
        self.capacity = capacity
        self.kind = .pooled(pool)
    }

    deinit {
        switch kind {
        case .malloc:
            pointer.deallocate()
        case .nsdata:
            break
        case .pooled(let pool):
            pool.recycle(pointer)
        }
    }
}

/// Per-EventLoop slab recycler for TX `PacketStorage`. In-flight `Data` retains
/// the storage (and thus the pool), so recycling is safe after the loop closes.
public final class TXBufferPool: @unchecked Sendable {
    private var free: [UnsafeMutableRawPointer] = []
    public let slab: Int
    private let maxIdle: Int

    public init(slab: Int = 2048, maxIdle: Int = 128) {
        self.slab = slab
        self.maxIdle = maxIdle
    }

    public func take(minimumCapacity: Int) -> PacketStorage {
        if minimumCapacity <= slab, let ptr = free.popLast() {
            return PacketStorage(pooled: ptr, capacity: slab, pool: self)
        }
        if minimumCapacity <= slab {
            let ptr = UnsafeMutableRawPointer.allocate(
                byteCount: slab,
                alignment: MemoryLayout<UInt64>.alignment
            )
            return PacketStorage(pooled: ptr, capacity: slab, pool: self)
        }
        return PacketStorage(capacity: minimumCapacity)
    }

    fileprivate func recycle(_ pointer: UnsafeMutableRawPointer) {
        if free.count < maxIdle {
            free.append(pointer)
        } else {
            pointer.deallocate()
        }
    }

    deinit {
        for pointer in free {
            pointer.deallocate()
        }
    }
}

/// Uniquely owned packet view. Parsing and slicing never memcpy the bytes.
///
/// RX path wraps `NSData` from `NEPacketTunnelFlow` (stable `bytes` pointer).
/// TX path allocates via `PacketStorage`.
///
/// Ownership:
/// - `borrowing` reads headers / payload views
/// - `consuming` transfers the view; backing storage is refcounted
/// - `slice` consumes `self` and returns a window into the same storage
public struct PacketBuffer: ~Copyable, Sendable {
    @usableFromInline
    var storage: PacketStorage

    @usableFromInline
    var start: Int

    @usableFromInline
    var end: Int

    @inlinable
    public var count: Int { end - start }

    @inlinable
    public var isEmpty: Bool { start == end }

    @inlinable
    public var capacity: Int { storage.capacity }

    public init(capacity: Int) {
        self.storage = PacketStorage(capacity: capacity)
        self.start = 0
        self.end = 0
    }

    public init(storage: PacketStorage) {
        self.storage = storage
        self.start = 0
        self.end = 0
    }

    /// Zero-copy wrap of Foundation `Data` produced by the tunnel.
    public init(wrapping data: Data) {
        self.storage = PacketStorage(wrapping: data)
        self.start = 0
        self.end = data.count
    }

    init(storage: PacketStorage, start: Int, end: Int) {
        self.storage = storage
        self.start = start
        self.end = end
    }

    @inlinable
    public borrowing func withUnsafeBytes<R>(
        _ body: (UnsafeRawBufferPointer) throws -> R
    ) rethrows -> R {
        try body(UnsafeRawBufferPointer(start: storage.pointer.advanced(by: start), count: count))
    }

    @inlinable
    public mutating func withUnsafeMutableBytes<R>(
        _ body: (UnsafeMutableRawBufferPointer) throws -> R
    ) rethrows -> R {
        try body(UnsafeMutableRawBufferPointer(start: storage.pointer.advanced(by: start), count: count))
    }

    /// Share bytes with Foundation without memcpy. The deallocator retains `PacketStorage`.
    public borrowing func asSharedData() -> Data {
        let base = storage.pointer.advanced(by: start)
        let n = count
        let storage = self.storage
        return Data(bytesNoCopy: base, count: n, deallocator: .custom { [storage] _, _ in
            _ = storage
        })
    }

    /// Append bytes into a TX buffer.
    public mutating func append(_ bytes: UnsafeRawBufferPointer) {
        precondition(end + bytes.count <= storage.capacity, "PacketBuffer overflow")
        if let base = bytes.baseAddress {
            storage.pointer.advanced(by: end).copyMemory(from: base, byteCount: bytes.count)
        }
        end += bytes.count
    }

    public mutating func append<T: FixedWidthInteger>(networkOrder value: T) {
        var be = value.bigEndian
        Swift.withUnsafeBytes(of: &be) { raw in
            append(UnsafeRawBufferPointer(raw))
        }
    }

    public mutating func append(bytes: Data) {
        bytes.withUnsafeBytes { append($0) }
    }

    public mutating func setCount(_ newCount: Int) {
        precondition(newCount >= 0 && start + newCount <= storage.capacity)
        end = start + newCount
    }

    /// Consume `self` and return a unique slice. No allocation, no memcpy.
    public consuming func slice(offset: Int, length: Int) -> PacketBuffer {
        precondition(offset >= 0 && length >= 0 && offset + length <= count)
        return PacketBuffer(
            storage: storage,
            start: start + offset,
            end: start + offset + length
        )
    }

    /// Payload `Data` that retains the original `NSData`. `NSData.subdata` copies;
    /// this uses `bytesNoCopy` and keeps the backing alive in the deallocator.
    public borrowing func retainedPayload(offset: Int, length: Int) -> Data {
        precondition(offset >= 0 && length >= 0 && offset + length <= count)
        let base = storage.pointer.advanced(by: start + offset)
        switch storage.kind {
        case .nsdata(let ns):
            return Data(
                bytesNoCopy: base,
                count: length,
                deallocator: .custom { [ns] _, _ in
                    _ = ns
                }
            )
        case .malloc, .pooled:
            return Data(bytes: base, count: length)
        }
    }

    public borrowing func loadUnaligned<T: FixedWidthInteger>(at offset: Int, as: T.Type = T.self) -> T {
        precondition(offset >= 0 && offset + MemoryLayout<T>.size <= count)
        return storage.pointer.advanced(by: start + offset).loadUnaligned(as: T.self)
    }

    public borrowing func loadNetwork<T: FixedWidthInteger>(at offset: Int) -> T {
        T(bigEndian: loadUnaligned(at: offset, as: T.self))
    }
}

/// Move-only batch used at the EventLoop boundary so a TUN read of N packets
/// is one hop, not N task wakes.
public struct PacketBatch: ~Copyable {
    @usableFromInline
    var nodes: [Box]

    public final class Box: @unchecked Sendable {
        @usableFromInline
        var buffer: PacketBuffer?

        public init(_ buffer: consuming PacketBuffer) {
            self.buffer = consume buffer
        }

        public func take() -> PacketBuffer {
            buffer.take()!
        }
    }

    public init() {
        self.nodes = []
        nodes.reserveCapacity(32)
    }

    public var count: Int { nodes.count }

    public mutating func append(_ buffer: consuming PacketBuffer) {
        nodes.append(Box(buffer))
    }

    public mutating func append(wrapping data: Data) {
        append(PacketBuffer(wrapping: data))
    }

    public consuming func consumeEach(_ body: (consuming PacketBuffer) -> Void) {
        for box in nodes {
            body(box.take())
        }
    }
}
