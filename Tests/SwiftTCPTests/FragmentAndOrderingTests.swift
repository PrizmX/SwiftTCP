import Foundation
import Testing
@testable import SwiftTCP

// MARK: - IPv4 fragment reassembly

private let fragSrc: [UInt8] = [10, 0, 0, 2]
private let fragDst: [UInt8] = [10, 0, 0, 1]

private func ipv4Checksum(_ header: [UInt8]) -> UInt16 {
    var sum: UInt32 = 0
    for index in stride(from: 0, to: header.count, by: 2) {
        sum &+= UInt32(header[index]) << 8 | UInt32(header[index + 1])
    }
    while sum >> 16 != 0 { sum = (sum & 0xffff) &+ (sum >> 16) }
    return ~UInt16(sum)
}

/// One IPv4 fragment of datagram `id`: `offset` in bytes (multiple of 8).
private func fragment(id: UInt16, offset: Int, more: Bool, payload: [UInt8], proto: UInt8 = 17) -> Data {
    let total = 20 + payload.count
    let field = UInt16(offset / 8) | (more ? 0x2000 : 0)
    var header: [UInt8] = [
        0x45, 0, UInt8(total >> 8), UInt8(total & 0xff),
        UInt8(id >> 8), UInt8(id & 0xff), UInt8(field >> 8), UInt8(field & 0xff),
        64, proto, 0, 0,
    ] + fragSrc + fragDst
    let checksum = ipv4Checksum(header)
    header[10] = UInt8(checksum >> 8)
    header[11] = UInt8(checksum & 0xff)
    return Data(header + payload)
}

/// UDP datagram (checksum 0 = none, allowed on IPv4) split at 8-byte-aligned `cuts`.
private func udpFragments(id: UInt16, body: [UInt8], cuts: [Int]) -> (udp: [UInt8], fragments: [Data]) {
    let length = 8 + body.count
    let udp: [UInt8] = [0x9c, 0x40, 0x13, 0x88, UInt8(length >> 8), UInt8(length & 0xff), 0, 0] + body
    var bounds = [0] + cuts + [udp.count]
    bounds = Array(Set(bounds)).sorted()
    var out: [Data] = []
    for index in 0..<(bounds.count - 1) {
        let lo = bounds[index]
        let hi = bounds[index + 1]
        out.append(fragment(id: id, offset: lo, more: hi < udp.count, payload: Array(udp[lo..<hi])))
    }
    return (udp, out)
}

@Test func reassemblesOutOfOrderFragmentsIntoOneDatagram() throws {
    let reassembler = IPv4Reassembler()
    let body = (0..<2_992).map { UInt8($0 & 0xff) }
    let (udp, frags) = udpFragments(id: 0x1234, body: body, cuts: [1_000, 2_000])
    #expect(frags.count == 3)

    #expect(reassembler.add(frags[2]) == .pending)
    #expect(reassembler.add(frags[0]) == .pending)
    guard case .complete(let datagram) = reassembler.add(frags[1]) else {
        Issue.record("expected a complete datagram")
        return
    }
    let bytes = [UInt8](datagram)
    #expect(bytes.count == 20 + udp.count)
    #expect(Int(bytes[2]) << 8 | Int(bytes[3]) == 20 + udp.count)
    #expect(bytes[6] == 0 && bytes[7] == 0)
    #expect(ipv4Checksum(Array(bytes[0..<20])) == 0)
    #expect(Array(bytes[20...]) == udp)
    #expect(reassembler.inFlight == 0)
    // The stack routes it like any unfragmented packet.
    let header = try IPHeader.peek(datagram)
    #expect(header.totalLength == 20 + udp.count)
}

@Test func ignoresDuplicateFragmentsAndDropsOverlaps() {
    let reassembler = IPv4Reassembler()
    let first = fragment(id: 7, offset: 0, more: true, payload: Array(repeating: 1, count: 16))
    #expect(reassembler.add(first) == .pending)
    #expect(reassembler.add(first) == .pending) // exact duplicate
    // Overlaps bytes 8..<16 of the first fragment: the whole datagram goes.
    let overlap = fragment(id: 7, offset: 8, more: false, payload: Array(repeating: 2, count: 16))
    #expect(reassembler.add(overlap) == .dropped(2))
    #expect(reassembler.inFlight == 0)
}

@Test func rejectsMalformedFragments() {
    let reassembler = IPv4Reassembler()
    // Non-final fragments must carry a multiple of 8 bytes.
    #expect(reassembler.add(fragment(id: 1, offset: 0, more: true, payload: [1, 2, 3])) == .dropped(1))
    // Offset + length past the 16-bit total length.
    #expect(reassembler.add(fragment(id: 2, offset: 65_528, more: false, payload: Array(repeating: 0, count: 16))) == .dropped(1))
    // A second "last" fragment that disagrees with the first.
    #expect(reassembler.add(fragment(id: 3, offset: 16, more: false, payload: Array(repeating: 0, count: 8))) == .pending)
    #expect(reassembler.add(fragment(id: 3, offset: 32, more: false, payload: Array(repeating: 0, count: 8))) == .dropped(2))
    #expect(reassembler.inFlight == 0)
}

@Test func expiresAndEvictsIncompleteDatagrams() {
    final class Clock: @unchecked Sendable {
        var now = ContinuousClock.now
    }
    let clock = Clock()
    let reassembler = IPv4Reassembler(
        limits: .init(maxDatagrams: 2, maxBytes: 1 << 20, timeout: .seconds(30)),
        clock: { clock.now }
    )
    let head = { (id: UInt16) in fragment(id: id, offset: 0, more: true, payload: Array(repeating: 0, count: 8)) }
    #expect(reassembler.add(head(1)) == .pending)
    #expect(reassembler.add(head(2)) == .pending)
    // A third datagram evicts the oldest.
    #expect(reassembler.add(head(3)) == .dropped(1))
    #expect(reassembler.inFlight == 2)
    // Past the timeout everything in flight is discarded.
    clock.now += .seconds(31)
    #expect(reassembler.add(head(4)) == .dropped(2))
    #expect(reassembler.inFlight == 1)
}

@Test func byteBudgetBoundsHeldFragments() {
    let reassembler = IPv4Reassembler(limits: .init(maxDatagrams: 64, maxBytes: 64, timeout: .seconds(30)))
    #expect(reassembler.add(fragment(id: 1, offset: 0, more: true, payload: Array(repeating: 0, count: 48))) == .pending)
    // 48 + 24 > 64: this datagram is dropped, holding nothing afterwards.
    #expect(reassembler.add(fragment(id: 2, offset: 0, more: true, payload: Array(repeating: 0, count: 24))) == .dropped(1))
    #expect(reassembler.inFlight == 1)
}

private final class DatagramRecorder: UDPDatagramHandler, @unchecked Sendable {
    private let lock = NSLock()
    private var payloads: [Data] = []

    func onDatagram(flow: FlowKey, payload: Data) {
        lock.lock()
        payloads.append(payload)
        lock.unlock()
    }

    func onClosed(flow: FlowKey) {}

    func snapshot() -> [Data] {
        lock.lock()
        defer { lock.unlock() }
        return payloads
    }
}

@Test func stackDeliversFragmentedUDPDatagramOnce() async throws {
    let recorder = DatagramRecorder()
    let stack = SwiftStack(sink: RecordingSink(), datagrams: recorder)
    let body = (0..<3_000).map { UInt8(($0 * 7) & 0xff) }
    let (_, frags) = udpFragments(id: 0x0bad, body: body, cuts: [1_376, 2_752])
    for frag in frags.reversed() {
        await stack.ingest(frag)
    }
    for _ in 0..<50 where recorder.snapshot().isEmpty {
        try await Task.sleep(for: .milliseconds(10))
    }
    #expect(recorder.snapshot() == [Data(body)])
    let metrics = await stack.metrics()
    #expect(metrics.reassembledDatagrams == 1)
    #expect(metrics.droppedFragment == 0)
    await stack.shutdown()
}
