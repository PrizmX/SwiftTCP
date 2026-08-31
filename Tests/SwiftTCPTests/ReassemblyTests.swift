import Foundation
import Testing
@testable import SwiftTCP

private let client = IPAddress.v4(octets: (10, 0, 0, 1))
private let server = IPAddress.v4(octets: (10, 0, 0, 2))

private func testFlow() -> FlowKey {
    FlowKey(src: client, srcPort: 40_000, dst: server, dstPort: 80)
}

private func handshake(pcb: TCPControlBlock) {
    let syn = TCPSegment(
        flow: pcb.flow, seq: 1000, ack: 0, flags: .syn, window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    _ = pcb.onSegment(syn, payload: Data())
    let ack = TCPSegment(
        flow: pcb.flow, seq: 1001, ack: pcb.iss &+ 1, flags: .ack, window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    _ = pcb.onSegment(ack, payload: Data())
}

private func dataSeg(pcb: TCPControlBlock, seq: UInt32, payload: Data, fin: Bool = false) -> TCPSegment {
    var flags: TCPFlags = .ack
    if fin { flags.insert(.fin) }
    return TCPSegment(
        flow: pcb.flow, seq: seq, ack: pcb.iss &+ 1, flags: flags, window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: payload.count,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
}

private func delivered(_ actions: [TCPAction]) -> Data {
    var out = Data()
    for action in actions {
        if case .deliver(let data) = action { out.append(data) }
    }
    return out
}

@Test func reassemblyHoldsUntilGapFills() {
    var q = TCPReassembly()
    let queued = q.insert(seq: 10, data: Data("world".utf8), rcvNxt: 5, rcvWnd: 100)
    #expect(queued)
    #expect(q.take(from: 5, maxBytes: 100).isEmpty)
    let filled = q.insert(seq: 5, data: Data("hello".utf8), rcvNxt: 5, rcvWnd: 100)
    #expect(filled)
    #expect(q.regionCount == 1)
    #expect(String(data: q.take(from: 5, maxBytes: 100), encoding: .utf8) == "helloworld")
    #expect(q.isEmpty)
}

@Test func reassemblyMergesOverlapPreferringNewBytes() {
    var q = TCPReassembly()
    _ = q.insert(seq: 0, data: Data("ABCDEF".utf8), rcvNxt: 0, rcvWnd: 100)
    _ = q.insert(seq: 2, data: Data("XY".utf8), rcvNxt: 0, rcvWnd: 100)
    #expect(q.regionCount == 1)
    #expect(String(data: q.take(from: 0, maxBytes: 100), encoding: .utf8) == "ABXYEF")
}

@Test func reassemblyTrimsLeftOfRcvNxtAndRightOfWindow() {
    var q = TCPReassembly()
    _ = q.insert(seq: 3, data: Data("hello".utf8), rcvNxt: 5, rcvWnd: 100)
    #expect(String(data: q.take(from: 5, maxBytes: 100), encoding: .utf8) == "llo")

    q.clear()
    _ = q.insert(seq: 0, data: Data("abcdef".utf8), rcvNxt: 0, rcvWnd: 3)
    #expect(String(data: q.take(from: 0, maxBytes: 100), encoding: .utf8) == "abc")
}

@Test func reassemblyDropsWhenHoleLimitReached() {
    var q = TCPReassembly(maxHoles: 2)
    let a = q.insert(seq: 10, data: Data([1]), rcvNxt: 0, rcvWnd: 100)
    let b = q.insert(seq: 20, data: Data([2]), rcvNxt: 0, rcvWnd: 100)
    let c = q.insert(seq: 30, data: Data([3]), rcvNxt: 0, rcvWnd: 100)
    #expect(a)
    #expect(b)
    #expect(!c)
    #expect(q.holeCount == 2)
}

@Test func reassemblyTakePartialLeavesRemainder() {
    var q = TCPReassembly()
    _ = q.insert(seq: 0, data: Data([1, 2, 3, 4, 5]), rcvNxt: 0, rcvWnd: 100)
    #expect(Array(q.take(from: 0, maxBytes: 2)) == [1, 2])
    #expect(q.holes[0].seq == 2)
    #expect(Array(q.take(from: 2, maxBytes: 10)) == [3, 4, 5])
}

@Test func reassemblyPendingFINWaitsForContiguousData() {
    var q = TCPReassembly()
    q.offerFIN(10, rcvNxt: 0, rcvWnd: 100)
    let early = q.takeFIN(rcvNxt: 0)
    #expect(!early)
    _ = q.insert(seq: 0, data: Data(count: 10), rcvNxt: 0, rcvWnd: 100)
    _ = q.take(from: 0, maxBytes: 10)
    let ready = q.takeFIN(rcvNxt: 10)
    #expect(ready)
    #expect(q.pendingFin == nil)
}

@Test func reassemblyWrapsSequenceSpace() {
    var q = TCPReassembly()
    let nxt: UInt32 = .max - 2
    _ = q.insert(seq: nxt &+ 4, data: Data([4, 5]), rcvNxt: nxt, rcvWnd: 10)
    #expect(q.take(from: nxt, maxBytes: 10).isEmpty)
    _ = q.insert(seq: nxt, data: Data([1, 2, 3, 4]), rcvNxt: nxt, rcvWnd: 10)
    #expect(Array(q.take(from: nxt, maxBytes: 10)) == [1, 2, 3, 4, 4, 5])
}

@Test func tcbReassemblesOutOfOrderThenDelivers() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    let later = pcb.onSegment(dataSeg(pcb: pcb, seq: 1006, payload: Data("world".utf8)), payload: Data("world".utf8))
    #expect(delivered(later).isEmpty)
    #expect(pcb.rcvNxt == 1001)
    #expect(pcb.reassembly.holeCount == 1)
    #expect(later.contains { if case .send(_, _, let ack, _, _, _) = $0 { return ack == 1001 } else { return false } })

    let first = pcb.onSegment(dataSeg(pcb: pcb, seq: 1001, payload: Data("hello".utf8)), payload: Data("hello".utf8))
    #expect(pcb.rcvNxt == 1011)
    #expect(pcb.reassembly.isEmpty)
    #expect(String(data: delivered(first), encoding: .utf8) == "helloworld")
}

@Test func tcbDuplicateDataDoesNotAdvanceRcvNxt() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    let payload = Data("abcd".utf8)
    _ = pcb.onSegment(dataSeg(pcb: pcb, seq: 1001, payload: payload), payload: payload)
    #expect(pcb.rcvNxt == 1005)
    let dup = pcb.onSegment(dataSeg(pcb: pcb, seq: 1001, payload: payload), payload: payload)
    #expect(pcb.rcvNxt == 1005)
    #expect(delivered(dup).isEmpty)
}

@Test func tcbOutOfOrderFINStaysEstablishedUntilGapFills() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    let fin = pcb.onSegment(
        dataSeg(pcb: pcb, seq: 1005, payload: Data(), fin: true),
        payload: Data()
    )
    #expect(pcb.state == .established)
    #expect(pcb.rcvNxt == 1001)
    #expect(pcb.reassembly.pendingFin == 1005)
    #expect(delivered(fin).isEmpty)

    let data = Data("abcd".utf8)
    let filled = pcb.onSegment(dataSeg(pcb: pcb, seq: 1001, payload: data), payload: data)
    #expect(pcb.state == .closeWait)
    #expect(pcb.rcvNxt == 1006)
    #expect(String(data: delivered(filled), encoding: .utf8) == "abcd")
    #expect(pcb.reassembly.isEmpty)
}

@Test func tcbInOrderDataWithFINStillCloses() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    let payload = Data([1, 2, 3, 4])
    _ = pcb.onSegment(
        dataSeg(pcb: pcb, seq: 1001, payload: payload, fin: true),
        payload: payload
    )
    #expect(pcb.state == .closeWait)
    #expect(pcb.rcvNxt == 1006)
}

@Test func tcbAdvertisedWindowKeepsRightEdgeWithOfO() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000, window: 64)
    handshake(pcb: pcb)
    let before = pcb.rcvWnd
    _ = pcb.onSegment(
        dataSeg(pcb: pcb, seq: 1020, payload: Data(repeating: 1, count: 16)),
        payload: Data(repeating: 1, count: 16)
    )
    #expect(pcb.rcvWnd == before)
    #expect(pcb.reassembly.storedBytes == 16)
    #expect(pcb.rcvNxt == 1001)
}

@Test func reassemblyDropsWhenByteLimitReached() {
    var q = TCPReassembly(maxHoles: 32, maxBytes: 4)
    let a = q.insert(seq: 10, data: Data([1, 2, 3]), rcvNxt: 0, rcvWnd: 100)
    let b = q.insert(seq: 20, data: Data([4, 5, 6]), rcvNxt: 0, rcvWnd: 100)
    #expect(a)
    #expect(!b)
    #expect(q.storedBytes == 3)
}

@Test func reassemblyDropsStaleHolesLeftOfRcvNxt() {
    var q = TCPReassembly()
    _ = q.insert(seq: 0, data: Data([1, 2, 3]), rcvNxt: 0, rcvWnd: 100)
    _ = q.insert(seq: 10, data: Data([9, 9]), rcvNxt: 0, rcvWnd: 100)
    #expect(Array(q.take(from: 5, maxBytes: 10)).isEmpty)
    #expect(q.holes.first?.seq == 10)
    #expect(q.storedBytes == 2)
}

@Test func reassemblySackBlocksPreferMostRecentRegion() {
    var q = TCPReassembly()
    _ = q.insert(seq: 20, data: Data([2, 2]), rcvNxt: 0, rcvWnd: 100)
    _ = q.insert(seq: 40, data: Data([4, 4]), rcvNxt: 0, rcvWnd: 100)
    let blocks = q.sackBlocks()
    #expect(blocks.first == SACKBlock(left: 40, right: 42))
    #expect(blocks.contains(SACKBlock(left: 20, right: 22)))
    #expect(blocks.count == 2)
}

@Test func tcbOutOfOrderEmitsSACKBlocks() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    let syn = TCPSegment(
        flow: pcb.flow, seq: 1000, ack: 0, flags: .syn, window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: TCPOptions(mss: nil, windowScale: nil, sackPermitted: true, tfoCookie: nil),
        ipHeaderLength: 20, version: .v4
    )
    _ = pcb.onSegment(syn, payload: Data())
    let ack = TCPSegment(
        flow: pcb.flow, seq: 1001, ack: pcb.iss &+ 1, flags: .ack, window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    _ = pcb.onSegment(ack, payload: Data())
    #expect(pcb.peerSackPermitted)

    let later = pcb.onSegment(dataSeg(pcb: pcb, seq: 1006, payload: Data("world".utf8)), payload: Data("world".utf8))
    let sack = later.compactMap { action -> [SACKBlock]? in
        if case .send(_, _, _, _, _, let options) = action { return options.sackBlocks }
        return nil
    }.first
    #expect(sack == [SACKBlock(left: 1006, right: 1011)])
}

@Test func tcbDupAckThrottledAfterThreeAtSameInstant() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    let now = ContinuousClock().now
    var acks = 0
    for i in 0..<6 {
        let payload = Data([UInt8(i)])
        let actions = pcb.onSegment(
            dataSeg(pcb: pcb, seq: 1100 + UInt32(i) * 10, payload: payload),
            payload: payload,
            now: now
        )
        acks += actions.filter { if case .send = $0 { return true } else { return false } }.count
    }
    #expect(acks == 3)
    #expect(pcb.reassembly.regionCount == 6)
}

@Test func batchCoalescesPureAcks() async throws {
    let sink = RecordingSink()
    let stack = TCPStack(config: TCPStackConfig(loopCount: 1), sink: sink)
    let f = testFlow()
    let syn = PacketBuilder.tcp(flow: f, seq: 1000, ack: 0, flags: .syn, window: 65_535).asSharedData()
    await stack.ingest(syn)
    let tx = sink.snapshot()
    let synAck = try IPPacket.parse(PacketBuffer(wrapping: tx[0]))
    sink.removeAll()
    let ack = PacketBuilder.tcp(
        flow: f, seq: 1001, ack: synAck.segment.seq &+ 1, flags: .ack, window: 65_535
    ).asSharedData()
    await stack.ingest(ack)
    sink.removeAll()

    var packets: [Data] = []
    for i in 0..<8 {
        packets.append(
            PacketBuilder.tcp(
                flow: f,
                seq: 1100 + UInt32(i) * 10,
                ack: synAck.segment.seq &+ 1,
                flags: .ack,
                window: 65_535,
                payload: Data([UInt8(i)])
            ).asSharedData()
        )
    }
    await stack.ingestBatch(packets)
    let oooAcks = sink.snapshot()
    #expect(oooAcks.count == 1)
}
