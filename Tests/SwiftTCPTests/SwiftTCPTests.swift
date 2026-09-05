import Foundation
import Testing
@testable import SwiftTCP

private let client = IPAddress.v4(octets: (10, 0, 0, 1))
private let server = IPAddress.v4(octets: (10, 0, 0, 2))

private func flow(_ sport: UInt16 = 40_000, _ dport: UInt16 = 80) -> FlowKey {
    FlowKey(src: client, srcPort: sport, dst: server, dstPort: dport)
}

private func packetData(
    flow: FlowKey,
    seq: UInt32,
    ack: UInt32,
    flags: TCPFlags,
    payload: Data = Data(),
    options: TCPOptions = .empty
) -> Data {
    PacketBuilder.tcp(
        flow: flow,
        seq: seq,
        ack: ack,
        flags: flags,
        window: 65_535,
        options: options,
        payload: payload
    ).asSharedData()
}

@Test func packetBufferZeroCopyWrapAndSlice() throws {
    let original = Data((0..<64).map { UInt8($0) })
    let buffer = PacketBuffer(wrapping: original)
    #expect(buffer.count == 64)
    #expect(buffer.loadNetwork(at: 0) as UInt8 == 0)
    #expect(buffer.loadNetwork(at: 10) as UInt8 == 10)

    let payload = buffer.retainedPayload(offset: 20, length: 8)
    #expect(Array(payload) == [20, 21, 22, 23, 24, 25, 26, 27])

    let sliced = buffer.slice(offset: 60, length: 4)
    #expect(sliced.count == 4)
    #expect(sliced.loadNetwork(at: 0) as UInt8 == 60)
}

@Test func ipv4TcpRoundTripParse() throws {
    let f = flow()
    let data = packetData(flow: f, seq: 42, ack: 0, flags: .syn, options: TCPOptions(mss: 1460, windowScale: 7, sackPermitted: true, tfoCookie: nil))
    let parsed = try IPPacket.parse(PacketBuffer(wrapping: data))
    #expect(parsed.segment.flow == f)
    #expect(parsed.segment.seq == 42)
    #expect(parsed.segment.hasSYN)
    #expect(parsed.segment.options.mss == 1460)
    #expect(parsed.segment.options.windowScale == 7)
    #expect(try IPPacket.peekFlowKey(data) == f)
}

@Test func sackOptionRoundTrip() throws {
    let blocks = [SACKBlock(left: 1000, right: 2000), SACKBlock(left: 3000, right: 3500)]
    let opts = TCPOptions(mss: nil, windowScale: nil, sackPermitted: false, tfoCookie: nil, sackBlocks: blocks)
    let f = flow()
    let data = packetData(flow: f, seq: 1, ack: 1000, flags: .ack, options: opts)
    let parsed = try IPPacket.parse(PacketBuffer(wrapping: data))
    #expect(parsed.segment.options.sackBlocks == blocks)
    #expect(!parsed.segment.options.sackPermitted)
}

@Test func ipv6TcpRoundTripParse() throws {
    let f = FlowKey(
        src: IPAddress(v6High: 0x20010db800000000, v6Low: 1),
        srcPort: 1234,
        dst: IPAddress(v6High: 0x20010db800000000, v6Low: 2),
        dstPort: 443
    )
    let data = packetData(flow: f, seq: 7, ack: 0, flags: .syn)
    let parsed = try IPPacket.parse(PacketBuffer(wrapping: data))
    #expect(parsed.segment.flow == f)
    #expect(parsed.segment.version == .v6)
}

@Test func internetChecksumFolds() {
    var bytes = [UInt8](repeating: 0, count: 8)
    bytes[0] = 0xff
    bytes[1] = 0xff
    let sum = bytes.withUnsafeBytes { InternetChecksum.compute(bytes: $0) }
    #expect(sum == 0)
}

@Test func ringBufferWrapsWithoutLosingBytes() {
    let ring = ByteRingBuffer(capacity: 8)
    #expect(ring.write(Data([1, 2, 3, 4, 5, 6])) == 6)
    var head = Data(count: 4)
    head.withUnsafeMutableBytes { _ = ring.read(into: $0) }
    #expect(Array(head) == [1, 2, 3, 4])
    #expect(ring.write(Data([7, 8, 9, 10])) == 4)
    #expect(Array(ring.peek(6)) == [5, 6, 7, 8, 9, 10])
}

@Test func stateMachineListenToEstablished() {
    let syn = TCPSegment(
        flow: flow(),
        seq: 100,
        ack: 0,
        flags: .syn,
        window: 1000,
        dataOffset: 20,
        payloadOffset: 40,
        payloadLength: 0,
        options: .empty,
        ipHeaderLength: 20,
        version: .v4
    )
    let (s1, a1) = TCPStateMachine.transition(state: .listen, event: .segment(syn))
    #expect(s1 == .synReceived)
    #expect(a1.contains(.sendSynAck))

    var ackSeg = syn
    ackSeg.flags = .ack
    ackSeg.ack = 1
    let (s2, a2) = TCPStateMachine.transition(state: .synReceived, event: .segment(ackSeg))
    #expect(s2 == .established)
    #expect(a2.contains(.established))
}

@Test func tcbHandshakeAndTFOPayload() {
    let f = flow()
    let pcb = TCPControlBlock(flow: f, state: .listen, iss: 5000)
    let payload = Data("hello".utf8)
    let syn = TCPSegment(
        flow: f,
        seq: 1000,
        ack: 0,
        flags: .syn,
        window: 65_535,
        dataOffset: 20,
        payloadOffset: 40,
        payloadLength: payload.count,
        options: TCPOptions(mss: 1400, windowScale: 7, sackPermitted: true, tfoCookie: Data([1, 2, 3, 4])),
        ipHeaderLength: 20,
        version: .v4
    )
    let synActions = pcb.onSegment(syn, payload: payload)
    #expect(pcb.state == .synReceived)
    #expect(synActions.contains { if case .send(let flags, _, _, _, _, _) = $0 { return flags.contains(.syn) && flags.contains(.ack) } else { return false } })
    #expect(synActions.contains { if case .deliver(let d) = $0 { return d == payload } else { return false } })

    let ack = TCPSegment(
        flow: f,
        seq: 1001 + UInt32(payload.count),
        ack: pcb.iss &+ 1,
        flags: .ack,
        window: 65_535,
        dataOffset: 20,
        payloadOffset: 40,
        payloadLength: 0,
        options: .empty,
        ipHeaderLength: 20,
        version: .v4
    )
    let ackActions = pcb.onSegment(ack, payload: Data())
    #expect(pcb.state == .established)
    #expect(ackActions.contains { if case .established = $0 { return true } else { return false } })
}

@Test func cubicAndBBRReactToAckAndLoss() {
    var cubic = CUBIC(mss: 1460, initialCwnd: 10 * 1460)
    let before = cubic.cwnd
    cubic.onAck(acked: 1460, rtt: .milliseconds(20), inflight: 10 * 1460, now: ContinuousClock().now)
    #expect(cubic.cwnd >= before)
    cubic.onLoss()
    #expect(cubic.cwnd < before)
    cubic.epochStart = ContinuousClock.now.advanced(by: .seconds(-3_600))
    cubic.onAck(acked: 1460, rtt: .milliseconds(20), inflight: 10 * 1460, now: ContinuousClock.now)
    #expect(cubic.cwnd <= 4_000_000)

    var bbr = BBR(mss: 1460)
    bbr.onAck(acked: 16_000, rtt: .milliseconds(10), inflight: 16_000, now: ContinuousClock().now)
    #expect(bbr.btlBw > 0)
    #expect(bbr.pacingRateBps > 0)
}

@Test func flowAffinityIsStableAndPartitions() {
    let a = flow(40000, 80)
    let b = flow(40001, 80)
    #expect(a.affinityHash == a.affinityHash)
    #expect(a.eventLoopIndex(loopCount: 4) == a.eventLoopIndex(loopCount: 4))
    #expect(a.affinityHash != b.affinityHash)
}

@Test func stackCompletesHandshakeAndWritesSynAck() async throws {
    let sink = RecordingSink()
    let events = StreamRecorder()
    let stack = TCPStack(
        config: TCPStackConfig(loopCount: 2, algorithm: .cubic),
        sink: sink,
        streams: events
    )
    let f = flow(41_000, 443)
    let syn = packetData(flow: f, seq: 99, ack: 0, flags: .syn)
    await stack.ingest(syn)

    let tx = sink.snapshot()
    #expect(tx.count >= 1)
    let synAck = try IPPacket.parse(PacketBuffer(wrapping: tx[0]))
    #expect(synAck.segment.hasSYN && synAck.segment.hasACK)
    #expect(synAck.segment.flow == f.reversed)

    let ack = packetData(flow: f, seq: 100, ack: synAck.segment.seq &+ 1, flags: .ack)
    await stack.ingest(ack)
    let established = events.established
    #expect(established.contains(f))
}

@Test func metricsSinkCountsWithoutRetainingPayload() async {
    let sink = MetricsSink()
    sink.write(bytes: Data(count: 128), protocolFamily: 2)
    sink.write(bytes: Data(count: 64), protocolFamily: 2)
    let snap = sink.snapshot()
    #expect(snap.packets == 2)
    #expect(snap.bytes == 192)
}

@Test func ringBufferGrowsAndPreservesWrap() {
    let ring = ByteRingBuffer(capacity: 8)
    #expect(ring.write(Data([1, 2, 3, 4, 5, 6])) == 6)
    ring.consume(4)
    #expect(ring.write(Data([7, 8, 9, 10])) == 4)
    ring.grow(to: 16)
    #expect(Array(ring.peek(6)) == [5, 6, 7, 8, 9, 10])
    #expect(ring.capacity == 16)
    #expect(ring.write(Data(repeating: 0xab, count: 10)) == 10)
}

@Test func handshakeDoesNotAllocateRingBuffers() {
    let pcb = TCPControlBlock(flow: flow(), state: .listen, iss: 5000)
    let syn = TCPSegment(
        flow: flow(), seq: 1000, ack: 0, flags: .syn, window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    _ = pcb.onSegment(syn, payload: Data())
    let ack = TCPSegment(
        flow: flow(), seq: 1001, ack: pcb.iss &+ 1, flags: .ack, window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    _ = pcb.onSegment(ack, payload: Data())
    #expect(pcb.state == .established)
    #expect(pcb.sendBuffer == nil)
    #expect(pcb.recvBuffer == nil)
}

@Test func txBufferPoolRecyclesSlabs() {
    let pool = TXBufferPool(slab: 256, maxIdle: 4)
    var firstPtr: UnsafeMutableRawPointer?
    do {
        let storage = pool.take(minimumCapacity: 64)
        firstPtr = storage.pointer
        _ = PacketBuffer(storage: storage)
    }
    let second = pool.take(minimumCapacity: 64)
    #expect(second.pointer == firstPtr)
}

private final class StreamRecorder: TCPStreamHandler, @unchecked Sendable {
    private let lock = NSLock()
    private var _established: [FlowKey] = []
    private var payloads: [Data] = []
    private var closed: [FlowKey] = []

    var established: [FlowKey] {
        lock.lock()
        defer { lock.unlock() }
        return _established
    }

    func onEstablished(flow: FlowKey) {
        lock.lock()
        _established.append(flow)
        lock.unlock()
    }

    func onData(flow: FlowKey, data: Data) {
        lock.lock()
        payloads.append(data)
        lock.unlock()
    }

    func onClosed(flow: FlowKey) {
        lock.lock()
        closed.append(flow)
        lock.unlock()
    }
}
