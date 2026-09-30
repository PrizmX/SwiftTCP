import Foundation
import Testing
@testable import SwiftTCP

private let client = IPAddress.v4(octets: (10, 0, 0, 1))
private let server = IPAddress.v4(octets: (10, 0, 0, 2))

private func testFlow(_ sport: UInt16 = 41_000) -> FlowKey {
    FlowKey(src: client, srcPort: sport, dst: server, dstPort: 80)
}

private func seg(
    _ pcb: TCPControlBlock,
    seq: UInt32,
    ack: UInt32 = 0,
    flags: TCPFlags,
    payloadLength: Int = 0,
    options: TCPOptions = .empty
) -> TCPSegment {
    TCPSegment(
        flow: pcb.flow, seq: seq, ack: ack, flags: flags, window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: payloadLength,
        options: options, ipHeaderLength: 20, version: .v4
    )
}

/// Client ISN 1000; after this rcvNxt == 1001 and the TCB is ESTABLISHED.
private func handshake(_ pcb: TCPControlBlock) {
    _ = pcb.onSegment(seg(pcb, seq: 1000, flags: .syn), payload: Data())
    _ = pcb.onSegment(seg(pcb, seq: 1001, ack: pcb.iss &+ 1, flags: .ack), payload: Data())
}

private func sent(_ actions: [TCPAction]) -> [(flags: TCPFlags, seq: UInt32, ack: UInt32, window: UInt16, options: TCPOptions)] {
    actions.compactMap {
        switch $0 {
        case .send(let flags, let seq, let ack, let window, _, let options):
            return (flags, seq, ack, window, options)
        case .sendFromBuffer(let flags, let seq, let ack, let window, _, _, let options):
            return (flags, seq, ack, window, options)
        default:
            return nil
        }
    }
}

private func delivered(_ actions: [TCPAction]) -> Data {
    var out = Data()
    for case .deliver(let d) in actions { out.append(d) }
    return out
}

private func hasPeerFinished(_ actions: [TCPAction]) -> Bool {
    actions.contains { if case .peerFinished = $0 { return true } else { return false } }
}

/// Hand-built IPv4/TCP packet so arbitrary (even illegal) option bytes can be sent.
private func rawIPv4TCP(flow: FlowKey, seq: UInt32, flags: TCPFlags, options: [UInt8]) -> Data {
    precondition(options.count % 4 == 0 && options.count <= 40)
    guard case .v4(let src) = flow.src.kind, case .v4(let dst) = flow.dst.kind else { fatalError() }
    let tcpLen = 20 + options.count
    let total = 20 + tcpLen
    var b: [UInt8] = []
    func u16(_ v: UInt16) { b += [UInt8(v >> 8), UInt8(v & 0xFF)] }
    func u32(_ v: UInt32) { b += [UInt8(v >> 24), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)] }
    b += [0x45, 0]; u16(UInt16(total)); u16(0); u16(0x4000); b += [64, 6]; u16(0); u32(src); u32(dst)
    u16(flow.srcPort); u16(flow.dstPort); u32(seq); u32(0)
    u16(UInt16(tcpLen / 4) << 12 | UInt16(flags.rawValue)); u16(65_535); u16(0); u16(0)
    b += options
    return Data(b)
}

private final class EventLog: TCPStreamHandler, @unchecked Sendable {
    private let lock = NSLock()
    private var events: [String] = []

    func onEstablished(flow: FlowKey) { record("established") }
    func onData(flow: FlowKey, data: Data) { record("data:\(data.count)") }
    func onPeerFinished(flow: FlowKey) { record("fin") }
    func onClosed(flow: FlowKey) { record("closed") }

    private func record(_ s: String) {
        lock.lock()
        events.append(s)
        lock.unlock()
    }

    func snapshot() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return events
    }
}

// MARK: 1. TFO cookie overflow

@Test func oversizedTFOCookieIsIgnoredAndNeverEchoed() async throws {
    // Window scale + a 32-byte TFO cookie: echoing it made the SYN-ACK header 64 bytes
    // and `UInt16((tcpHeader / 4) << 12)` trapped, killing the tunnel.
    var options: [UInt8] = [1, 3, 3, 7, 34, 34]
    options += Array(repeating: 0xAB, count: 32)
    options += [1, 1]
    let parsed = options.withUnsafeBytes { TCPOptions.parse(bytes: $0) }
    #expect(parsed.tfoCookie == nil)
    #expect(parsed.windowScale == 7)

    let sink = RecordingSink()
    let stack = TCPStack(config: TCPStackConfig(loopCount: 1, tfo: true), sink: sink)
    let flow = testFlow(41_001)
    await stack.ingest(rawIPv4TCP(flow: flow, seq: 7, flags: .syn, options: options))
    let tx = sink.snapshot()
    #expect(tx.count == 1)
    let synAck = try IPPacket.parse(PacketBuffer(wrapping: tx[0])).segment
    #expect(synAck.hasSYN && synAck.hasACK)
    #expect(synAck.dataOffset <= 60)
    #expect(synAck.options.tfoCookie == nil)
}

@Test func tfoCookieRequestGetsServerCookieNotClientBytes() async throws {
    let sink = RecordingSink()
    let stack = TCPStack(config: TCPStackConfig(loopCount: 1, tfo: true), sink: sink)
    let flow = testFlow(41_002)
    await stack.ingest(rawIPv4TCP(flow: flow, seq: 7, flags: .syn, options: [34, 2, 1, 1]))
    let synAck = try IPPacket.parse(PacketBuffer(wrapping: sink.snapshot()[0])).segment
    #expect(synAck.options.tfoCookie == TCPControlBlock.tfoCookie(for: flow.src))

    // Client-supplied cookie is not reflected when TFO is disabled.
    let sink2 = RecordingSink()
    let off = TCPStack(config: TCPStackConfig(loopCount: 1, tfo: false), sink: sink2)
    await off.ingest(rawIPv4TCP(flow: flow, seq: 7, flags: .syn, options: [34, 10, 1, 2, 3, 4, 5, 6, 7, 8, 1, 1]))
    let synAck2 = try IPPacket.parse(PacketBuffer(wrapping: sink2.snapshot()[0])).segment
    #expect(synAck2.options.tfoCookie == nil)
}

@Test func optionEncodingNeverExceedsFortyBytes() throws {
    let blocks = (0..<4).map { SACKBlock(left: UInt32($0) * 100, right: UInt32($0) * 100 + 50) }
    let opts = TCPOptions(
        mss: 1460, windowScale: 7, sackPermitted: true,
        tfoCookie: Data(repeating: 1, count: 16), sackBlocks: blocks
    )
    let bytes = opts.encoded()
    #expect(bytes.count <= 40)
    #expect(bytes.count % 4 == 0)
    let huge = TCPOptions(mss: nil, windowScale: nil, sackPermitted: false, tfoCookie: Data(repeating: 2, count: 200))
    #expect(huge.encoded().count <= 40)
    // Builders must not trap on any option set.
    let pkt = PacketBuilder.tcp(flow: testFlow(), seq: 1, ack: 1, flags: .ack, window: 1, options: opts).asSharedData()
    let parsed = try IPPacket.parse(PacketBuffer(wrapping: pkt)).segment
    #expect(parsed.dataOffset == 20 + bytes.count)
}

// MARK: 2. TX pool thread safety

@Test func txBufferPoolRecyclesFromManyThreads() {
    let pool = TXBufferPool(slab: 256, maxIdle: 16)
    DispatchQueue.concurrentPerform(iterations: 8) { _ in
        for _ in 0..<5_000 {
            var buffer = PacketBuffer(storage: pool.take(minimumCapacity: 64))
            buffer.append(networkOrder: UInt8(0xAB))
            let data = buffer.asSharedData()
            #expect(data.count == 1)
        }
    }
    #expect(pool.idleCount <= 16)
    #expect(pool.idleCount > 0)
}

// MARK: 3. SYN-ACK / FIN retransmission

@Test func synAckIsRetransmittedOnTimeoutAndOnDuplicateSyn() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    _ = pcb.onSegment(seg(pcb, seq: 1000, flags: .syn), payload: Data())
    #expect(pcb.state == .synReceived)

    let rto = sent(pcb.onTimeout(.retransmission))
    #expect(rto.contains { $0.flags == [.syn, .ack] && $0.seq == 5000 && $0.ack == 1001 })

    let dup = sent(pcb.onSegment(seg(pcb, seq: 1000, flags: .syn), payload: Data()))
    #expect(dup.contains { $0.flags == [.syn, .ack] && $0.seq == 5000 && $0.ack == 1001 })
    #expect(pcb.state == .synReceived)
    #expect(pcb.rcvNxt == 1001)
}

@Test func finIsRetransmittedAfterDataIsAcked() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb)
    _ = pcb.onAppSend(Data(repeating: 1, count: 10))
    _ = pcb.onAppClose()
    #expect(pcb.state == .finWait1)
    #expect(pcb.sndNxt == 5001 + 10 + 1)

    // Data outstanding: RTO resends data first.
    let first = sent(pcb.onTimeout(.retransmission))
    #expect(first.first?.seq == 5001)
    #expect(first.first.map { !$0.flags.contains(.fin) } == true)

    // Data ACKed, FIN still in flight: RTO resends the FIN.
    _ = pcb.onSegment(seg(pcb, seq: 1001, ack: 5011, flags: .ack), payload: Data())
    #expect(pcb.state == .finWait1)
    let second = sent(pcb.onTimeout(.retransmission))
    #expect(second.contains { $0.flags.contains(.fin) && $0.seq == 5011 })
}

// MARK: 4. Only an ACK covering our FIN advances the close

@Test func ackBelowFinDoesNotLeaveFinWait1OrLastAck() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb)
    _ = pcb.onAppSend(Data(repeating: 1, count: 10))
    _ = pcb.onAppClose()
    _ = pcb.onSegment(seg(pcb, seq: 1001, ack: 5006, flags: .ack), payload: Data())
    #expect(pcb.state == .finWait1)
    _ = pcb.onSegment(seg(pcb, seq: 1001, ack: 5012, flags: .ack), payload: Data())
    #expect(pcb.state == .finWait2)

    let last = TCPControlBlock(flow: testFlow(41_010), state: .listen, iss: 5000)
    handshake(last)
    _ = last.onSegment(seg(last, seq: 1001, ack: 5001, flags: [.fin, .ack]), payload: Data())
    #expect(last.state == .closeWait)
    _ = last.onAppSend(Data(repeating: 2, count: 10))
    _ = last.onAppClose()
    #expect(last.state == .lastAck)
    let partial = last.onSegment(seg(last, seq: 1002, ack: 5011, flags: .ack), payload: Data())
    #expect(last.state == .lastAck)
    #expect(!partial.contains { if case .closed = $0 { return true } else { return false } })
    let full = last.onSegment(seg(last, seq: 1002, ack: 5012, flags: .ack), payload: Data())
    #expect(full.contains { if case .closed = $0 { return true } else { return false } })
}

// MARK: 5 + 6. Half-close: data after our FIN, and peer FIN surfaced

@Test func dataAfterOurFinIsDeliveredAndAcked() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb)
    _ = pcb.onAppClose()
    #expect(pcb.state == .finWait1)

    let a = Data("abc".utf8)
    let r1 = pcb.onSegment(seg(pcb, seq: 1001, ack: 5001, flags: .ack, payloadLength: 3), payload: a)
    #expect(pcb.state == .finWait1)
    #expect(delivered(r1) == a)
    #expect(sent(r1).contains { $0.ack == 1004 })

    let r2 = pcb.onSegment(seg(pcb, seq: 1004, ack: 5002, flags: .ack), payload: Data())
    #expect(pcb.state == .finWait2)
    #expect(delivered(r2).isEmpty)

    let b = Data("defg".utf8)
    let r3 = pcb.onSegment(seg(pcb, seq: 1004, ack: 5002, flags: .ack, payloadLength: 4), payload: b)
    #expect(delivered(r3) == b)
    #expect(sent(r3).contains { $0.ack == 1008 })

    let c = Data("hi".utf8)
    let r4 = pcb.onSegment(seg(pcb, seq: 1008, ack: 5002, flags: [.fin, .ack], payloadLength: 2), payload: c)
    #expect(pcb.state == .timeWait)
    #expect(delivered(r4) == c)
    #expect(sent(r4).contains { $0.ack == 1011 })
    #expect(hasPeerFinished(r4))
}

@Test func finWithDataInFinWait1IsDelivered() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb)
    _ = pcb.onAppClose()
    let d = Data("xyz".utf8)
    let r = pcb.onSegment(seg(pcb, seq: 1001, ack: 5002, flags: [.fin, .ack], payloadLength: 3), payload: d)
    #expect(pcb.state == .timeWait)
    #expect(delivered(r) == d)
    #expect(hasPeerFinished(r))
}

@Test func peerFinIsSurfacedAfterDataInOrder() async throws {
    let sink = RecordingSink()
    let log = EventLog()
    let stack = TCPStack(config: TCPStackConfig(loopCount: 1), sink: sink, streams: log)
    let flow = testFlow(41_020)
    await stack.ingest(PacketBuilder.tcp(flow: flow, seq: 100, ack: 0, flags: .syn, window: 65_535).asSharedData())
    let synAck = try IPPacket.parse(PacketBuffer(wrapping: sink.snapshot()[0])).segment
    let ack = synAck.seq &+ 1
    await stack.ingest(PacketBuilder.tcp(flow: flow, seq: 101, ack: ack, flags: .ack, window: 65_535).asSharedData())
    await stack.ingest(
        PacketBuilder.tcp(
            flow: flow, seq: 101, ack: ack, flags: [.fin, .ack, .psh], window: 65_535,
            payload: Data("bye".utf8)
        ).asSharedData()
    )
    #expect(log.snapshot() == ["established", "data:3", "fin"])
}

// MARK: 7. SYN data without a valid cookie

@Test func synDataWithoutValidCookieIsNotAckedOrDelivered() {
    let payload = Data("early".utf8)
    for tfo in [false, true] {
        let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
        pcb.tfoEnabled = tfo
        let cookie: Data? = tfo ? Data([9, 9, 9, 9]) : nil
        let r = pcb.onSegment(
            seg(pcb, seq: 1000, flags: .syn, payloadLength: payload.count,
                options: TCPOptions(mss: nil, windowScale: nil, sackPermitted: false, tfoCookie: cookie)),
            payload: payload
        )
        #expect(delivered(r).isEmpty)
        #expect(sent(r).contains { $0.flags == [.syn, .ack] && $0.ack == 1001 })
        #expect(pcb.rcvNxt == 1001)

        // Client retransmits the data after the handshake; delivered exactly once.
        let e = pcb.onSegment(seg(pcb, seq: 1001, ack: 5001, flags: .ack, payloadLength: payload.count), payload: payload)
        #expect(pcb.state == .established)
        #expect(delivered(e) == payload)
        #expect(pcb.rcvNxt == 1006)
    }
}

// MARK: 8. Reassembly bounds

@Test func reassemblyCapsAdjacentSegmentsAndCopiesOutOfOrderBytes() {
    var q = TCPReassembly(maxHoles: 2, maxBytes: 1 << 20, maxSegments: 8)
    var accepted = 0
    for i in 0..<100 {
        if q.insert(seq: UInt32(10 + i), data: Data([UInt8(i)]), rcvNxt: 0, rcvWnd: 1_000) { accepted += 1 }
    }
    #expect(accepted == 8)
    #expect(q.holeCount == 8)
    #expect(q.regionCount == 1)
    // Out-of-order data no longer pins the (large) source packet.
    let packet = Data(repeating: 7, count: 1_500)
    let view = PacketBuffer(wrapping: packet).retainedPayload(offset: 40, length: 4)
    var r = TCPReassembly()
    _ = r.insert(seq: 500, data: view, rcvNxt: 0, rcvWnd: 10_000)
    #expect(r.holes[0].slice.count == 4)
    if case .malloc = r.holes[0].slice.storage.kind {} else { Issue.record("OOO slice still pins the packet") }
    // In-order data at rcvNxt bypasses the caps (it is drained immediately).
    let inOrder = q.insert(seq: 0, data: Data([1, 2]), rcvNxt: 0, rcvWnd: 1_000)
    #expect(inOrder)
}

// MARK: 9. Global connection cap / send buffer cap

@Test func maxConnectionsIsGlobalAcrossLoops() async throws {
    let sink = RecordingSink()
    let stack = TCPStack(config: TCPStackConfig(loopCount: 4, maxConnections: 3), sink: sink)
    for port in UInt16(42_000)..<42_016 {
        await stack.ingest(PacketBuilder.tcp(flow: testFlow(port), seq: 1, ack: 0, flags: .syn, window: 1000).asSharedData())
    }
    #expect(await stack.connectionCount() == 3)
}

@Test func sendBufferCapHonorsConfiguredLimit() {
    let small = TCPControlBlock(flow: testFlow(), window: 64 * 1024, sendBufferLimit: 64 * 1024)
    #expect(small.maxSendBytes == 64 * 1024)
    let def = TCPControlBlock(flow: testFlow(), window: 64 * 1024)
    #expect(def.maxSendBytes == 256 * 1024)
    let big = TCPControlBlock(flow: testFlow(), window: 1 << 20)
    #expect(big.maxSendBytes == 1 << 20)
}

// MARK: 11. TIME-WAIT re-ACK, SYN window, Karn

@Test func timeWaitReAcksRetransmittedFin() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb)
    _ = pcb.onAppClose()
    _ = pcb.onSegment(seg(pcb, seq: 1001, ack: 5002, flags: [.fin, .ack]), payload: Data())
    #expect(pcb.state == .timeWait)
    let again = pcb.onSegment(seg(pcb, seq: 1001, ack: 5002, flags: [.fin, .ack]), payload: Data())
    #expect(pcb.state == .timeWait)
    #expect(sent(again).contains { $0.flags == .ack && $0.ack == 1002 })
    #expect(!hasPeerFinished(again))
}

@Test func synAckWindowIsNotScaled() async throws {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    let r = pcb.onSegment(
        seg(pcb, seq: 1000, flags: .syn, options: TCPOptions(mss: 1460, windowScale: 7, sackPermitted: true, tfoCookie: nil)),
        payload: Data()
    )
    #expect(pcb.windowScaleEnabled)
    #expect(sent(r).first?.window == UInt16(min(pcb.rcvWnd, 65_535)))

    let sink = RecordingSink()
    let stack = TCPStack(config: TCPStackConfig(loopCount: 1), sink: sink)
    await stack.ingest(
        PacketBuilder.tcp(
            flow: testFlow(41_030), seq: 1, ack: 0, flags: .syn, window: 65_535,
            options: TCPOptions(mss: 1460, windowScale: 7, sackPermitted: true, tfoCookie: nil)
        ).asSharedData()
    )
    let synAck = try IPPacket.parse(PacketBuffer(wrapping: sink.snapshot()[0])).segment
    #expect(synAck.window == 65_535)
}

@Test func retransmittedSegmentIsNotRttSampled() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb)
    _ = pcb.onAppSend(Data(repeating: 1, count: 100))
    #expect(pcb.rttProbeSeq == 5101)
    _ = pcb.onTimeout(.retransmission)
    #expect(pcb.rttProbeSeq == nil)
    _ = pcb.onSegment(seg(pcb, seq: 1001, ack: 5101, flags: .ack), payload: Data())
    #expect(!pcb.rtt.sampled)
}
