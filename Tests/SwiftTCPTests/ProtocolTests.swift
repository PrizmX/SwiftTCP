import Foundation
import Testing
@testable import SwiftTCP

private let client = IPAddress.v4(octets: (10, 0, 0, 1))
private let server = IPAddress.v4(octets: (10, 0, 0, 2))

private func testFlow(_ sport: UInt16 = 40_000) -> FlowKey {
    FlowKey(src: client, srcPort: sport, dst: server, dstPort: 80)
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

private func sendSeq(_ action: TCPAction) -> UInt32? {
    switch action {
    case .send(_, let seq, _, _, _, _): return seq
    case .sendFromBuffer(_, let seq, _, _, _, _, _): return seq
    default: return nil
    }
}

private func sendPayload(_ action: TCPAction) -> Data? {
    if case .send(_, _, _, _, let payload, _) = action { return payload }
    return nil
}

private func sendPayloadCount(_ action: TCPAction) -> Int? {
    switch action {
    case .send(_, _, _, _, let payload, _): return payload.count
    case .sendFromBuffer(_, _, _, _, _, let length, _): return length
    default: return nil
    }
}

@Test func sendDataAdvancesFromSndNxtNotSndUna() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    let first = pcb.onAppSend(Data(repeating: 0x11, count: 2000))
    let seq0 = first.compactMap(sendSeq).first
    let lens = first.compactMap(sendPayloadCount)
    #expect(seq0 == pcb.iss &+ 1)
    #expect(lens.first == Int(pcb.mss))
    #expect(lens.reduce(0, +) == 2000)

    let second = pcb.onAppSend(Data([0x22]))
    let seq1 = second.compactMap(sendSeq).first
    #expect(seq1 == pcb.iss &+ 1 &+ 2000)
}

@Test func finWithPayloadDoesNotRewindRcvNxt() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    #expect(pcb.rcvNxt == 1001)
    let payload = Data([1, 2, 3, 4])
    let fin = TCPSegment(
        flow: pcb.flow, seq: 1001, ack: pcb.iss &+ 1,
        flags: .fin.union(.ack), window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: payload.count,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    _ = pcb.onSegment(fin, payload: payload)
    #expect(pcb.rcvNxt == 1001 + 4 + 1)
    #expect(pcb.state == .closeWait)
}

@Test func synInEstablishedDoesNotResetRcvNxt() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    #expect(pcb.rcvNxt == 1001)
    let syn = TCPSegment(
        flow: pcb.flow, seq: 9_999, ack: 0, flags: .syn, window: 1000,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    _ = pcb.onSegment(syn, payload: Data())
    #expect(pcb.rcvNxt == 1001)
    #expect(pcb.state == .established)
}

@Test func finWait1FinAckEntersTimeWaitWithoutClosingPCB() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    _ = pcb.onAppClose()
    #expect(pcb.state == .finWait1)
    let finAck = TCPSegment(
        flow: pcb.flow, seq: 1001, ack: pcb.sndNxt,
        flags: .fin.union(.ack), window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    let actions = pcb.onSegment(finAck, payload: Data())
    #expect(pcb.state == .timeWait)
    #expect(pcb.deadlines.timeWaitAt != nil)
    #expect(!actions.contains { if case .closed = $0 { return true } else { return false } })
}

@Test func synWindowIsNotScaledAndPeerMustOfferScale() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    let syn = TCPSegment(
        flow: pcb.flow, seq: 1, ack: 0, flags: .syn, window: 1000,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    _ = pcb.onSegment(syn, payload: Data())
    #expect(!pcb.windowScaleEnabled)
    #expect(pcb.sndWnd == 1000)
    #expect(pcb.advertisedWindow == UInt16(min(pcb.rcvWnd, UInt32(UInt16.max))))
}

@Test func unacceptableHandshakeAckResets() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    let syn = TCPSegment(
        flow: pcb.flow, seq: 1, ack: 0, flags: .syn, window: 1000,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    _ = pcb.onSegment(syn, payload: Data())
    let bogus = TCPSegment(
        flow: pcb.flow, seq: 2, ack: pcb.iss &+ 99, flags: .ack, window: 1000,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    let actions = pcb.onSegment(bogus, payload: Data())
    #expect(pcb.state == .closed)
    #expect(actions.contains { if case .send(let flags, _, _, _, _, _) = $0 { return flags.contains(.rst) } else { return false } })
}

@Test func idleTimeoutEmitsRstSegment() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    let syn = TCPSegment(
        flow: pcb.flow, seq: 1, ack: 0, flags: .syn, window: 1000,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    _ = pcb.onSegment(syn, payload: Data())
    let done = pcb.onTimeout(.idle)
    #expect(pcb.state == .closed)
    #expect(done.contains { if case .send(let flags, _, _, _, _, _) = $0 { return flags.contains(.rst) } else { return false } })
    #expect(done.contains { if case .closed = $0 { return true } else { return false } })
}

@Test func ipv4MoreFragmentsAreRejected() throws {
    var buf = PacketBuffer(capacity: 40)
    IPWire.appendIPv4(&buf, src: IPWire.v4(client), dst: IPWire.v4(server), total: 20, proto: 6, df: false)
    buf.withUnsafeMutableBytes { raw in
        raw.storeBytes(of: UInt16(0x2000).bigEndian, toByteOffset: 6, as: UInt16.self)
    }
    IPWire.fillIPv4HeaderChecksum(&buf)
    #expect(throws: PacketParseError.fragment) {
        try IPHeader.peek(buf.asSharedData())
    }
}

@Test func truncatedIPv4TcpHeaderDoesNotOverread() {
    var buf = PacketBuffer(capacity: 20)
    IPWire.appendIPv4(&buf, src: IPWire.v4(client), dst: IPWire.v4(server), total: 20, proto: 6)
    IPWire.fillIPv4HeaderChecksum(&buf)
    let data = buf.asSharedData()
    #expect(throws: PacketParseError.self) {
        _ = try IPPacket.parse(PacketBuffer(wrapping: data))
    }
}

@Test func persistTimerSendsWindowProbe() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    pcb.sndWnd = 0
    _ = pcb.ensureSendBuffer().write(Data([0xab]))
    let probe = pcb.onTimeout(.persist)
    #expect(probe.contains { action in
        if case .send(_, let seq, _, _, let payload, _) = action {
            return seq == pcb.sndUna && payload == Data([0xab])
        }
        return false
    })
}

@Test func unknownFlowEllicitsRst() async throws {
    let sink = RecordingSink()
    let stack = TCPStack(config: TCPStackConfig(loopCount: 1), sink: sink)
    let ack = PacketBuilder.tcp(
        flow: testFlow(51_000),
        seq: 1, ack: 1, flags: .ack, window: 1000
    ).asSharedData()
    await stack.ingest(ack)
    let tx = sink.snapshot()
    #expect(tx.count == 1)
    let parsed = try IPPacket.parse(PacketBuffer(wrapping: tx[0]))
    #expect(parsed.segment.hasRST)
}

@Test func maxConnectionsDropsNewSynWithRst() async throws {
    let sink = RecordingSink()
    let stack = TCPStack(
        config: TCPStackConfig(loopCount: 1, maxConnections: 1),
        sink: sink
    )
    let syn1 = PacketBuilder.tcp(
        flow: testFlow(52_000), seq: 1, ack: 0, flags: .syn, window: 1000
    ).asSharedData()
    await stack.ingest(syn1)
    sink.removeAll()
    let syn2 = PacketBuilder.tcp(
        flow: testFlow(52_001), seq: 1, ack: 0, flags: .syn, window: 1000
    ).asSharedData()
    await stack.ingest(syn2)
    let tx = sink.snapshot()
    #expect(tx.count == 1)
    let parsed = try IPPacket.parse(PacketBuffer(wrapping: tx[0]))
    #expect(parsed.segment.hasRST)
    #expect(await stack.connectionCount() == 1)
}

@Test func ringBufferPeekOffset() {
    let ring = ByteRingBuffer(capacity: 8)
    #expect(ring.write(Data([1, 2, 3, 4, 5, 6])) == 6)
    #expect(Array(ring.peek(offset: 2, maxCount: 3)) == [3, 4, 5])
    ring.consume(4)
    #expect(ring.write(Data([7, 8, 9, 10])) == 4)
    #expect(Array(ring.peek(offset: 2, maxCount: 4)) == [7, 8, 9, 10])
}

@Test func ackFillsWindowFromSendBuffer() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    pcb.congestion.cubic.cwnd = UInt32(pcb.mss)
    let first = pcb.onAppSend(Data(repeating: 1, count: 3000))
    #expect(first.compactMap(sendPayloadCount).reduce(0, +) == Int(pcb.mss))
    let ack = TCPSegment(
        flow: pcb.flow, seq: 1001, ack: pcb.sndNxt, flags: .ack, window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    let more = pcb.onSegment(ack, payload: Data())
    #expect(more.compactMap(sendPayloadCount).reduce(0, +) > 0)
}

@Test func fullAckCancelsRetransmitTimer() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    _ = pcb.onAppSend(Data([1, 2, 3]))
    #expect(pcb.deadlines.retransmitAt != nil)
    let ack = TCPSegment(
        flow: pcb.flow, seq: 1001, ack: pcb.sndNxt, flags: .ack, window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    _ = pcb.onSegment(ack, payload: Data())
    #expect(pcb.deadlines.retransmitAt == nil)
    #expect(pcb.inflight == 0)
}

@Test func rstWithWrongSeqIsIgnored() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    let rst = TCPSegment(
        flow: pcb.flow, seq: pcb.rcvNxt &+ 5_000_000, ack: 0, flags: .rst, window: 0,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    let actions = pcb.onSegment(rst, payload: Data())
    #expect(pcb.state == .established)
    #expect(!actions.contains { if case .closed = $0 { return true } else { return false } })
}

@Test func rstAtRcvNxtClosesWithoutReplyRst() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    let rst = TCPSegment(
        flow: pcb.flow, seq: pcb.rcvNxt, ack: 0, flags: .rst, window: 0,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    let actions = pcb.onSegment(rst, payload: Data())
    #expect(pcb.state == .closed)
    #expect(actions.contains { if case .closed = $0 { return true } else { return false } })
    #expect(!actions.contains { if case .send(let flags, _, _, _, _, _) = $0 { return flags.contains(.rst) } else { return false } })
}

@Test func threeDupAcksRetransmitSndUna() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    _ = pcb.onAppSend(Data(repeating: 1, count: Int(pcb.mss) * 2))
    let una = pcb.sndUna
    let dup = TCPSegment(
        flow: pcb.flow, seq: 1001, ack: una, flags: .ack, window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    _ = pcb.onSegment(dup, payload: Data())
    _ = pcb.onSegment(dup, payload: Data())
    let third = pcb.onSegment(dup, payload: Data())
    #expect(third.contains { action in
        if case .sendFromBuffer(_, let seq, _, _, _, _, _) = action {
            return seq == una
        }
        return false
    })
}

@Test func peerMssIsClampedToMaxMss() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000, maxMss: 1460)
    let syn = TCPSegment(
        flow: pcb.flow, seq: 1, ack: 0, flags: .syn, window: 1000,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: TCPOptions(mss: 65_000, windowScale: nil, sackPermitted: false, tfoCookie: nil),
        ipHeaderLength: 20, version: .v4
    )
    _ = pcb.onSegment(syn, payload: Data())
    #expect(pcb.mss == 1460)
}

@Test func appSendGrowsBufferInsteadOfDropping() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    pcb.congestion.cubic.cwnd = UInt32(pcb.mss)
    let count = 80 * 1024
    _ = pcb.onAppSend(Data(repeating: 1, count: count))
    #expect(pcb.sendBuffer?.count == count)
}

@Test func rstInWindowSendsChallengeAck() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    let rst = TCPSegment(
        flow: pcb.flow, seq: pcb.rcvNxt &+ 10, ack: 0, flags: .rst, window: 0,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    let actions = pcb.onSegment(rst, payload: Data())
    #expect(pcb.state == .established)
    #expect(actions.contains { action in
        if case .send(let flags, _, _, _, let payload, _) = action {
            return flags.contains(.ack) && !flags.contains(.rst) && payload.isEmpty
        }
        return false
    })
}

@Test func fourthDupAckDoesNotRetransmitAgain() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    _ = pcb.onAppSend(Data(repeating: 1, count: Int(pcb.mss) * 2))
    let una = pcb.sndUna
    let dup = TCPSegment(
        flow: pcb.flow, seq: 1001, ack: una, flags: .ack, window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    _ = pcb.onSegment(dup, payload: Data())
    _ = pcb.onSegment(dup, payload: Data())
    _ = pcb.onSegment(dup, payload: Data())
    let cwnd = pcb.congestion.cwnd
    let fourth = pcb.onSegment(dup, payload: Data())
    #expect(pcb.congestion.cwnd == cwnd)
    #expect(!fourth.contains { action in
        if case .sendFromBuffer(_, let seq, _, _, _, _, _) = action { return seq == una }
        return false
    })
}

@Test func partialAckKeepsRetransmitTimerArmed() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    _ = pcb.onAppSend(Data(repeating: 1, count: Int(pcb.mss) * 2))
    #expect(pcb.deadlines.retransmitAt != nil)
    let ack = TCPSegment(
        flow: pcb.flow, seq: 1001, ack: pcb.sndUna &+ UInt32(pcb.mss), flags: .ack, window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    _ = pcb.onSegment(ack, payload: Data())
    #expect(pcb.inflight > 0)
    #expect(pcb.deadlines.retransmitAt != nil)
}

@Test func retransmissionTimeoutWithNoInflightDoesNotCollapse() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    #expect(pcb.inflight == 0)
    let cwnd = pcb.congestion.cwnd
    let actions = pcb.onTimeout(.retransmission)
    #expect(pcb.state == .established)
    #expect(pcb.congestion.cwnd == cwnd)
    #expect(!actions.contains { if case .closed = $0 { return true } else { return false } })
}

@Test func windowOpenAfterZeroSendsBufferedData() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    pcb.sndWnd = 0
    let queued = pcb.onAppSend(Data([0xab, 0xcd]))
    #expect(queued.compactMap(sendPayloadCount).reduce(0, +) == 0)
    let open = TCPSegment(
        flow: pcb.flow, seq: 1001, ack: pcb.sndUna, flags: .ack, window: 4_000,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    let flushed = pcb.onSegment(open, payload: Data())
    #expect(flushed.compactMap(sendPayloadCount).reduce(0, +) == 2)
}

@Test func synAckAdvertisesClampedMaxMss() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000, maxMss: 1_200)
    let syn = TCPSegment(
        flow: pcb.flow, seq: 1, ack: 0, flags: .syn, window: 1000,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: TCPOptions(mss: 9_000, windowScale: nil, sackPermitted: false, tfoCookie: nil),
        ipHeaderLength: 20, version: .v4
    )
    let actions = pcb.onSegment(syn, payload: Data())
    #expect(pcb.mss == 1_200)
    #expect(actions.contains { action in
        if case .send(let flags, _, _, _, _, let options) = action {
            return flags.contains(.syn) && flags.contains(.ack) && options.mss == 1_200
        }
        return false
    })
}

@Test func sackOfLaterSegmentRetransmitsHole() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    let segmentSize = Int(pcb.mss)
    _ = pcb.onAppSend(Data(repeating: 0x11, count: segmentSize * 3))
    let una = pcb.sndUna
    let sacked = TCPOptions(
        mss: nil, windowScale: nil, sackPermitted: false, tfoCookie: nil,
        sackBlocks: [SACKBlock(left: una &+ UInt32(segmentSize), right: una &+ UInt32(segmentSize * 3))]
    )
    let dup = TCPSegment(
        flow: pcb.flow, seq: 1001, ack: una, flags: .ack, window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: sacked, ipHeaderLength: 20, version: .v4
    )
    let actions = pcb.onSegment(dup, payload: Data())
    #expect(actions.contains { action in
        if case .sendFromBuffer(_, let seq, _, _, _, let length, _) = action {
            return seq == una && length == segmentSize
        }
        return false
    })
    let again = pcb.onSegment(dup, payload: Data())
    #expect(!again.contains { action in
        if case .sendFromBuffer(_, let seq, _, _, _, _, _) = action { return seq == una }
        return false
    })
}

@Test func sackBelowDupThreshDoesNotRetransmit() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    let segmentSize = Int(pcb.mss)
    _ = pcb.onAppSend(Data(repeating: 0x22, count: segmentSize * 3))
    let una = pcb.sndUna
    let sacked = TCPOptions(
        mss: nil, windowScale: nil, sackPermitted: false, tfoCookie: nil,
        sackBlocks: [SACKBlock(left: una &+ UInt32(segmentSize) * 2, right: una &+ UInt32(segmentSize) * 3)]
    )
    let dup = TCPSegment(
        flow: pcb.flow, seq: 1001, ack: una, flags: .ack, window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: sacked, ipHeaderLength: 20, version: .v4
    )
    let actions = pcb.onSegment(dup, payload: Data())
    #expect(!actions.contains { action in
        if case .sendFromBuffer(_, let seq, _, _, _, _, _) = action { return seq == una }
        return false
    })
}

@Test func sackIsLostRetransmitsTwoSegmentsOfHole() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    let segmentSize = Int(pcb.mss)
    _ = pcb.onAppSend(Data(repeating: 0x33, count: segmentSize * 5))
    let una = pcb.sndUna
    let sacked = TCPOptions(
        mss: nil, windowScale: nil, sackPermitted: false, tfoCookie: nil,
        sackBlocks: [SACKBlock(left: una &+ UInt32(segmentSize * 2), right: una &+ UInt32(segmentSize * 5))]
    )
    let dup = TCPSegment(
        flow: pcb.flow, seq: 1001, ack: una, flags: .ack, window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: sacked, ipHeaderLength: 20, version: .v4
    )
    let actions = pcb.onSegment(dup, payload: Data())
    let rexmit = actions.compactMap { action -> UInt32? in
        if case .sendFromBuffer(_, let seq, _, _, _, _, _) = action { return seq }
        return nil
    }
    #expect(rexmit.contains(una))
    #expect(rexmit.contains(una &+ UInt32(segmentSize)))
}

@Test func closeDrainsUnsentThenSendsFin() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    pcb.congestion.cubic.cwnd = UInt32(pcb.mss)
    _ = pcb.onAppSend(Data(repeating: 1, count: 3000))
    _ = pcb.onAppClose()
    #expect(pcb.state == .established)
    let ack = TCPSegment(
        flow: pcb.flow, seq: 1001, ack: pcb.sndNxt, flags: .ack, window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    let after = pcb.onSegment(ack, payload: Data())
    #expect(pcb.state == .finWait1)
    #expect(after.contains { action in
        if case .send(let flags, _, _, _, _, _) = action { return flags.contains(.fin) }
        return false
    })
}

@Test func applyPMTUShrinksMss() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000, maxMss: 1460)
    handshake(pcb: pcb)
    pcb.applyPMTU(mtu: 800)
    #expect(pcb.mss == 760)
}

@Test func largeDeliveryCancelsDelayedAckWithWindowUpdate() {
    let pcb = TCPControlBlock(
        flow: testFlow(),
        state: .listen,
        iss: 5000,
        timerConfig: .init(delayedAck: .milliseconds(20))
    )
    handshake(pcb: pcb)
    let count = Int(pcb.mss) * 2
    let data = TCPSegment(
        flow: pcb.flow, seq: 1001, ack: pcb.iss &+ 1, flags: .ack, window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: count,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    let actions = pcb.onSegment(data, payload: Data(repeating: 1, count: count))
    #expect(pcb.deadlines.delayedAckAt == nil)
    #expect(actions.contains { if case .send = $0 { return true } else { return false } })
}
