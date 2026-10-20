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

@Test func rtoFloorAndExponentialBackoff() {
    var rtt = RTTEstimator(timers: .init(
        minRTO: .milliseconds(20),
        maxRTO: .seconds(2),
        initialRTO: .milliseconds(50)
    ))
    #expect(rtt.rto == .milliseconds(50))
    rtt.backoff()
    #expect(rtt.rto == .milliseconds(100))
    rtt.backoff()
    #expect(rtt.rto == .milliseconds(200))
    for _ in 0..<8 { rtt.backoff() }
    #expect(rtt.rto == .seconds(2))
    rtt.sample(.microseconds(100))
    #expect(rtt.rto >= .milliseconds(20))
    #expect(rtt.rto <= .seconds(2))
}

@Test func synAckArmsRetransmitDeadlineOnThePCB() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    let syn = TCPSegment(
        flow: pcb.flow, seq: 1, ack: 0, flags: .syn, window: 1000,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    _ = pcb.onSegment(syn, payload: Data())
    #expect(pcb.state == .synReceived)
    #expect(pcb.deadlines.retransmitAt != nil)
    #expect(pcb.deadlines.keepAliveAt == nil)
}

@Test func establishedCancelsRTOAndArmsKeepAlive() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    #expect(pcb.state == .established)
    #expect(pcb.deadlines.retransmitAt == nil)
    #expect(pcb.deadlines.keepAliveAt != nil)
}

@Test func keepAliveSendsProbeThenClosesAfterBudget() {
    let timers = TCPTimerConfig(keepAliveProbes: 2)
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000, timerConfig: timers)
    handshake(pcb: pcb)

    let first = pcb.onTimeout(.keepAlive)
    #expect(pcb.state == .established)
    #expect(first.contains { action in
        if case .send(let flags, let seq, _, _, let payload, _) = action {
            return flags.contains(.ack) && seq == pcb.sndNxt &- 1 && payload.isEmpty
        }
        return false
    })
    #expect(pcb.deadlines.keepAliveAt != nil)

    _ = pcb.onTimeout(.keepAlive)
    #expect(pcb.state == .established)

    let last = pcb.onTimeout(.keepAlive)
    #expect(pcb.state == .closed)
    #expect(last.contains { if case .closed = $0 { return true } else { return false } })
    #expect(pcb.deadlines.earliest == nil)
}

private func segment(_ pcb: TCPControlBlock, seq: UInt32, ack: UInt32, flags: TCPFlags = .ack, payloadLength: Int = 0) -> TCPSegment {
    TCPSegment(
        flow: pcb.flow, seq: seq, ack: ack, flags: flags, window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: payloadLength,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
}

/// BSD / XNU keep-alive probe: zero-length ACK with SEQ = SND.UNA - 1 (one left of our RCV.NXT).
private func keepAliveProbe(_ pcb: TCPControlBlock) -> TCPSegment {
    segment(pcb, seq: pcb.rcvNxt &- 1, ack: pcb.sndNxt)
}

private func pureAcks(_ actions: [TCPAction]) -> [(seq: UInt32, ack: UInt32)] {
    actions.compactMap {
        if case .send(let flags, let seq, let ack, _, let payload, _) = $0, flags == .ack, payload.isEmpty {
            return (seq, ack)
        }
        return nil
    }
}

@Test func peerKeepAliveProbeIsAcked() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    _ = pcb.onSegment(segment(pcb, seq: 1001, ack: pcb.sndNxt, flags: [.ack, .psh], payloadLength: 100), payload: Data(count: 100))
    _ = pcb.onAppSend(Data(count: 50))
    _ = pcb.onSegment(segment(pcb, seq: 1101, ack: pcb.sndNxt), payload: Data())
    #expect(pcb.rcvNxt == 1101 && pcb.sndUna == pcb.sndNxt)

    let acks = pureAcks(pcb.onSegment(keepAliveProbe(pcb), payload: Data()))
    #expect(acks.count == 1)
    #expect(acks.first?.seq == pcb.sndNxt)
    #expect(acks.first?.ack == 1101)
    #expect(pcb.state == .established)
    #expect(pcb.dupAcks == 0)

    // An acceptable pure ACK is still not ACKed (no ACK-of-ACK loop).
    #expect(pureAcks(pcb.onSegment(segment(pcb, seq: 1101, ack: pcb.sndNxt), payload: Data())).isEmpty)
}

/// Go's default keep-alive (15 s idle and interval, 9 probes) times an idle connection out
/// after ~150 s unless every probe is answered.
@Test func idleConnectionSurvivesPeerKeepAlive() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    let start = ContinuousClock().now
    for round in 1...12 {
        let now = start.advanced(by: .seconds(15 * round))
        for kind in pcb.deadlines.expired(now: now) { _ = pcb.onTimeout(kind, now: now) }
        let acks = pureAcks(pcb.onSegment(keepAliveProbe(pcb), payload: Data(), now: now))
        #expect(acks.count == 1)
        #expect(pcb.state == .established)
    }
    #expect(pcb.deadlines.keepAliveAt != nil)
}

/// After the app's FIN (it shut down writing) XNU keeps probing from FIN-WAIT-2: SEQ = its FIN.
@Test func keepAliveProbeInCloseWaitIsAcked() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    _ = pcb.onSegment(segment(pcb, seq: 1001, ack: pcb.sndNxt, flags: [.ack, .fin]), payload: Data())
    #expect(pcb.state == .closeWait)
    let acks = pureAcks(pcb.onSegment(keepAliveProbe(pcb), payload: Data()))
    #expect(acks.count == 1)
    #expect(acks.first?.ack == 1002)
    #expect(pcb.state == .closeWait)
}

@Test func rtoExhaustionClosesTheFlow() {
    let timers = TCPTimerConfig(maxRetransmits: 2)
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000, timerConfig: timers)
    let syn = TCPSegment(
        flow: pcb.flow, seq: 1, ack: 0, flags: .syn, window: 1000,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    _ = pcb.onSegment(syn, payload: Data())
    _ = pcb.onTimeout(.retransmission)
    #expect(pcb.state == .synReceived)
    let done = pcb.onTimeout(.retransmission)
    #expect(pcb.state == .closed)
    #expect(done.contains { if case .closed = $0 { return true } else { return false } })
}

@Test func delayedAckArmsInsteadOfImmediateWhenConfigured() {
    let timers = TCPTimerConfig(delayedAck: .milliseconds(20))
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000, timerConfig: timers)
    handshake(pcb: pcb)
    let data = TCPSegment(
        flow: pcb.flow, seq: 1001, ack: pcb.iss &+ 1, flags: .ack, window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: 4,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    let actions = pcb.onSegment(data, payload: Data([1, 2, 3, 4]))
    #expect(pcb.deadlines.delayedAckAt != nil)
    #expect(!actions.contains { if case .send = $0 { return true } else { return false } })
}

@Test func handshakeIdleTimeoutReapsHalfOpen() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    let syn = TCPSegment(
        flow: pcb.flow, seq: 1, ack: 0, flags: .syn, window: 1000,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    _ = pcb.onSegment(syn, payload: Data())
    #expect(pcb.state == .synReceived)
    #expect(pcb.deadlines.idleAt != nil)
    let done = pcb.onTimeout(.idle)
    #expect(pcb.state == .closed)
    #expect(done.contains { if case .closed = $0 { return true } else { return false } })
}

@Test func finWait2IdleTimeoutReapsPeerGoneAfterOurClose() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    _ = pcb.onAppClose()
    #expect(pcb.state == .finWait1)
    let ack = TCPSegment(
        flow: pcb.flow, seq: 1001, ack: pcb.sndNxt, flags: .ack, window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    _ = pcb.onSegment(ack, payload: Data())
    #expect(pcb.state == .finWait2)
    #expect(pcb.deadlines.idleAt != nil)
    _ = pcb.onTimeout(.idle)
    #expect(pcb.state == .closed)
}

@Test func closeWaitIdleTimeoutReapsAppNeverClosed() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    let fin = TCPSegment(
        flow: pcb.flow, seq: 1001, ack: pcb.iss &+ 1, flags: .fin.union(.ack), window: 65_535,
        dataOffset: 20, payloadOffset: 40, payloadLength: 0,
        options: .empty, ipHeaderLength: 20, version: .v4
    )
    _ = pcb.onSegment(fin, payload: Data())
    #expect(pcb.state == .closeWait)
    #expect(pcb.deadlines.idleAt != nil)
    _ = pcb.onTimeout(.idle)
    #expect(pcb.state == .closed)
}

@Test func maxLifetimeReapsAnyPCB() {
    let pcb = TCPControlBlock(
        flow: testFlow(),
        state: .listen,
        iss: 5000,
        timerConfig: .init(maxLifetime: .milliseconds(1))
    )
    handshake(pcb: pcb)
    #expect(pcb.deadlines.lifetimeAt != nil)
    _ = pcb.onTimeout(.lifetime)
    #expect(pcb.state == .closed)
}

@Test func establishedDoesNotUseIdleTTLKeepAliveOwnsIt() {
    let pcb = TCPControlBlock(flow: testFlow(), state: .listen, iss: 5000)
    handshake(pcb: pcb)
    #expect(pcb.state == .established)
    #expect(pcb.deadlines.idleAt == nil)
    #expect(pcb.deadlines.keepAliveAt != nil)
}
