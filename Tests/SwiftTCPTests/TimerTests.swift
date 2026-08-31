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
