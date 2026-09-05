import Foundation
import Testing
@testable import SwiftTCP

/// TUN-style handler: bytes stay with the app until `creditAppReceive`.
private final class HoldingHandler: TCPStreamHandler, @unchecked Sendable {
    var consumesOnData: Bool { false }
    private let lock = NSLock()
    private var inbound = 0

    func onEstablished(flow: FlowKey) { _ = flow }
    func onData(flow: FlowKey, data: Data) {
        _ = flow
        lock.lock()
        inbound += data.count
        lock.unlock()
    }
    func onClosed(flow: FlowKey) { _ = flow }
    var held: Int {
        lock.lock()
        defer { lock.unlock() }
        return inbound
    }
}

private let clientAddr = IPAddress.v4(octets: (10, 0, 0, 1))
private let serverAddr = IPAddress.v4(octets: (10, 0, 0, 2))

private func holdingFlow(_ sport: UInt16 = 41_000) -> FlowKey {
    FlowKey(src: clientAddr, srcPort: sport, dst: serverAddr, dstPort: 80)
}

private func tcpPacket(
    flow: FlowKey,
    seq: UInt32,
    ack: UInt32,
    flags: TCPFlags,
    payload: Data = Data()
) -> Data {
    PacketBuilder.tcp(
        flow: flow,
        seq: seq,
        ack: ack,
        flags: flags,
        window: 65_535,
        options: TCPOptions(mss: 1460, windowScale: 7, sackPermitted: true, tfoCookie: nil),
        payload: payload
    ).asSharedData()
}

private func handshake(
    stack: TCPStack,
    sink: RecordingSink,
    events: HoldingHandler,
    flow: FlowKey
) async throws -> UInt32 {
    _ = events
    await stack.ingest(tcpPacket(flow: flow, seq: 1_000, ack: 0, flags: .syn))
    let synAckData = sink.snapshot()
    #expect(!synAckData.isEmpty)
    let synAck = try IPPacket.parse(PacketBuffer(wrapping: synAckData[0]))
    sink.removeAll()
    let ack = synAck.segment.seq &+ 1
    await stack.ingest(tcpPacket(flow: flow, seq: 1_001, ack: ack, flags: .ack))
    return ack
}

private func lastWindow(_ packets: [Data]) throws -> UInt16 {
    var window: UInt16 = 0
    for data in packets {
        let parsed = try IPPacket.parse(PacketBuffer(wrapping: data))
        window = parsed.segment.window
    }
    return window
}

@Test func holdingAppShrinksReceiveWindowUntilCredit() async throws {
    let sink = RecordingSink()
    let events = HoldingHandler()
    let stack = TCPStack(sink: sink, streams: events)
    let flow = holdingFlow()
    let serverSeq = try await handshake(stack: stack, sink: sink, events: events, flow: flow)

    sink.removeAll()
    let payload = Data(repeating: 0xAB, count: 16_384)
    await stack.ingest(
        tcpPacket(flow: flow, seq: 1_001, ack: serverSeq, flags: [.ack, .psh], payload: payload)
    )
    #expect(events.held == payload.count)

    let shrunk = try lastWindow(sink.snapshot())
    // Window scale 7: full 64 KiB → advertised 512. 16 KiB held must drop that.
    #expect(shrunk < 512)
    #expect(shrunk > 0)

    sink.removeAll()
    await stack.creditAppReceive(flow: flow, bytes: payload.count)
    let restored = try lastWindow(sink.snapshot())
    #expect(restored >= shrunk)
    #expect(restored == 512)
}
