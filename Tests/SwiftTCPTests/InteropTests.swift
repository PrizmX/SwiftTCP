import Foundation
import Testing
@testable import SwiftTCP

private let clientAddr = IPAddress.v4(octets: (10, 0, 0, 1))
private let serverAddr = IPAddress.v4(octets: (10, 0, 0, 2))

private func testFlow(_ sport: UInt16 = 40_100) -> FlowKey {
    FlowKey(src: clientAddr, srcPort: sport, dst: serverAddr, dstPort: 80)
}

private func tcpPacket(
    flow: FlowKey,
    seq: UInt32,
    ack: UInt32,
    flags: TCPFlags,
    payload: Data = Data(),
    options: TCPOptions = .empty
) -> Data {
    PacketBuilder.tcp(
        flow: flow, seq: seq, ack: ack, flags: flags, window: 65_535,
        options: options, payload: payload
    ).asSharedData()
}

private final class CollectingHandler: TCPStreamHandler, @unchecked Sendable {
    private let lock = NSLock()
    private var inbound = Data()
    private var established: [FlowKey] = []
    private var closed: [FlowKey] = []

    func onEstablished(flow: FlowKey) {
        lock.lock()
        established.append(flow)
        lock.unlock()
    }

    func onData(flow: FlowKey, data: Data) {
        _ = flow
        lock.lock()
        inbound.append(data)
        lock.unlock()
    }

    func onClosed(flow: FlowKey) {
        lock.lock()
        closed.append(flow)
        lock.unlock()
    }

    func snapshot() -> (established: [FlowKey], inbound: Data, closed: [FlowKey]) {
        lock.lock()
        defer { lock.unlock() }
        return (established, inbound, closed)
    }
}

private struct ClientPeer {
    var flow: FlowKey
    var seq: UInt32
    var ack: UInt32
}

private func handshake(
    stack: TCPStack,
    sink: RecordingSink,
    events: CollectingHandler,
    flow: FlowKey
) async throws -> ClientPeer {
    let syn = tcpPacket(
        flow: flow, seq: 1_000, ack: 0, flags: .syn,
        options: TCPOptions(mss: 1460, windowScale: 7, sackPermitted: true, tfoCookie: nil)
    )
    await stack.ingest(syn)
    let synAckData = sink.snapshot()
    #expect(synAckData.count >= 1)
    let synAck = try IPPacket.parse(PacketBuffer(wrapping: synAckData[0]))
    sink.removeAll()
    let ack = synAck.segment.seq &+ 1
    await stack.ingest(tcpPacket(flow: flow, seq: 1_001, ack: ack, flags: .ack))
    #expect(events.snapshot().established.contains(flow))
    return ClientPeer(flow: flow, seq: 1_001, ack: ack)
}

private func ackAllData(from tx: [Data], peer: inout ClientPeer) throws -> (payload: Data, acks: [Data]) {
    var payload = Data()
    var acks: [Data] = []
    acks.reserveCapacity(tx.count)
    for data in tx {
        let packet = try IPPacket.parse(PacketBuffer(wrapping: data))
        let segment = packet.segment
        if segment.payloadLength > 0 {
            payload.append(packet.retainedPayload())
            peer.ack = segment.seq &+ UInt32(segment.payloadLength)
            acks.append(tcpPacket(flow: peer.flow, seq: peer.seq, ack: peer.ack, flags: .ack))
        }
    }
    return (payload, acks)
}

/// Pull stack TX, ACK it, until `expected` bytes are collected or the deadline hits.
private func drainDownload(
    stack: TCPStack,
    sink: RecordingSink,
    peer: inout ClientPeer,
    expected: Int
) async throws -> Data {
    var collected = Data()
    collected.reserveCapacity(expected)
    let deadline = ContinuousClock().now.advanced(by: .seconds(5))
    while collected.count < expected {
        if ContinuousClock().now >= deadline {
            Issue.record("download drain timed out at \(collected.count)/\(expected)")
            break
        }
        let tx = sink.snapshot()
        sink.removeAll()
        let result = try ackAllData(from: tx, peer: &peer)
        collected.append(result.payload)
        if !result.acks.isEmpty {
            await stack.ingestBatch(result.acks)
        } else {
            try await Task.sleep(for: .milliseconds(1))
        }
    }
    return collected
}

@Test func interopClientUploadsAndStackDeliversIntact() async throws {
    let sink = RecordingSink()
    let events = CollectingHandler()
    let stack = TCPStack(config: TCPStackConfig(loopCount: 1), sink: sink, streams: events)
    let flow = testFlow(40_110)
    var peer = try await handshake(stack: stack, sink: sink, events: events, flow: flow)

    let payload = Data((0..<64 * 1024).map { UInt8($0 & 0xff) })
    var offset = 0
    while offset < payload.count {
        let chunkSize = min(1400, payload.count - offset)
        let chunk = payload.subdata(in: offset..<(offset + chunkSize))
        await stack.ingest(
            tcpPacket(
                flow: flow, seq: peer.seq, ack: peer.ack,
                flags: .ack.union(.psh), payload: chunk
            )
        )
        peer.seq &+= UInt32(chunkSize)
        offset += chunkSize
        sink.removeAll()
    }
    #expect(events.snapshot().inbound == payload)
}

@Test func interopStackDownloadSurvivesSendBufferCap() async throws {
    let sink = RecordingSink()
    let events = CollectingHandler()
    let stack = TCPStack(config: TCPStackConfig(loopCount: 1), sink: sink, streams: events)
    let flow = testFlow(40_111)
    let peer = try await handshake(stack: stack, sink: sink, events: events, flow: flow)

    let payload = Data((0..<256 * 1024).map { UInt8(($0 * 31) & 0xff) })
    let downloaded = try await withThrowingTaskGroup(of: Data.self) { group in
        group.addTask {
            let written = await stack.send(flow: flow, data: payload)
            #expect(written == payload.count)
            return Data()
        }
        group.addTask {
            var drainPeer = peer
            return try await drainDownload(
                stack: stack,
                sink: sink,
                peer: &drainPeer,
                expected: payload.count
            )
        }
        var result = Data()
        for try await item in group {
            if item.count == payload.count { result = item }
        }
        return result
    }
    #expect(downloaded == payload)
}

@Test func interopHalfCloseAfterUpload() async throws {
    let sink = RecordingSink()
    let events = CollectingHandler()
    let stack = TCPStack(config: TCPStackConfig(loopCount: 1), sink: sink, streams: events)
    let flow = testFlow(40_112)
    var peer = try await handshake(stack: stack, sink: sink, events: events, flow: flow)

    let payload = Data("hello-interop".utf8)
    await stack.ingest(
        tcpPacket(
            flow: flow, seq: peer.seq, ack: peer.ack,
            flags: .ack.union(.psh), payload: payload
        )
    )
    peer.seq &+= UInt32(payload.count)
    sink.removeAll()
    #expect(events.snapshot().inbound == payload)

    await stack.ingest(
        tcpPacket(flow: flow, seq: peer.seq, ack: peer.ack, flags: .fin.union(.ack))
    )
    #expect(events.snapshot().inbound == payload)

    await stack.close(flow: flow)
    let tx = sink.snapshot()
    let flags = try tx.compactMap { data -> TCPFlags? in
        try IPPacket.parse(PacketBuffer(wrapping: data)).segment.flags
    }
    #expect(flags.contains { $0.contains(.fin) || $0.contains(.ack) })
}

@Test func swiftStackClampsMaxMssToTunnelMTU() {
    let config = SwiftStackConfig(mtu: 1400)
    #expect(config.tcp.maxMss == 1_340)
}

@Test func udpMaxSessionsDropsAdditionalFlows() async throws {
    let sink = RecordingSink()
    let udp = UDPHandler(sink: sink, maxSessions: 1)
    let flow1 = FlowKey(src: clientAddr, srcPort: 1, dst: serverAddr, dstPort: 53)
    let flow2 = FlowKey(src: clientAddr, srcPort: 2, dst: serverAddr, dstPort: 54)
    let p1 = UDPPacket.encapsulate(flow: flow1, payload: Data([1])).asSharedData()
    let p2 = UDPPacket.encapsulate(flow: flow2, payload: Data([2])).asSharedData()
    await udp.ingest(header: try IPHeader.peek(p1), packet: p1)
    await udp.ingest(header: try IPHeader.peek(p2), packet: p2)
    #expect(await udp.sessionCount() == 1)
    #expect(await udp.droppedAtCap == 1)
}

#if canImport(Network)
import Network

private final class ByteStreamBox: TCPByteStream, @unchecked Sendable {
    var inner: (any TCPByteStream)?

    func send(flow: FlowKey, data: Data) async -> Int {
        guard let inner else { return 0 }
        return await inner.send(flow: flow, data: data)
    }

    func close(flow: FlowKey) async {
        await inner?.close(flow: flow)
    }
}

private final class TeeStreams: TCPStreamHandler, @unchecked Sendable {
    let first: any TCPStreamHandler
    let second: any TCPStreamHandler

    init(_ first: any TCPStreamHandler, _ second: any TCPStreamHandler) {
        self.first = first
        self.second = second
    }

    func onEstablished(flow: FlowKey) {
        first.onEstablished(flow: flow)
        second.onEstablished(flow: flow)
    }

    func onData(flow: FlowKey, data: Data) {
        first.onData(flow: flow, data: data)
        second.onData(flow: flow, data: data)
    }

    func onClosed(flow: FlowKey) {
        first.onClosed(flow: flow)
        second.onClosed(flow: flow)
    }
}

private func startEchoListener() async throws -> (NWListener, UInt16) {
    let parameters = NWParameters.tcp
    parameters.acceptLocalOnly = true
    parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
    let listener = try NWListener(using: parameters)
    listener.newConnectionHandler = { connection in
        connection.start(queue: .global())
        final class EchoPump: @unchecked Sendable {
            let connection: NWConnection
            init(_ connection: NWConnection) { self.connection = connection }
            func pump() {
                connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { content, _, isComplete, error in
                    if let content, !content.isEmpty {
                        self.connection.send(content: content, completion: .contentProcessed { _ in })
                    }
                    if isComplete || error != nil {
                        self.connection.cancel()
                    } else {
                        self.pump()
                    }
                }
            }
        }
        EchoPump(connection).pump()
    }
    let port: UInt16 = try await withCheckedThrowingContinuation { continuation in
        final class Gate: @unchecked Sendable {
            let lock = NSLock()
            var resumed = false
            func take() -> Bool {
                lock.lock()
                defer { lock.unlock() }
                if resumed { return false }
                resumed = true
                return true
            }
        }
        let gate = Gate()
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                guard gate.take() else { return }
                if let port = listener.port?.rawValue {
                    continuation.resume(returning: port)
                } else {
                    continuation.resume(throwing: CancellationError())
                }
            case .failed(let error):
                guard gate.take() else { return }
                continuation.resume(throwing: error)
            default:
                break
            }
        }
        listener.start(queue: .global())
    }
    return (listener, port)
}

@Test func interopForwarderEchoesThroughKernelTCP() async throws {
    let (listener, port) = try await startEchoListener()
    defer { listener.cancel() }

    let loopback = IPAddress.v4(octets: (127, 0, 0, 1))
    let flow = FlowKey(src: clientAddr, srcPort: 40_200, dst: loopback, dstPort: port)
    let sink = RecordingSink()
    let events = CollectingHandler()
    let box = ByteStreamBox()
    let forwarder = NWConnectionForwarder(stack: box)
    let streams = TeeStreams(events, forwarder)
    let stack = TCPStack(
        config: TCPStackConfig(loopCount: 1, tfo: false),
        sink: sink,
        streams: streams
    )
    box.inner = stack

    var peer = try await handshake(stack: stack, sink: sink, events: events, flow: flow)
    try await Task.sleep(for: .milliseconds(100))
    let payload = Data("kernel-echo-payload".utf8)
    await stack.ingest(
        tcpPacket(
            flow: flow, seq: peer.seq, ack: peer.ack,
            flags: .ack.union(.psh), payload: payload
        )
    )
    peer.seq &+= UInt32(payload.count)

    let deadline = ContinuousClock().now.advanced(by: .seconds(2))
    while events.snapshot().inbound != payload {
        if ContinuousClock().now >= deadline {
            Issue.record("TUN did not deliver payload to forwarder")
            break
        }
        try await Task.sleep(for: .milliseconds(5))
    }
    #expect(events.snapshot().inbound == payload)

    let echoed = try await drainDownload(
        stack: stack, sink: sink, peer: &peer, expected: payload.count
    )
    #expect(echoed == payload)
}
#endif
