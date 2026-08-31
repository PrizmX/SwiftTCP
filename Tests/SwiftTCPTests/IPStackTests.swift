import Foundation
import Testing
@testable import SwiftTCP

private let client = IPAddress.v4(octets: (10, 0, 0, 1))
private let server = IPAddress.v4(octets: (10, 0, 0, 2))
private let client6 = IPAddress(v6High: 0x20010db800000000, v6Low: 1)
private let server6 = IPAddress(v6High: 0x20010db800000000, v6Low: 2)

@Test func ipHeaderPeeksIPv4AndIPv6WithoutCopy() throws {
    let tcp = PacketBuilder.tcp(
        flow: FlowKey(src: client, srcPort: 1, dst: server, dstPort: 80),
        seq: 1, ack: 0, flags: .syn, window: 1000
    ).asSharedData()
    let v4 = try IPHeader.peek(tcp)
    #expect(v4.version == .v4)
    #expect(v4.protocol == .tcp)
    #expect(v4.src == client)
    #expect(v4.dst == server)
    #expect(v4.dontFragment)
    #expect(IPDemuxer.classify(v4) == .tcp)

    let tcp6 = PacketBuilder.tcp(
        flow: FlowKey(src: client6, srcPort: 1, dst: server6, dstPort: 443),
        seq: 1, ack: 0, flags: .syn, window: 1000
    ).asSharedData()
    let v6 = try IPHeader.peek(tcp6)
    #expect(v6.version == .v6)
    #expect(v6.dontFragment)
    #expect(IPDemuxer.classify(v6) == .tcp)
}

@Test func udpDatagramRoundTrip() throws {
    let flow = FlowKey(src: client, srcPort: 53_000, dst: server, dstPort: 53)
    let payload = Data([0xde, 0xad, 0xbe, 0xef])
    let packet = UDPPacket.encapsulate(flow: flow, payload: payload).asSharedData()
    let ip = try IPHeader.peek(packet)
    #expect(IPDemuxer.classify(ip) == .udp)
    let udp = try UDPDatagram.parse(packet: packet, ip: ip)
    #expect(udp.flow == flow)
    #expect(Array(packet[udp.payloadOffset..<(udp.payloadOffset + udp.payloadLength)]) == [0xde, 0xad, 0xbe, 0xef])
}

@Test func icmpEchoReplySwapsAddressesAndType() throws {
    let request = ICMPHandler.icmpv4(
        src: client,
        dst: server,
        type: ICMPv4Type.echoRequest,
        code: 0,
        rest: 0x1234_0001,
        payload: Data("ping".utf8)
    ).asSharedData()
    let header = try IPHeader.peek(request)
    guard let reply = ICMPHandler.echoReply(header: header, original: request) else {
        Issue.record("expected echo reply")
        return
    }
    let replyData = reply.asSharedData()
    let replyHeader = try IPHeader.peek(replyData)
    #expect(replyHeader.src == server)
    #expect(replyHeader.dst == client)
    let message = try ICMPMessage.parse(packet: replyData, ip: replyHeader)
    #expect(message.type == ICMPv4Type.echoReply)
    #expect(message.rest == 0x1234_0001)
}

@Test func icmpv6EchoReply() throws {
    let request = ICMPHandler.icmpv6(
        src: client6,
        dst: server6,
        type: ICMPv6Type.echoRequest,
        code: 0,
        rest: 0x0002_0003,
        payload: Data([1, 2, 3, 4])
    ).asSharedData()
    let header = try IPHeader.peek(request)
    let reply = ICMPHandler.echoReply(header: header, original: request)!.asSharedData()
    let replyHeader = try IPHeader.peek(reply)
    let message = try ICMPMessage.parse(packet: reply, ip: replyHeader)
    #expect(message.type == ICMPv6Type.echoReply)
    #expect(replyHeader.src == server6)
}

@Test func pmtuQuotesOriginalIPHeaderAndEightPayloadBytes() throws {
    let flow = FlowKey(src: client, srcPort: 40_000, dst: server, dstPort: 443)
    let original = PacketBuilder.tcp(
        flow: flow, seq: 1, ack: 0, flags: .syn, window: 1000,
        payload: Data(repeating: 0xab, count: 8)
    ).asSharedData()
    let header = try IPHeader.peek(original)
    let icmp = ICMPHandler.packetTooBig(header: header, original: original, mtu: 1400).asSharedData()
    let icmpHeader = try IPHeader.peek(icmp)
    #expect(icmpHeader.src == server)
    #expect(icmpHeader.dst == client)
    let message = try ICMPMessage.parse(packet: icmp, ip: icmpHeader)
    #expect(message.type == ICMPv4Type.destinationUnreachable)
    #expect(message.code == ICMPv4Type.fragmentationNeeded)
    #expect(message.rest == 1400)
    let quote = icmp.subdata(in: message.payloadOffset..<(message.payloadOffset + message.payloadLength))
    #expect(quote.count == header.headerLength + 8)
    #expect(quote == original.prefix(header.headerLength + 8))
}

@Test func demuxerEmitsPMTUAndDoesNotForwardOversizedDF() async throws {
    let sink = RecordingSink()
    let stack = SwiftStack(config: SwiftStackConfig(mtu: 50), sink: sink)
    let flow = FlowKey(src: client, srcPort: 40_000, dst: server, dstPort: 80)
    let oversized = PacketBuilder.tcp(
        flow: flow, seq: 1, ack: 0, flags: .syn, window: 1000,
        payload: Data(repeating: 0x11, count: 80)
    ).asSharedData()
    #expect(oversized.count > 50)
    await stack.ingest(oversized)
    let tx = sink.snapshot()
    #expect(tx.count == 1)
    let ip = try IPHeader.peek(tx[0])
    #expect(ip.protocol == .icmp)
    let icmp = try ICMPMessage.parse(packet: tx[0], ip: ip)
    #expect(icmp.type == ICMPv4Type.destinationUnreachable)
    let metrics = await stack.metrics()
    #expect(metrics.pmtuMessages == 1)
    #expect(metrics.inboundTCP == 0)
}

@Test func demuxerAnswersPingOnTheTunPath() async throws {
    let sink = RecordingSink()
    let stack = SwiftStack(sink: sink)
    let request = ICMPHandler.icmpv4(
        src: client, dst: server,
        type: ICMPv4Type.echoRequest, code: 0,
        rest: 0x0001_0001,
        payload: Data("hello".utf8)
    ).asSharedData()
    await stack.ingest(request)
    let tx = sink.snapshot()
    #expect(tx.count == 1)
    let ip = try IPHeader.peek(tx[0])
    let icmp = try ICMPMessage.parse(packet: tx[0], ip: ip)
    #expect(icmp.type == ICMPv4Type.echoReply)
    let metrics = await stack.metrics()
    #expect(metrics.echoReplies == 1)
    #expect(metrics.inboundICMP == 1)
}

@Test func demuxerDropsUnknownProtocolAndCountsIt() async throws {
    let sink = RecordingSink()
    let stack = SwiftStack(sink: sink)
    var gre = PacketBuffer(capacity: 40)
    IPWire.appendIPv4(&gre, src: IPWire.v4(client), dst: IPWire.v4(server), total: 20, proto: 47)
    IPWire.fillIPv4HeaderChecksum(&gre)
    await stack.ingest(gre.asSharedData())
    let tx = sink.snapshot()
    #expect(tx.isEmpty)
    let metrics = await stack.metrics()
    #expect(metrics.droppedUnknown == 1)
}

@Test func icmpEchoReplyIsNotGeneratedForReplies() throws {
    let reply = ICMPHandler.icmpv4(
        src: server, dst: client,
        type: ICMPv4Type.echoReply, code: 0, rest: 0, payload: Data()
    ).asSharedData()
    let header = try IPHeader.peek(reply)
    let again = ICMPHandler.echoReply(header: header, original: reply)
    if let again {
        _ = again
        Issue.record("echo reply must not be generated for type 0")
    }
}

@Test func udpPortZeroIsDropped() async throws {
    let sink = RecordingSink()
    let udp = UDPHandler(sink: sink)
    let flow = FlowKey(src: client, srcPort: 53_000, dst: server, dstPort: 0)
    let packet = UDPPacket.encapsulate(flow: flow, payload: Data([1, 2, 3])).asSharedData()
    let header = try IPHeader.peek(packet)
    await udp.ingest(header: header, packet: packet)
    #expect(await udp.sessionCount() == 0)
    #expect(sink.snapshot().isEmpty)
}
