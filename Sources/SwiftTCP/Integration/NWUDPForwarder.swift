#if canImport(Network)
import Foundation
import Network

/// One TUN UDP 5-tuple → one `NWConnection(.udp)` to the original destination.
/// Stack callbacks go through one `AsyncStream`, so datagrams keep their order
/// and a close never overtakes the datagrams queued before it.
public actor NWUDPForwarder: UDPDatagramHandler {
    private enum Event: Sendable {
        case datagram(FlowKey, Data)
        case closed(FlowKey)
    }

    private weak var replies: (any UDPReplyPath)?
    private let queue = DispatchQueue(label: "swifttcp.udp", qos: .userInitiated)
    private var conns: [FlowKey: NWConnection] = [:]
    private nonisolated let events: AsyncStream<Event>.Continuation

    public init(replies: any UDPReplyPath) {
        self.replies = replies
        let (stream, continuation) = AsyncStream.makeStream(of: Event.self)
        self.events = continuation
        Task { [weak self] in
            for await event in stream {
                guard let self else { return }
                await self.handle(event)
            }
        }
    }

    deinit {
        events.finish()
    }

    nonisolated public func onDatagram(flow: FlowKey, payload: Data) {
        events.yield(.datagram(flow, payload))
    }

    nonisolated public func onClosed(flow: FlowKey) {
        events.yield(.closed(flow))
    }

    private func handle(_ event: Event) {
        switch event {
        case .datagram(let flow, let payload):
            handleDatagram(flow: flow, payload: payload)
        case .closed(let flow):
            handleClosed(flow: flow)
        }
    }

    private func handleDatagram(flow: FlowKey, payload: Data) {
        guard let conn = open(flow: flow) else { return }
        conn.send(content: payload, completion: .contentProcessed { _ in })
    }

    private func handleClosed(flow: FlowKey) {
        conns.removeValue(forKey: flow)?.cancel()
    }

    private func open(flow: FlowKey) -> NWConnection? {
        if let existing = conns[flow] { return existing }
        guard flow.dstPort != 0, let port = NWEndpoint.Port(rawValue: flow.dstPort) else { return nil }
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(flow.dst.description),
            port: port
        )
        let conn = NWConnection(to: endpoint, using: .udp)
        conns[flow] = conn
        conn.start(queue: queue)
        receive(flow: flow, connection: conn)
        return conn
    }

    private func receive(flow: FlowKey, connection: NWConnection) {
        connection.receiveMessage { content, _, isComplete, error in
            // One task per message, and the next receive starts only after
            // this reply is forwarded, so replies stay in order.
            Task {
                if let content, !content.isEmpty {
                    await self.forwardReply(flow: flow, payload: content)
                }
                if error != nil || isComplete {
                    await self.handleClosed(flow: flow)
                    await self.closeReplyPath(flow: flow)
                } else {
                    await self.receiveAgain(flow: flow)
                }
            }
        }
    }

    private func forwardReply(flow: FlowKey, payload: Data) async {
        await replies?.sendReply(flow: flow, payload: payload)
    }

    private func closeReplyPath(flow: FlowKey) async {
        await replies?.close(flow: flow)
    }

    private func receiveAgain(flow: FlowKey) {
        guard let conn = conns[flow] else { return }
        receive(flow: flow, connection: conn)
    }
}
#endif
