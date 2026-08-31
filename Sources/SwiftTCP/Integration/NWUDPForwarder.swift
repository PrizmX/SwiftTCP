#if canImport(Network)
import Foundation
import Network

/// One TUN UDP 5-tuple → one `NWConnection(.udp)` to the original destination.
public actor NWUDPForwarder: UDPDatagramHandler {
    private unowned let replies: any UDPReplyPath
    private let queue = DispatchQueue(label: "swifttcp.udp", qos: .userInitiated)
    private var conns: [FlowKey: NWConnection] = [:]

    public init(replies: any UDPReplyPath) {
        self.replies = replies
    }

    nonisolated public func onDatagram(flow: FlowKey, payload: Data) {
        Task { await self.handleDatagram(flow: flow, payload: payload) }
    }

    nonisolated public func onClosed(flow: FlowKey) {
        Task { await self.handleClosed(flow: flow) }
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
            if let content, !content.isEmpty {
                Task { await self.replies.sendReply(flow: flow, payload: content) }
            }
            if error != nil || isComplete {
                Task {
                    await self.handleClosed(flow: flow)
                    await self.replies.close(flow: flow)
                }
            } else {
                Task { await self.receiveAgain(flow: flow) }
            }
        }
    }

    private func receiveAgain(flow: FlowKey) {
        guard let conn = conns[flow] else { return }
        receive(flow: flow, connection: conn)
    }
}
#endif
