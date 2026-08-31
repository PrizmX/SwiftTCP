#if canImport(Network)
import Foundation
import Network

/// Destination-keyed TFO cookie cache (Fast Open simulation).
public actor TFOCookieCache {
    private var cookies: [Key: Data] = [:]

    public struct Key: Hashable, Sendable {
        public var host: IPAddress
        public var port: UInt16
        public init(host: IPAddress, port: UInt16) {
            self.host = host
            self.port = port
        }
    }

    public init() {}

    public func store(_ cookie: Data, for key: Key) {
        cookies[key] = cookie
    }

    public func cookie(for key: Key) -> Data? {
        cookies[key]
    }
}

/// One TUN TCP flow → one `NWConnection` to the original destination.
public actor NWConnectionForwarder: TCPStreamHandler {
    private let queue = DispatchQueue(label: "swifttcp.nwforward")
    private let cookies: TFOCookieCache
    private var conns: [FlowKey: NWConnection] = [:]
    private let stack: any TCPByteStream

    public init(stack: any TCPByteStream, cookies: TFOCookieCache = TFOCookieCache()) {
        self.stack = stack
        self.cookies = cookies
    }

    nonisolated public func onEstablished(flow: FlowKey) {
        Task { await self.handleEstablished(flow: flow) }
    }

    nonisolated public func onData(flow: FlowKey, data: Data) {
        Task { await self.handleData(flow: flow, data: data) }
    }

    nonisolated public func onClosed(flow: FlowKey) {
        Task { await self.handleClosed(flow: flow) }
    }

    private func handleEstablished(flow: FlowKey) {
        _ = open(flow: flow)
    }

    private func handleData(flow: FlowKey, data: Data) {
        guard let conn = open(flow: flow) else { return }
        conn.send(content: data, completion: .contentProcessed { _ in })
    }

    private func handleClosed(flow: FlowKey) {
        conns.removeValue(forKey: flow)?.cancel()
    }

    private func open(flow: FlowKey) -> NWConnection? {
        if let existing = conns[flow] { return existing }
        guard let port = NWEndpoint.Port(rawValue: flow.dstPort) else { return nil }
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(flow.dst.description),
            port: port
        )
        let parameters = NWParameters.tcp
        parameters.allowFastOpen = false
        let conn = NWConnection(to: endpoint, using: parameters)
        conns[flow] = conn
        conn.start(queue: queue)
        receive(flow: flow, conn: conn)
        Task { _ = await self.cookies.cookie(for: TFOCookieCache.Key(host: flow.dst, port: flow.dstPort)) }
        return conn
    }

    private func receive(flow: FlowKey, conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { content, _, isComplete, error in
            Task { await self.handleInbound(flow: flow, conn: conn, content: content, isComplete: isComplete, error: error) }
        }
    }

    private func handleInbound(
        flow: FlowKey,
        conn: NWConnection,
        content: Data?,
        isComplete: Bool,
        error: (any Error)?
    ) async {
        if let content, !content.isEmpty {
            _ = await stack.send(flow: flow, data: content)
        }
        if isComplete || error != nil {
            await stack.close(flow: flow)
        } else if conns[flow] != nil {
            receive(flow: flow, conn: conn)
        }
    }
}
#endif
