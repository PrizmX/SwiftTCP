#if canImport(Network)
import Foundation
import Network

/// mptcpd-style next-hop multiplexing: many TUN flows share one `NWConnection`
/// to a userspace proxy, framed as `[id:UInt32][len:UInt32][payload]`.
public actor ProxyMux: TCPStreamHandler {
    public struct Destination: Hashable, Sendable {
        public var host: String
        public var port: UInt16
        public init(host: String, port: UInt16) {
            self.host = host
            self.port = port
        }
    }

    private let proxy: Destination
    private let stack: any TCPByteStream
    private var connection: NWConnection?
    private var flowIDs: [FlowKey: UInt32] = [:]
    private var ids: [UInt32: FlowKey] = [:]
    private var nextID: UInt32 = 1
    private var rxRemainder = Data()

    public init(proxy: Destination, stack: any TCPByteStream) {
        self.proxy = proxy
        self.stack = stack
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

    private func handleEstablished(flow: FlowKey) async {
        await ensureConnection()
        let id = nextID
        nextID &+= 1
        flowIDs[flow] = id
        ids[id] = flow
        sendFrame(id: id, payload: Data())
    }

    private func handleData(flow: FlowKey, data: Data) {
        guard let id = flowIDs[flow] else { return }
        sendFrame(id: id, payload: data)
    }

    private func handleClosed(flow: FlowKey) {
        if let id = flowIDs.removeValue(forKey: flow) {
            ids.removeValue(forKey: id)
            sendFrame(id: id, payload: Data())
        }
    }

    private func ensureConnection() async {
        if connection != nil { return }
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(proxy.host),
            port: NWEndpoint.Port(rawValue: proxy.port)!
        )
        let conn = NWConnection(to: endpoint, using: .tcp)
        connection = conn
        conn.start(queue: .global())
        pump(conn)
    }

    private func sendFrame(id: UInt32, payload: Data) {
        var frame = Data()
        var beID = id.bigEndian
        var beLen = UInt32(payload.count).bigEndian
        frame.append(Data(bytes: &beID, count: 4))
        frame.append(Data(bytes: &beLen, count: 4))
        frame.append(payload)
        connection?.send(content: frame, completion: .contentProcessed { _ in })
    }

    private func pump(_ conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { content, _, isComplete, _ in
            Task {
                if let content { await self.ingest(content) }
                if !isComplete { await self.pumpAgain(conn) }
            }
        }
    }

    private func pumpAgain(_ conn: NWConnection) {
        pump(conn)
    }

    private static let maxFramePayload = 1_048_576

    private func ingest(_ data: Data) async {
        rxRemainder.append(data)
        while rxRemainder.count >= 8 {
            let id = rxRemainder.prefix(4).withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) }
            let len = Int(rxRemainder.subdata(in: 4..<8).withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) })
            guard len >= 0, len <= Self.maxFramePayload else {
                rxRemainder.removeAll(keepingCapacity: false)
                return
            }
            guard rxRemainder.count >= 8 + len else { return }
            let payload = rxRemainder.subdata(in: 8..<(8 + len))
            rxRemainder.removeSubrange(0..<(8 + len))
            if let flow = ids[id] {
                await stack.send(flow: flow, data: payload)
            }
        }
    }
}
#endif
