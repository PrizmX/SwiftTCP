import Foundation

/// TCP-only facade for tests and isolated TCP benches. Prefer `SwiftStack` on the TUN path.
public actor TCPStack: TCPByteStream {
    nonisolated let dispatcher: TCPDispatcher
    nonisolated public let config: TCPStackConfig

    public init(
        config: TCPStackConfig = .init(),
        sink: any PacketSink,
        streams: any TCPStreamHandler = NoopStreamHandler()
    ) {
        self.config = config
        self.dispatcher = TCPDispatcher(config: config, sink: sink, streams: streams)
    }

    nonisolated public func ingest(_ data: Data) async {
        await dispatcher.ingestBatch([data])
    }

    nonisolated public func ingestBatch(_ packets: [Data], protocols: [NSNumber] = []) async {
        await dispatcher.ingestBatch(packets, protocols: protocols)
    }

    @discardableResult
    nonisolated public func send(flow: FlowKey, data: Data) async -> Int {
        await dispatcher.send(flow: flow, data: data)
    }

    nonisolated public func sendBatch(_ items: [(FlowKey, Data)]) async {
        await dispatcher.sendBatch(items)
    }

    nonisolated public func close(flow: FlowKey) async {
        await dispatcher.close(flow: flow)
    }

    nonisolated public func connect(flow: FlowKey) async {
        await dispatcher.connect(flow: flow)
    }

    nonisolated public func shutdown() async {
        await dispatcher.shutdown()
    }

    public func connectionCount() async -> Int {
        await dispatcher.connectionCount()
    }
}
