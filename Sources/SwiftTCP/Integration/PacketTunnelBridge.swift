#if canImport(NetworkExtension)
import Foundation
@preconcurrency import NetworkExtension

/// TUN adapter: `NEPacketTunnelFlow` ↔ `SwiftStack` with no extra payload copies.
///
/// `readPackets` already vends `[Data]`. SwiftTCP wraps each `Data` as
/// `PacketBuffer` (NSData retain). TX uses `PacketBuffer.asSharedData()` so
/// `writePackets` shares the malloc backing until the kernel takes it.
public final class PacketTunnelBridge: @unchecked Sendable {
    private let stack: SwiftStack
    private let flow: NEPacketTunnelFlow

    public init(provider: NEPacketTunnelProvider, stack: SwiftStack) {
        self.flow = provider.packetFlow
        self.stack = stack
    }

    public convenience init(
        provider: NEPacketTunnelProvider,
        config: SwiftStackConfig = .init(),
        streams: any TCPStreamHandler
    ) {
        let sink = TunnelSink(flow: provider.packetFlow)
        let stack = SwiftStack(config: config, sink: sink, streams: streams)
        self.init(provider: provider, stack: stack)
    }

    /// Recurring `readPackets` pump. Must be started from the provider's work queue.
    public func start() {
        pump()
    }

    private func pump() {
        flow.readPackets { [weak self] packets, protocols in
            guard let self else { return }
            Task { [stack = self.stack] in
                await stack.ingestBatch(packets, protocols: protocols)
                self.pump()
            }
        }
    }
}

public final class TunnelSink: PacketSink, @unchecked Sendable {
    private let flow: NEPacketTunnelFlow

    public init(flow: NEPacketTunnelFlow) {
        self.flow = flow
    }

    public func write(bytes: Data, protocolFamily: UInt8) {
        flow.writePackets([bytes], withProtocols: [NSNumber(value: protocolFamily)])
    }

    public func writeBatch(_ items: [(Data, UInt8)]) {
        guard !items.isEmpty else { return }
        let packets = items.map(\.0)
        let protocols = items.map { NSNumber(value: $0.1) }
        flow.writePackets(packets, withProtocols: protocols)
    }
}
#endif
