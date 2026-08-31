#if canImport(NetworkExtension)
import Foundation
import NetworkExtension
import SwiftTCP

/// Sample `NEPacketTunnelProvider`. Copy into a Packet Tunnel target and set
/// `streamHandler` before `startTunnel`. Addresses here are placeholders.
open class SwiftTCPPacketTunnelProvider: NEPacketTunnelProvider {
    public var stackConfig = SwiftStackConfig()
    public var streamHandler: any TCPStreamHandler = NoopStreamHandler()
    private var bridge: PacketTunnelBridge?

    override open func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.ipv4Settings = {
            let v4 = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
            v4.includedRoutes = [NEIPv4Route.default()]
            return v4
        }()
        settings.mtu = NSNumber(value: stackConfig.mtu)
        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else {
                completionHandler(error)
                return
            }
            if error == nil {
                let sink = TunnelSink(flow: self.packetFlow)
                let stack = SwiftStack(config: self.stackConfig, sink: sink, streams: self.streamHandler)
                let bridge = PacketTunnelBridge(provider: self, stack: stack)
                self.bridge = bridge
                bridge.start()
            }
            completionHandler(error)
        }
    }

    override open func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        bridge = nil
        completionHandler()
    }
}
#endif
