# SwiftTCP

A Swift 6 userspace TCP/IP stack for Apple Network Extension (`NEPacketTunnelProvider`): it reads raw IP packets from TUN, terminates or forwards TCP, and writes replies back to TUN.

Targets macOS / iOS / tvOS. There is no Linux port; it uses Darwin, `Network.framework`, and `NetworkExtension` directly.

## Data path

```
NEPacketTunnelFlow.readPackets  →  [Data]          TUN ingress (already allocated)
        │
        ▼  PacketBuffer(wrapping:)  retain NSData, no memcpy
  PacketBuffer (~Copyable)
        │  borrowing parse of IPv4/IPv6 + TCP headers
        ▼
  FlowKey (src, sport, dst, dport)
        │  stable FNV-1a → EventLoop index
        ▼
  TCPDispatcher ──► TCPEventLoop[i]   pinned serial executor, lock-free per flow
        │
        ▼  TCPControlBlock (enum TCPState + CUBIC/BBR + ring windows)
  TCPAction: ACK / data / timer / ESTABLISHED / CLOSE
        │
        ├─► PacketSink.writePackets     TUN egress (preallocated TX buffers)
        └─► TCPStreamHandler            NWConnection / app byte stream
```

UDP is demuxed by `IPDemuxer` into `UDPHandler` (session table), then handed to a `UDPDatagramHandler` (default `NWUDPForwarder`). ICMP echo and PMTU stay on the demux path and are handled synchronously.

Each connection is hashed onto one `TCPEventLoop` for its lifetime. The TCB is mutable only on that actor, so the hot path has no locks. A TUN read of N packets is bucketed by affinity, then each loop is hopped onto once (batched).

## Zero-copy contract

| Stage | Strategy |
| --- | --- |
| TUN → stack | `PacketBuffer` wraps `NSData.bytes`; parsing is `borrowing` only |
| In-order payload | `retainedPayload` / `asSharedData` share the backing store |
| Out-of-order / send window | `ByteRingBuffer` (per connection, loop-private) |
| Stack → TUN | TX `PacketStorage` malloc; `writePackets` shares the same memory |

`PacketBuffer` is `~Copyable`: implicit copies are forbidden, `consuming` slices transfer the window, and `PacketStorage` owns the backing uniquely.

## Modules

The public entry point is `SwiftStack` (TCP + UDP + ICMP). `TCPStack` remains for TCP-only tests.

- `Buffer/` — `PacketBuffer`, `ByteRingBuffer`
- `Packet/` — `FlowKey`, `IPHeader`, checksums, TCP/UDP/ICMP assembly (`IPWire`)
- `IP/` — `IPDemuxer`, `StackMetrics`
- `TCP/` — state machine, CUBIC / BBR, TCB (split across Segment / Send / SACK / Timers files)
- `UDP/` — `UDPDatagram` / `UDPPacket` codecs, `UDPHandler` session table (no Network dependency)
- `ICMP/` — echo reply, Packet Too Big
- `Runtime/` — `SwiftStack`, `LoopExecutor`, EventLoop / Dispatcher (internal)
- `Integration/` — `PacketTunnelBridge`, `NWConnectionForwarder`, `NWUDPForwarder`, `ProxyMux`

A Packet Tunnel sample lives in [`Examples/PacketTunnelProvider.swift`](Examples/PacketTunnelProvider.swift).

## Packet Tunnel integration

```swift
import NetworkExtension
import SwiftTCP

final class TunnelProvider: NEPacketTunnelProvider {
    var bridge: PacketTunnelBridge?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.ipv4Settings = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
        settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
        settings.mtu = 1400

        setTunnelNetworkSettings(settings) { error in
            if error == nil {
                let stack = SwiftStack(
                    config: SwiftStackConfig(tcp: TCPStackConfig(algorithm: .bbr, tfo: true)),
                    sink: TunnelSink(flow: self.packetFlow),
                    streams: NoopStreamHandler() // or NWConnectionForwarder
                )
                let bridge = PacketTunnelBridge(provider: self, stack: stack)
                self.bridge = bridge
                bridge.start()
            }
            completionHandler(error)
        }
    }
}
```

You can also copy [`Examples/PacketTunnelProvider.swift`](Examples/PacketTunnelProvider.swift) into a Packet Tunnel target and set `streamHandler` before `startTunnel`.

Congestion control defaults to CUBIC; switch to `.bbr` if needed. TFO: a SYN with payload can `deliver` before the handshake completes. Share one next hop across many flows with `ProxyMux` (length-framed). For a custom UDP upstream, implement `UDPDatagramHandler` and pass it to `SwiftStack`.

## Benchmarks

In-process packet injection saturates the stack (no TUN) and compares pps, bandwidth, CPU, RSS, short-connection RPS, and latency percentiles against gVisor netstack. Default scenarios cover TX / duplex / multi-flow / RPS / loss / IPv6 / multi-core scaling. See [`Benchmarks/SPEC.md`](Benchmarks/SPEC.md).

```bash
# Recommended: Docker only on the host (Swift / Go / Rust are in the image)
./Benchmarks/docker.sh

# Or a local toolchain
swift run -c release SwiftTCPBench --scenario all --duration 5
./Benchmarks/run.sh
```

On a Mac, Docker Desktop runs inside a Linux VM. **Do not** compare container numbers to host `SwiftTCPBench` in absolute terms; comparing the three stacks inside the same container is still valid. See “How Docker affects the numbers” in the SPEC.
