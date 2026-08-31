/// SwiftTCP — a user-space TCP/IP stack for Apple Network Extension packet tunnels.
///
/// # Architecture
///
/// ```
/// NEPacketTunnelFlow.readPackets  [Data]          (TUN ingress)
///         │
///         ▼  PacketBuffer(wrapping:)  保留 NSData，不 memcpy
///   IPHeader  (borrowing IPv4/IPv6)
///         │
///         ├─ length > MTU && DF ──► ICMP Dest Unreachable / Packet Too Big
///         │
///         ▼  IPDemuxer
///   ┌─────┼─────────────┬──────────────┐
///   TCP(6)            UDP(17)     ICMP(1/58)
///   TCPDispatcher     UDPHandler  ICMPHandler
///   EventLoop[i]      UDPDatagramHandler  Echo Reply
///                     (default NWUDPForwarder)
/// ```
///
/// Public entry is `SwiftStack`. Ingress never copies packet bytes to parse
/// headers. Payload is delivered as a shared `Data` slice (retain of the
/// original NSData). Each TCP 4-tuple is pinned to one `TCPEventLoop`. Timers
/// are smoltcp-style: each PCB stores `Instant` deadlines and the loop sleeps
/// once until `poll_delay`.
public enum SwiftTCP {
    public static let version = "0.2.0"
}
