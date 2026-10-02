import Foundation

/// Guest-originated 4-tuple identity. Replies encapsulate `flow.reversed`.
public protocol UDPReplyPath: AnyObject, Sendable {
    func sendReply(flow: FlowKey, payload: Data) async
    func close(flow: FlowKey) async
}

/// Session table and TUN encapsulation. Upstream I/O is a `UDPDatagramHandler`
/// (default: `NWUDPForwarder`); this type does not import Network.
actor UDPHandler: UDPReplyPath {
    var idle: Duration
    var dnsIdle: Duration
    var maxLifetime: Duration
    var maxSessions: Int
    private(set) var droppedAtCap: UInt64 = 0
    /// Sessions evicted (least recently used) to admit a new flow at `maxSessions`.
    private(set) var evictedAtCap: UInt64 = 0

    private let sink: any PacketSink
    private var sessions: [FlowKey: Session] = [:]
    private var pollTask: Task<Void, Never>?
    private let upstreamSlot = UpstreamSlot()

    init(
        sink: any PacketSink,
        idle: Duration = .seconds(120),
        dnsIdle: Duration = .seconds(15),
        maxLifetime: Duration = .seconds(24 * 60 * 60),
        maxSessions: Int = 8_192
    ) {
        self.sink = sink
        self.idle = idle
        self.dnsIdle = dnsIdle
        self.maxLifetime = maxLifetime
        self.maxSessions = max(1, maxSessions)
    }

    nonisolated func setUpstream(_ handler: any UDPDatagramHandler) {
        upstreamSlot.handler = handler
    }

    func ingestBatch(_ packets: [(IPHeader, Data)]) {
        for (header, data) in packets {
            ingest(header: header, packet: data)
        }
        sweep(now: ContinuousClock().now)
        armPoll()
    }

    func ingest(header: IPHeader, packet: Data) {
        let datagram: UDPDatagram
        do {
            datagram = try UDPDatagram.parse(packet: packet, ip: header)
        } catch {
            return
        }
        guard datagram.flow.dstPort != 0 else { return }
        guard session(for: datagram.flow) != nil else {
            droppedAtCap &+= 1
            return
        }
        sessions[datagram.flow]?.lastSeen = ContinuousClock().now
        let payload = PacketBuffer(wrapping: packet)
            .retainedPayload(offset: datagram.payloadOffset, length: datagram.payloadLength)
        upstreamSlot.handler.onDatagram(flow: datagram.flow, payload: payload)
    }

    func sessionCount() -> Int { sessions.count }

    func closeAll() {
        pollTask?.cancel()
        pollTask = nil
        let flows = Array(sessions.keys)
        sessions.removeAll()
        for flow in flows {
            upstreamSlot.handler.onUDPSessionClosed(flow: flow, reason: .shutdown)
        }
    }

    func sendReply(flow: FlowKey, payload: Data) async {
        guard sessions[flow] != nil else { return }
        // An upstream reply can exceed one IP datagram (UDP-over-stream frames,
        // an IPv6 peer answering a FakeIP IPv4 flow). There is no fragmentation
        // on this path, and encoding it would overflow the length fields.
        guard payload.count <= UDPPacket.maxPayload(for: flow.src.version) else { return }
        sessions[flow]?.lastSeen = ContinuousClock().now
        let tx = UDPPacket.encapsulate(flow: flow.reversed, payload: payload)
        sink.write(bytes: tx.asSharedData(), protocolFamily: AddressFamily.of(flow.src.version))
        armPoll()
    }

    func close(flow: FlowKey) async {
        guard sessions.removeValue(forKey: flow) != nil else { return }
        upstreamSlot.handler.onUDPSessionClosed(flow: flow, reason: .closed)
        armPoll()
    }

    private func timeout(for flow: FlowKey) -> Duration {
        flow.dstPort == 53 || flow.srcPort == 53 ? dnsIdle : idle
    }

    @discardableResult
    private func session(for flow: FlowKey) -> Session? {
        if let existing = sessions[flow] {
            return existing
        }
        if sessions.count >= maxSessions, !evictLeastRecentlyUsed() {
            return nil
        }
        let created = Session()
        sessions[flow] = created
        return created
    }

    private func armPoll() {
        pollTask?.cancel()
        let now = ContinuousClock().now
        var earliest: ContinuousClock.Instant?
        for (flow, session) in sessions {
            let idleExpiry = session.lastSeen.advanced(by: timeout(for: flow))
            let lifeExpiry = maxLifetime > .zero
                ? session.createdAt.advanced(by: maxLifetime)
                : idleExpiry
            let expiry = idleExpiry < lifeExpiry ? idleExpiry : lifeExpiry
            if let current = earliest {
                if expiry < current { earliest = expiry }
            } else {
                earliest = expiry
            }
        }
        guard let earliest else { return }
        var delay = now.duration(to: earliest)
        if delay < .zero { delay = .zero }
        if delay == .zero { delay = .milliseconds(1) }
        pollTask = Task {
            try? await Task.sleep(for: delay)
            guard !Task.isCancelled else { return }
            self.onPollWake()
        }
    }

    private func onPollWake() {
        sweep(now: ContinuousClock().now)
        armPoll()
    }

    private func sweep(now: ContinuousClock.Instant) {
        let stale = sessions.filter { flow, session in
            let idle = session.lastSeen.duration(to: now) > timeout(for: flow)
            let expired = maxLifetime > .zero && session.createdAt.duration(to: now) > maxLifetime
            return idle || expired
        }.map(\.key)
        for flow in stale {
            sessions.removeValue(forKey: flow)
            upstreamSlot.handler.onUDPSessionClosed(flow: flow, reason: .expired)
        }
    }

    /// O(n) scan; only runs when the table is full and a new flow arrives.
    private func evictLeastRecentlyUsed() -> Bool {
        guard let victim = sessions.min(by: { $0.value.lastSeen < $1.value.lastSeen })?.key else {
            return false
        }
        sessions.removeValue(forKey: victim)
        evictedAtCap &+= 1
        upstreamSlot.handler.onUDPSessionClosed(flow: victim, reason: .evicted)
        return true
    }
}

private final class UpstreamSlot: @unchecked Sendable {
    var handler: any UDPDatagramHandler = NoopUDPHandler()
}

private final class Session {
    var lastSeen: ContinuousClock.Instant
    let createdAt: ContinuousClock.Instant

    init() {
        let now = ContinuousClock().now
        lastSeen = now
        createdAt = now
    }
}
