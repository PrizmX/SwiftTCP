import Foundation

/// Timer policy for local microVM / proxy: short RTO floor, modest TIME-WAIT,
/// Keep-Alive on the same EventLoop tick as RTO (no per-flow `Task.sleep`).
public struct TCPTimerConfig: Sendable {
    public var minRTO: Duration
    public var maxRTO: Duration
    public var initialRTO: Duration
    public var timeWait: Duration
    public var keepAliveIdle: Duration
    public var keepAliveInterval: Duration
    public var keepAliveProbes: UInt8
    public var delayedAck: Duration
    public var maxRetransmits: UInt8
    /// SYN-SENT / SYN-RCVD hard cap (half-open / handshake never completes).
    public var handshakeTimeout: Duration
    /// FIN-WAIT-2: we closed, peer ACKed, never sent FIN (Linux `tcp_fin_timeout`).
    public var finWaitTimeout: Duration
    /// CLOSE-WAIT: peer FINed, local app never close().
    public var closeWaitTimeout: Duration
    /// Absolute lifetime from PCB creation. `.zero` disables.
    public var maxLifetime: Duration

    public init(
        minRTO: Duration = .milliseconds(20),
        maxRTO: Duration = .seconds(2),
        initialRTO: Duration = .milliseconds(50),
        timeWait: Duration = .seconds(2),
        keepAliveIdle: Duration = .seconds(45),
        keepAliveInterval: Duration = .seconds(15),
        keepAliveProbes: UInt8 = 4,
        delayedAck: Duration = .zero,
        maxRetransmits: UInt8 = 8,
        handshakeTimeout: Duration = .seconds(10),
        finWaitTimeout: Duration = .seconds(60),
        closeWaitTimeout: Duration = .seconds(30),
        maxLifetime: Duration = .seconds(24 * 60 * 60)
    ) {
        self.minRTO = minRTO
        self.maxRTO = maxRTO
        self.initialRTO = initialRTO
        self.timeWait = timeWait
        self.keepAliveIdle = keepAliveIdle
        self.keepAliveInterval = keepAliveInterval
        self.keepAliveProbes = keepAliveProbes
        self.delayedAck = delayedAck
        self.maxRetransmits = maxRetransmits
        self.handshakeTimeout = handshakeTimeout
        self.finWaitTimeout = finWaitTimeout
        self.closeWaitTimeout = closeWaitTimeout
        self.maxLifetime = maxLifetime
    }

    /// Idle TTL for zombie states. `nil` means another timer (RTO / Keep-Alive / TIME-WAIT) owns expiry.
    public func idleTTL(for state: TCPState) -> Duration? {
        switch state {
        case .synSent, .synReceived: handshakeTimeout
        case .finWait2, .closing: finWaitTimeout
        case .closeWait: closeWaitTimeout
        default: nil
        }
    }
}

/// smoltcp-style per-socket deadlines. The EventLoop sleeps until `earliest`.
public struct TCPDeadlines: Sendable, Equatable {
    public var retransmitAt: ContinuousClock.Instant?
    public var timeWaitAt: ContinuousClock.Instant?
    public var persistAt: ContinuousClock.Instant?
    public var delayedAckAt: ContinuousClock.Instant?
    public var keepAliveAt: ContinuousClock.Instant?
    public var idleAt: ContinuousClock.Instant?
    public var lifetimeAt: ContinuousClock.Instant?

    public init() {}

    public var earliest: ContinuousClock.Instant? {
        var best: ContinuousClock.Instant?
        func consider(_ instant: ContinuousClock.Instant?) {
            guard let instant else { return }
            if let current = best {
                if instant < current { best = instant }
            } else {
                best = instant
            }
        }
        consider(retransmitAt)
        consider(timeWaitAt)
        consider(persistAt)
        consider(delayedAckAt)
        consider(keepAliveAt)
        consider(idleAt)
        consider(lifetimeAt)
        return best
    }

    public mutating func arm(_ kind: TCPTimerKind, at instant: ContinuousClock.Instant) {
        switch kind {
        case .retransmission: retransmitAt = instant
        case .timeWait: timeWaitAt = instant
        case .persist: persistAt = instant
        case .delayedAck: delayedAckAt = instant
        case .keepAlive: keepAliveAt = instant
        case .idle: idleAt = instant
        case .lifetime: lifetimeAt = instant
        }
    }

    public mutating func clear(_ kind: TCPTimerKind) {
        switch kind {
        case .retransmission: retransmitAt = nil
        case .timeWait: timeWaitAt = nil
        case .persist: persistAt = nil
        case .delayedAck: delayedAckAt = nil
        case .keepAlive: keepAliveAt = nil
        case .idle: idleAt = nil
        case .lifetime: lifetimeAt = nil
        }
    }

    public mutating func clearAll() {
        self = TCPDeadlines()
    }

    public func expired(now: ContinuousClock.Instant) -> [TCPTimerKind] {
        var kinds: [TCPTimerKind] = []
        if let t = retransmitAt, t <= now { kinds.append(.retransmission) }
        if let t = timeWaitAt, t <= now { kinds.append(.timeWait) }
        if let t = persistAt, t <= now { kinds.append(.persist) }
        if let t = delayedAckAt, t <= now { kinds.append(.delayedAck) }
        if let t = keepAliveAt, t <= now { kinds.append(.keepAlive) }
        if let t = idleAt, t <= now { kinds.append(.idle) }
        if let t = lifetimeAt, t <= now { kinds.append(.lifetime) }
        return kinds
    }
}
