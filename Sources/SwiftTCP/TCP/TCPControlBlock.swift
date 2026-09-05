import Foundation

/// Per-connection control block. Lives exclusively on one `TCPEventLoop`.
final class TCPControlBlock: @unchecked Sendable {
    var flow: FlowKey
    var state: TCPState
    var sndUna: UInt32
    var sndNxt: UInt32
    var sndWnd: UInt32
    var rcvNxt: UInt32
    var rcvWnd: UInt32
    var iss: UInt32
    var irs: UInt32
    var mss: UInt16
    var maxMss: UInt16
    var sndWndShift: UInt8
    var rcvWndShift: UInt8
    /// RFC 7323: scale only after both sides sent Window Scale on SYN.
    var windowScaleEnabled: Bool
    var rtt: RTTEstimator
    var congestion: CongestionState
    var tfoEnabled: Bool
    var tfoDelivered: Bool
    var deadlines: TCPDeadlines
    let timerConfig: TCPTimerConfig
    var keepAliveProbesSent: UInt8
    var retransmitCount: UInt8
    let bornAt: ContinuousClock.Instant
    var lastActivity: ContinuousClock.Instant

    var sendBuffer: ByteRingBuffer?
    var recvBuffer: ByteRingBuffer?
    /// Bytes delivered to the app that have not been `creditAppReceive`'d yet.
    var appBuffered = 0
    var reassembly: TCPReassembly
    var maxWindow: Int
    var algorithm: CongestionAlgorithm

    var lastAcked: UInt32
    var dupAcks: UInt32
    var rttProbeSeq: UInt32?
    var rttProbeTime: ContinuousClock.Instant?
    /// Peer sent SACK-permitted on SYN; we only emit SACK blocks after that.
    var peerSackPermitted: Bool
    /// Latest SACK ranges advertised by the peer (TX recovery).
    var sackScoreboard: [SACKBlock] = []
    /// RFC 6675: SND.NXT at recovery entry; nil when not in recovery.
    var recoveryMark: UInt32?
    /// RFC 6675 HighRxt: next sequence considered for retransmission.
    var highRxt: UInt32?
    static let dupThresh: UInt32 = 3
    /// Set for the duration of `onSegment`: FIN was consumed in-order this call.
    var acceptedFIN = false
    /// This segment was not the next expected byte (dup or gap) — ACK immediately.
    var queuedOutOfOrder = false
    /// Dup-ACK was rate-limited this call; `ackIfNeeded` must not fall through to a data ACK.
    var suppressAck = false
    var dupAckEmitted: UInt8 = 0
    var lastDupAckAt: ContinuousClock.Instant?
    /// App called close(); FIN is deferred until `unsentCount == 0`.
    var closePending = false
    var finSent = false

    init(
        flow: FlowKey,
        state: TCPState = .listen,
        iss: UInt32 = UInt32.random(in: 1...UInt32.max / 2),
        window: Int = 64 * 1024,
        algorithm: CongestionAlgorithm = .cubic,
        timerConfig: TCPTimerConfig = .init(),
        maxMss: UInt16 = 1460
    ) {
        self.flow = flow
        self.state = state
        self.iss = iss
        self.sndUna = iss
        self.sndNxt = iss
        self.sndWnd = UInt32(window)
        self.rcvNxt = 0
        self.rcvWnd = UInt32(window)
        self.irs = 0
        self.maxMss = max(1, maxMss)
        self.mss = self.maxMss
        self.sndWndShift = 0
        self.rcvWndShift = 7
        self.windowScaleEnabled = false
        self.rtt = RTTEstimator(timers: timerConfig)
        self.congestion = CongestionState(algorithm: algorithm, mss: UInt32(self.maxMss))
        self.tfoEnabled = true
        self.tfoDelivered = false
        self.deadlines = TCPDeadlines()
        self.timerConfig = timerConfig
        self.keepAliveProbesSent = 0
        self.retransmitCount = 0
        let now = ContinuousClock().now
        self.bornAt = now
        self.lastActivity = now
        self.sendBuffer = nil
        self.recvBuffer = nil
        self.maxWindow = window
        self.algorithm = algorithm
        self.reassembly = TCPReassembly(
            maxHoles: 32,
            maxBytes: min(max(window, 1), TCPReassembly.defaultMaxBytes)
        )
        self.lastAcked = iss
        self.peerSackPermitted = false
        self.dupAcks = 0
        self.rttProbeSeq = nil
        self.rttProbeTime = nil
        if timerConfig.maxLifetime > .zero {
            self.deadlines.arm(.lifetime, at: now.advanced(by: timerConfig.maxLifetime))
        }
        if let ttl = timerConfig.idleTTL(for: state) {
            self.deadlines.arm(.idle, at: now.advanced(by: ttl))
        }
    }

    var advertisedWindow: UInt16 {
        let shift = windowScaleEnabled ? rcvWndShift : 0
        let scaled = min(rcvWnd >> shift, UInt32(UInt16.max))
        return UInt16(scaled)
    }

    var inflight: UInt32 { sndNxt &- sndUna }

    /// Bytes that still fit under the send-buffer cap (including grow room).
    var sendAvailable: Int {
        max(0, maxSendBytes - (sendBuffer?.count ?? 0))
    }

    var canAppSend: Bool {
        if closePending { return false }
        switch state {
        case .established, .closeWait: return true
        default: return false
        }
    }

    /// Drive the TCB with an inbound segment and optional zero-copy payload.
    @discardableResult
    func onSegment(
        _ segment: TCPSegment,
        payload: Data,
        now: ContinuousClock.Instant = ContinuousClock().now
    ) -> [TCPAction] {
        if segment.hasRST {
            return handleIncomingRST(segment, now: now)
        }
        if let reject = rejectUnacceptable(segment, now: now) {
            return reject
        }
        acceptedFIN = false
        queuedOutOfOrder = false
        suppressAck = false
        let unaBefore = sndUna
        applyPassive(segment: segment, payload: payload, now: now)
        let newlyAcked = Seq.lt(unaBefore, sndUna)
        let rcvWndBeforeDeliver = rcvWnd
        var smSegment = segment
        if acceptedFIN {
            smSegment.flags.insert(.fin)
        } else {
            smSegment.flags.remove(.fin)
        }
        let (next, kinds) = TCPStateMachine.transition(state: state, event: .segment(smSegment))
        var actions = kinds.flatMap { expand($0, segment: segment, payload: payload) }
        state = next
        lastActivity = now
        if newlyAcked {
            if inflight == 0 {
                actions.append(.cancel(.retransmission))
                actions.append(.cancel(.persist))
            } else {
                actions.append(.schedule(.retransmission, rtt.rto))
            }
        }
        if newlyAcked {
            if let high = highRxt, Seq.lt(high, sndUna) { highRxt = sndUna }
            if let mark = recoveryMark, Seq.leq(mark, sndUna) {
                recoveryMark = nil
                highRxt = nil
            }
        }
        actions.append(contentsOf: recoverLost())
        if unsentCount > 0, sndWnd > 0 {
            let extra: UInt32
            if recoveryMark == nil, dupAcks > 0, dupAcks < Self.dupThresh {
                extra = UInt32(mss) &* dupAcks
            } else {
                extra = 0
            }
            actions.append(contentsOf: emitData(retransmit: false, extraCwnd: extra))
        }
        actions.append(contentsOf: finishCloseIfDrained(now: now))
        if kinds.contains(.deliverData), rcvWnd > rcvWndBeforeDeliver {
            let jump = rcvWnd &- rcvWndBeforeDeliver
            if rcvWndBeforeDeliver == 0 || jump >= UInt32(mss) &* 2 {
                actions.append(emitAck())
                actions.append(.cancel(.delayedAck))
            }
        }
        actions.append(contentsOf: activityTimers())
        actions.append(contentsOf: orphanTimers())
        return commitTimers(actions, now: now)
    }

    func onAppSend(_ data: Data, now: ContinuousClock.Instant = ContinuousClock().now) -> [TCPAction] {
        enqueueSend(data)
        let (next, kinds) = TCPStateMachine.transition(state: state, event: .appSend(data.count))
        var actions = kinds.flatMap { expand($0, segment: nil, payload: Data()) }
        state = next
        if sndWnd == 0, (sendBuffer?.count ?? 0) > 0 {
            actions.append(.schedule(.persist, rtt.rto))
        }
        lastActivity = now
        actions.append(contentsOf: activityTimers())
        actions.append(contentsOf: orphanTimers())
        return commitTimers(actions, now: now)
    }

    func onAppClose(now: ContinuousClock.Instant = ContinuousClock().now) -> [TCPAction] {
        closePending = true
        lastActivity = now
        var actions: [TCPAction] = []
        if unsentCount > 0 {
            actions.append(contentsOf: emitData(retransmit: false))
        }
        actions.append(contentsOf: finishCloseIfDrained(now: now))
        if unsentCount > 0 {
            actions.append(.schedule(.retransmission, rtt.rto))
        }
        return commitTimers(actions + orphanTimers(), now: now)
    }

    /// Active open: emit SYN and move to SYN-SENT (listenLocal / inbound relay).
    func onAppConnect(now: ContinuousClock.Instant = ContinuousClock().now) -> [TCPAction] {
        state = .synSent
        sndNxt = iss &+ 1
        lastActivity = now
        let opts = TCPOptions(
            mss: maxMss,
            windowScale: rcvWndShift,
            sackPermitted: true,
            tfoCookie: nil
        )
        var actions: [TCPAction] = [
            .send(
                flags: .syn,
                seq: iss,
                ack: 0,
                window: advertisedWindow,
                payload: Data(),
                options: opts
            ),
            .schedule(.retransmission, rtt.rto),
        ]
        if let ttl = timerConfig.idleTTL(for: .synSent) {
            actions.append(.schedule(.idle, ttl))
        }
        return commitTimers(actions + orphanTimers(), now: now)
    }

    /// RFC 1191 / 1981: shrink MSS when a Packet Too Big is reported for this flow.
    func applyPMTU(mtu: Int) {
        let overhead = flow.src.version == .v4 ? 40 : 60
        let clamped = UInt16(clamping: max(536, mtu - overhead))
        if clamped < mss {
            mss = clamped
        }
    }

    func onTimeout(_ kind: TCPTimerKind, now: ContinuousClock.Instant = ContinuousClock().now) -> [TCPAction] {
        if kind == .idle || kind == .lifetime {
            return abort(now: now)
        }
        if kind == .retransmission {
            if inflight == 0 {
                return commitTimers([.cancel(.retransmission)] + orphanTimers(), now: now)
            }
            retransmitCount &+= 1
            if retransmitCount >= timerConfig.maxRetransmits {
                return abort(now: now)
            }
            congestion.onTimeout()
            rtt.backoff()
            rttProbeSeq = nil
            rttProbeTime = nil
        }
        if kind == .keepAlive {
            if keepAliveProbesSent >= timerConfig.keepAliveProbes {
                return abort(now: now)
            }
            keepAliveProbesSent &+= 1
        }
        let (next, kinds) = TCPStateMachine.transition(state: state, event: .timeout(kind))
        var actions = kinds.flatMap { expand($0, segment: nil, payload: Data()) }
        state = next
        if kind == .keepAlive, state == .established {
            actions.append(.schedule(.keepAlive, timerConfig.keepAliveInterval))
        }
        actions.append(contentsOf: orphanTimers())
        return commitTimers(actions, now: now)
    }

    /// RST + close so the EventLoop both emits a reset segment and frees the PCB.
    func abort(now: ContinuousClock.Instant) -> [TCPAction] {
        reassembly.clear()
        var actions = expand(.reset, segment: nil, payload: Data())
        actions.append(.closed)
        state = .closed
        return commitTimers(actions, now: now)
    }

    /// Close without emitting RST (incoming RST, RFC 793).
    func closeQuietly(now: ContinuousClock.Instant) -> [TCPAction] {
        reassembly.clear()
        state = .closed
        return commitTimers([.closed], now: now)
    }

    /// RFC 5961: reset only when SEQ == RCV.NXT; in-window RST gets a challenge ACK.
    func handleIncomingRST(_ segment: TCPSegment, now: ContinuousClock.Instant) -> [TCPAction] {
        switch state {
        case .closed, .listen, .timeWait:
            return []
        case .synSent:
            let acceptable = segment.hasACK && segment.ack == sndNxt
            return acceptable ? closeQuietly(now: now) : []
        default:
            if segment.seq == rcvNxt {
                return closeQuietly(now: now)
            }
            let inWindow = rcvWnd > 0
                && Seq.between(segment.seq, start: rcvNxt, end: rcvNxt &+ rcvWnd)
            guard inWindow else { return [] }
            lastActivity = now
            return commitTimers(
                [emitAck(), .cancel(.delayedAck)] + activityTimers() + orphanTimers(),
                now: now
            )
        }
    }

    /// RFC 793: SYN-RECEIVED with an ACK outside [SND.UNA, SND.NXT] is reset.
    func rejectUnacceptable(_ segment: TCPSegment, now: ContinuousClock.Instant) -> [TCPAction]? {
        guard state == .synReceived, segment.hasACK else { return nil }
        let ackOk = segment.ack == sndNxt
        return ackOk ? nil : abort(now: now)
    }
    @discardableResult
    func ensureSendBuffer() -> ByteRingBuffer {
        if let existing = sendBuffer { return existing }
        let created = ByteRingBuffer(capacity: maxWindow.nextPowerOfTwo)
        sendBuffer = created
        return created
    }

    @discardableResult
    func ensureRecvBuffer() -> ByteRingBuffer {
        if let existing = recvBuffer { return existing }
        let created = ByteRingBuffer(capacity: maxWindow.nextPowerOfTwo)
        recvBuffer = created
        rcvWnd = UInt32(created.available)
        return created
    }

    /// Drop payload, keep ring allocations so a pooled PCB can skip malloc.
    func prepareForPool() {
        sendBuffer?.clear()
        recvBuffer?.clear()
        appBuffered = 0
        reassembly.clear()
        deadlines.clearAll()
        tfoDelivered = false
        acceptedFIN = false
        queuedOutOfOrder = false
        suppressAck = false
        dupAckEmitted = 0
        lastDupAckAt = nil
        lastAcked = iss
        dupAcks = 0
        rttProbeSeq = nil
        rttProbeTime = nil
        keepAliveProbesSent = 0
        retransmitCount = 0
        peerSackPermitted = false
        windowScaleEnabled = false
        closePending = false
        finSent = false
        sackScoreboard = []
        recoveryMark = nil
        highRxt = nil
    }

    func resetForReuse(
        flow: FlowKey,
        iss: UInt32,
        window: Int,
        algorithm: CongestionAlgorithm,
        timerConfig: TCPTimerConfig,
        tfo: Bool,
        maxMss: UInt16 = 1460
    ) {
        let want = window.nextPowerOfTwo
        if sendBuffer?.capacity != want { sendBuffer = nil }
        if recvBuffer?.capacity != want { recvBuffer = nil }
        prepareForPool()
        self.flow = flow
        self.state = .listen
        self.iss = iss
        self.sndUna = iss
        self.sndNxt = iss
        self.sndWnd = UInt32(window)
        self.rcvNxt = 0
        self.rcvWnd = UInt32(window)
        self.irs = 0
        self.maxMss = max(1, maxMss)
        self.mss = self.maxMss
        self.sndWndShift = 0
        self.rcvWndShift = 7
        self.windowScaleEnabled = false
        self.rtt = RTTEstimator(timers: timerConfig)
        self.congestion = CongestionState(algorithm: algorithm, mss: UInt32(self.maxMss))
        self.tfoEnabled = tfo
        self.tfoDelivered = false
        self.maxWindow = window
        self.algorithm = algorithm
        self.reassembly = TCPReassembly(
            maxHoles: 32,
            maxBytes: min(max(window, 1), TCPReassembly.defaultMaxBytes)
        )
        let now = ContinuousClock().now
        self.lastActivity = now
        self.lastAcked = iss
        if timerConfig.maxLifetime > .zero {
            self.deadlines.arm(.lifetime, at: now.advanced(by: timerConfig.maxLifetime))
        }
        if let ttl = timerConfig.idleTTL(for: state) {
            self.deadlines.arm(.idle, at: now.advanced(by: ttl))
        }
    }

}
