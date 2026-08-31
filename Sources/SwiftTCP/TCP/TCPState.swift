import Foundation

/// smoltcp-style TCP states. Pure data: no sockets, no threads.
public enum TCPState: Sendable, Equatable {
    case closed
    case listen
    case synSent
    case synReceived
    case established
    case finWait1
    case finWait2
    case closing
    case timeWait
    case closeWait
    case lastAck
}

public enum TCPTimerKind: Sendable, Equatable, Hashable {
    case retransmission
    case timeWait
    case persist
    case delayedAck
    case keepAlive
    /// State-specific zombie TTL (handshake / FIN-WAIT-2 / CLOSE-WAIT).
    case idle
    /// Absolute PCB lifetime from creation.
    case lifetime
}

public enum TCPEvent: Sendable {
    case segment(TCPSegment)
    case appSend(Int)
    case appClose
    case timeout(TCPTimerKind)
    case userAbort
}

/// Side effects emitted by the pure state machine. The EventLoop performs them.
public enum TCPAction: Sendable {
    case send(flags: TCPFlags, seq: UInt32, ack: UInt32, window: UInt16, payload: Data, options: TCPOptions)
    /// Payload lives in `TCPControlBlock.sendBuffer` at `[offset, offset+length)`.
    case sendFromBuffer(
        flags: TCPFlags, seq: UInt32, ack: UInt32, window: UInt16,
        offset: Int, length: Int, options: TCPOptions
    )
    case deliver(Data)
    case established
    case closed
    case reset
    case schedule(TCPTimerKind, Duration)
    case cancel(TCPTimerKind)
}

/// Sequence-number arithmetic (RFC 793 unsigned modular compare).
public enum Seq: Sendable {
    @inlinable
    public static func lt(_ a: UInt32, _ b: UInt32) -> Bool {
        Int32(bitPattern: a &- b) < 0
    }

    @inlinable
    public static func leq(_ a: UInt32, _ b: UInt32) -> Bool {
        Int32(bitPattern: a &- b) <= 0
    }

    @inlinable
    public static func between(_ seq: UInt32, start: UInt32, end: UInt32) -> Bool {
        Seq.leq(start, seq) && Seq.lt(seq, end)
    }
}

/// Data-driven transition table. Given `(state, event)` returns the next state
/// plus an ordered list of actions. The TCB is mutated separately for seq/ack
/// bookkeeping; this function only encodes legal RFC 793 edges.
public enum TCPStateMachine: Sendable {
    public static func transition(state: TCPState, event: TCPEvent) -> (TCPState, [TCPActionKind]) {
        switch (state, event) {
        case (.closed, .segment(let s)) where s.hasSYN && !s.hasRST:
            return (.synReceived, [.sendSynAck, .scheduleRetransmit])

        case (.listen, .segment(let s)) where s.hasSYN && !s.hasRST:
            return (.synReceived, [.sendSynAck, .scheduleRetransmit, .deliverData])

        case (.synReceived, .segment(let s)) where s.hasRST:
            return (.closed, [.closed])

        case (.synReceived, .segment(let s)) where s.hasACK && !s.hasRST:
            return (.established, [.cancelRetransmit, .established, .ackIfNeeded, .deliverData])

        case (.synSent, .segment(let s)) where s.hasSYN && s.hasACK:
            return (.established, [.cancelRetransmit, .sendAck, .established])

        case (.synSent, .segment(let s)) where s.hasSYN && !s.hasACK:
            return (.synReceived, [.sendSynAck])

        case (.established, .segment(let s)) where s.hasRST:
            // RFC 793: never emit RST in response to RST.
            return (.closed, [.closed])

        case (.established, .segment(let s)) where s.hasFIN:
            return (.closeWait, [.deliverData, .sendAck])

        case (.established, .segment):
            return (.established, [.deliverData, .ackIfNeeded])

        case (.established, .appClose):
            return (.finWait1, [.sendFin, .scheduleRetransmit])

        case (.established, .appSend):
            return (.established, [.sendData, .scheduleRetransmit])

        case (.finWait1, .segment(let s)) where s.hasFIN && s.hasACK:
            return (.timeWait, [.sendAck, .scheduleTimeWait])

        case (.finWait1, .segment(let s)) where s.hasFIN:
            return (.closing, [.sendAck])

        case (.finWait1, .segment(let s)) where s.hasACK:
            return (.finWait2, [.cancelRetransmit, .deliverData])

        case (.finWait2, .segment(let s)) where s.hasFIN:
            return (.timeWait, [.sendAck, .scheduleTimeWait])

        case (.closing, .segment(let s)) where s.hasACK:
            return (.timeWait, [.scheduleTimeWait])

        case (.closeWait, .appClose):
            return (.lastAck, [.sendFin, .scheduleRetransmit])

        case (.lastAck, .segment(let s)) where s.hasACK:
            return (.closed, [.cancelRetransmit, .closed])

        case (.established, .timeout(.delayedAck)):
            return (.established, [.sendAck])

        case (.established, .timeout(.persist)):
            return (.established, [.windowProbe])

        case (.established, .timeout(.keepAlive)):
            return (.established, [.keepAliveProbe])

        case (_, .timeout(.idle)), (_, .timeout(.lifetime)):
            return (.closed, [.reset, .closed])

        case (.timeWait, .timeout(.timeWait)):
            return (.closed, [.closed])

        case (_, .segment(let s)) where s.hasRST:
            return (.closed, [.closed])

        case (_, .userAbort):
            return (.closed, [.reset, .closed])

        case (_, .timeout(.retransmission)):
            return (state, [.retransmit, .scheduleRetransmit])

        default:
            return (state, [])
        }
    }
}

/// Coarse action tags used by the table. `TCPControlBlock` expands them
/// into concrete `TCPAction` values using seq/ack/window.
public enum TCPActionKind: Sendable, Equatable {
    case sendSynAck
    case sendAck
    case sendFin
    case sendData
    case ackIfNeeded
    case deliverData
    case maybeDeliverTFO
    case established
    case closed
    case reset
    case scheduleRetransmit
    case cancelRetransmit
    case scheduleTimeWait
    case retransmit
    case keepAliveProbe
    case windowProbe
}
