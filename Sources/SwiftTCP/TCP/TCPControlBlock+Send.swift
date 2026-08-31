import Foundation

extension TCPControlBlock {
    var unsentCount: Int {
        let buffered = sendBuffer?.count ?? 0
        let inFlightData = min(Int(sndNxt &- sndUna), buffered)
        return buffered - inFlightData
    }

    var maxSendBytes: Int {
        let scaled = maxWindow <= Int.max / 4 ? maxWindow * 4 : Int.max / 2
        return max(maxWindow.nextPowerOfTwo, scaled.nextPowerOfTwo)
    }

    /// Copy into the send ring, growing up to `maxSendBytes` instead of dropping.
    @discardableResult
    func enqueueSend(_ data: Data) -> Int {
        let buffer = ensureSendBuffer()
        var written = buffer.write(data)
        if written < data.count {
            let needed = buffer.count + (data.count - written)
            var capacity = needed.nextPowerOfTwo
            if capacity > maxSendBytes { capacity = maxSendBytes }
            if capacity > buffer.capacity {
                buffer.grow(to: capacity)
                written += buffer.write(Data(data.dropFirst(written)))
            }
        }
        return written
    }

    /// Send remaining data first; only then emit FIN (RFC 793).
    func finishCloseIfDrained(now: ContinuousClock.Instant) -> [TCPAction] {
        _ = now
        guard closePending, !finSent, unsentCount == 0 else { return [] }
        switch state {
        case .established, .closeWait, .synReceived, .synSent:
            break
        default:
            return []
        }
        let (next, kinds) = TCPStateMachine.transition(state: state, event: .appClose)
        guard kinds.contains(.sendFin) else { return [] }
        finSent = true
        let actions = kinds.flatMap { expand($0, segment: nil, payload: Data()) }
        state = next
        return actions
    }

    /// Send buffer: index 0 is SND.UNA. Unsent data starts at min(SND.NXT-SND.UNA, count).
    /// New data fills cwnd/window (up to 32 segments). Retransmit sends one segment from SND.UNA.
    func emitData(retransmit: Bool, extraCwnd: UInt32 = 0) -> [TCPAction] {
        if retransmit {
            if let segment = emitOneSegment(retransmit: true) { return [segment] }
            return []
        }
        if sndWnd == 0 {
            return persistIfNeeded()
        }
        var actions: [TCPAction] = []
        while actions.count < 32 {
            guard let segment = emitOneSegment(retransmit: false, extraCwnd: extraCwnd) else { break }
            actions.append(segment)
        }
        return actions
    }

    func persistIfNeeded() -> [TCPAction] {
        if (sendBuffer?.count ?? 0) > 0 {
            return [.schedule(.persist, rtt.rto)]
        }
        return []
    }
    func emitOneSegment(retransmit: Bool, extraCwnd: UInt32 = 0) -> TCPAction? {
        let buffered = sendBuffer?.count ?? 0
        let inFlightData = min(Int(sndNxt &- sndUna), buffered)
        let offset = retransmit ? 0 : inFlightData
        let seq = retransmit ? sndUna : sndNxt
        let remaining = buffered - offset
        let effectiveCwnd = congestion.cwnd &+ extraCwnd
        let cwndLeft = effectiveCwnd > inflight ? Int(effectiveCwnd - inflight) : 0
        let windowLeft = sndWnd > inflight ? Int(sndWnd - inflight) : 0
        let budget = retransmit
            ? min(Int(mss), remaining, max(Int(sndWnd), 1))
            : min(Int(mss), remaining, cwndLeft, windowLeft)
        guard budget > 0 else { return nil }
        if rttProbeSeq == nil {
            rttProbeSeq = seq
            rttProbeTime = lastActivity
        }
        if !retransmit {
            sndNxt &+= UInt32(budget)
        }
        return .sendFromBuffer(
            flags: .ack.union(.psh),
            seq: seq,
            ack: rcvNxt,
            window: advertisedWindow,
            offset: offset,
            length: budget,
            options: ackOptions()
        )
    }

    func emitAck() -> TCPAction {
        .send(
            flags: .ack,
            seq: sndNxt,
            ack: rcvNxt,
            window: advertisedWindow,
            payload: Data(),
            options: ackOptions()
        )
    }

    func emitWindowProbe() -> [TCPAction] {
        let bytes = sendBuffer?.peek(offset: 0, maxCount: 1) ?? Data()
        return [
            .send(
                flags: .ack,
                seq: sndUna,
                ack: rcvNxt,
                window: advertisedWindow,
                payload: bytes,
                options: .empty
            ),
            .schedule(.persist, rtt.rto),
        ]
    }
}
