import Foundation

extension TCPControlBlock {
    func applyPassive(segment: TCPSegment, payload: Data, now: ContinuousClock.Instant) {
        let opening = state == .listen || state == .synSent || state == .closed
        if segment.hasSYN, opening {
            irs = segment.seq
            rcvNxt = segment.seq &+ 1
            if let peerMss = segment.options.mss, peerMss > 0 {
                self.mss = min(peerMss, maxMss)
            }
            if let ws = segment.options.windowScale {
                sndWndShift = min(ws, 14)
                windowScaleEnabled = true
            }
            if segment.options.sackPermitted {
                peerSackPermitted = true
            }
            // RFC 7323: the SYN window field is never scaled.
            sndWnd = UInt32(segment.window)
        } else if !segment.hasSYN {
            sndWnd = UInt32(segment.window) << (windowScaleEnabled ? sndWndShift : 0)
        }

        if segment.hasACK, Seq.leq(sndUna, segment.ack), Seq.leq(segment.ack, sndNxt) {
            let acked = segment.ack &- sndUna
            if acked > 0 {
                let dataAcked = min(Int(acked), sendBuffer?.count ?? 0)
                sendBuffer?.consume(dataAcked)
                sndUna = segment.ack
                dupAcks = 0
                retransmitCount = 0
                if let probe = rttProbeSeq, Seq.leq(probe, segment.ack), let t0 = rttProbeTime {
                    rtt.sample(t0.duration(to: now))
                    rttProbeSeq = nil
                    rttProbeTime = nil
                }
                congestion.onAck(acked: acked, rtt: rtt.srtt, inflight: inflight, now: now)
            } else if state == .established {
                dupAcks &+= 1
            }
            if !segment.options.sackBlocks.isEmpty {
                sackScoreboard = segment.options.sackBlocks.filter { Seq.lt($0.left, $0.right) }
            }
            sackScoreboard.removeAll { Seq.leq($0.right, sndUna) }
        }

        if !payload.isEmpty {
            let payloadSeq = segment.hasSYN ? segment.seq &+ 1 : segment.seq
            let before = rcvNxt
            _ = reassembly.insert(seq: payloadSeq, data: payload, rcvNxt: rcvNxt, rcvWnd: rcvWnd)
            drainReceiveQueue()
            if rcvNxt == before {
                if shouldEmitDupAck(now: now) {
                    queuedOutOfOrder = true
                } else {
                    suppressAck = true
                }
            } else {
                dupAckEmitted = 0
            }
        }

        if segment.hasFIN {
            let finSeq = segment.seq
                &+ UInt32(payload.count)
                &+ (segment.hasSYN ? 1 : 0)
            if finSeq != rcvNxt, !queuedOutOfOrder, !suppressAck {
                if shouldEmitDupAck(now: now) {
                    queuedOutOfOrder = true
                } else {
                    suppressAck = true
                }
            }
            reassembly.offerFIN(finSeq, rcvNxt: rcvNxt, rcvWnd: rcvWnd)
        }
        acceptedFIN = reassembly.takeFIN(rcvNxt: rcvNxt)
        if acceptedFIN {
            rcvNxt &+= 1
            queuedOutOfOrder = false
            suppressAck = false
            dupAckEmitted = 0
        }
        updateRcvWnd()
    }

    func drainReceiveQueue() {
        let dest = ensureRecvBuffer()
        let n = reassembly.take(from: rcvNxt, maxBytes: dest.available, into: dest)
        rcvNxt &+= UInt32(n)
    }

    func updateRcvWnd() {
        let ringAvail = recvBuffer?.available ?? maxWindow
        let appAvail = max(0, maxWindow - appBuffered)
        rcvWnd = UInt32(min(ringAvail, appAvail))
    }

    func creditAppReceive(_ bytes: Int) {
        guard bytes > 0 else { return }
        appBuffered = max(0, appBuffered - bytes)
        updateRcvWnd()
    }
    func shouldEmitDupAck(now: ContinuousClock.Instant) -> Bool {
        if dupAckEmitted < 3 {
            dupAckEmitted &+= 1
            lastDupAckAt = now
            return true
        }
        let quarter = rtt.srtt / 4
        let minGap: Duration = quarter > .milliseconds(2) ? quarter : .milliseconds(2)
        if let t0 = lastDupAckAt, t0.duration(to: now) < minGap {
            return false
        }
        lastDupAckAt = now
        return true
    }

    func expand(_ kind: TCPActionKind, segment: TCPSegment?, payload: Data) -> [TCPAction] {
        switch kind {
        case .sendSynAck:
            sndNxt = iss &+ 1
            let opts = TCPOptions(
                mss: maxMss,
                windowScale: windowScaleEnabled ? rcvWndShift : nil,
                sackPermitted: true,
                tfoCookie: segment?.options.tfoCookie
            )
            return [
                .send(
                    flags: .syn.union(.ack),
                    seq: iss,
                    ack: rcvNxt,
                    window: advertisedWindow,
                    payload: Data(),
                    options: opts
                ),
            ]
        case .sendAck:
            return [
                emitAck(),
                .cancel(.delayedAck),
            ]
        case .ackIfNeeded:
            guard let segment, segment.payloadLength > 0 || segment.hasFIN else { return [] }
            if suppressAck { return [] }
            if queuedOutOfOrder {
                return [emitAck(), .cancel(.delayedAck)]
            }
            if timerConfig.delayedAck > .zero, segment.payloadLength > 0, !segment.hasFIN {
                if deadlines.delayedAckAt != nil {
                    return [emitAck(), .cancel(.delayedAck)]
                }
                return [.schedule(.delayedAck, timerConfig.delayedAck)]
            }
            return [emitAck()]
        case .sendFin:
            let seq = sndNxt
            sndNxt &+= 1
            return [
                .send(
                    flags: .fin.union(.ack),
                    seq: seq,
                    ack: rcvNxt,
                    window: advertisedWindow,
                    payload: Data(),
                    options: ackOptions()
                ),
            ]
        case .sendData, .retransmit:
            return emitData(retransmit: kind == .retransmit)
        case .windowProbe:
            return emitWindowProbe()
        case .keepAliveProbe:
            let seq = sndNxt &- 1
            return [
                .send(
                    flags: .ack,
                    seq: seq,
                    ack: rcvNxt,
                    window: advertisedWindow,
                    payload: Data(),
                    options: .empty
                ),
            ]
        case .deliverData:
            guard let recv = recvBuffer, recv.count > 0 else { return [] }
            let data = recv.peek(recv.count)
            recv.consume(data.count)
            updateRcvWnd()
            return [.deliver(data)]
        case .maybeDeliverTFO:
            guard tfoEnabled, !tfoDelivered, !payload.isEmpty else { return [] }
            tfoDelivered = true
            return [.deliver(payload)]
        case .established:
            return [.established]
        case .closed:
            return [.closed]
        case .reset:
            return [
                .send(
                    flags: .rst.union(.ack),
                    seq: sndNxt,
                    ack: rcvNxt,
                    window: 0,
                    payload: Data(),
                    options: .empty
                ),
                .reset,
            ]
        case .scheduleRetransmit:
            return [.schedule(.retransmission, rtt.rto)]
        case .cancelRetransmit:
            var actions: [TCPAction] = [.cancel(.retransmission)]
            if inflight > 0 {
                actions.append(.schedule(.retransmission, rtt.rto))
            }
            return actions
        case .scheduleTimeWait:
            return [.schedule(.timeWait, timerConfig.timeWait)]
        }
    }

}
