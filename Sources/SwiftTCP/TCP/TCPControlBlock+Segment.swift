import Foundation

extension TCPControlBlock {
    func applyPassive(segment: TCPSegment, payload rawPayload: Data, now: ContinuousClock.Instant) {
        let opening = state == .listen || state == .synSent || state == .closed
        var payload = rawPayload
        if segment.hasSYN {
            // RFC 7413: passive SYN data only with a valid cookie; otherwise ACK just the SYN
            // so the client retransmits it after the handshake.
            let passive = state == .listen || state == .closed
            let acceptData = opening && (!passive || tfoCookieValid(segment.options.tfoCookie))
            if !acceptData { payload = Data() }
        }
        if segment.hasSYN, opening {
            irs = segment.seq
            rcvNxt = segment.seq &+ 1
            if tfoEnabled, segment.options.tfoCookie != nil {
                synAckCookie = Self.tfoCookie(for: flow.src)
            }
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
                // `rttProbeSeq` is the probe's end; Karn's rule clears it on retransmit.
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
                &+ UInt32(rawPayload.count)
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
            return [synAck()]
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
        case .sendData:
            return emitData(retransmit: false)
        case .retransmit:
            return retransmitOldest()
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
            // SYN data is queued in `recvBuffer` and flushed by `.deliverData` after ESTABLISHED.
            return []
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

    /// RFC 7323: the window field of a SYN is never scaled.
    var synWindow: UInt16 { UInt16(min(rcvWnd, UInt32(UInt16.max))) }

    func synAck() -> TCPAction {
        .send(
            flags: .syn.union(.ack),
            seq: iss,
            ack: rcvNxt,
            window: synWindow,
            payload: Data(),
            options: TCPOptions(
                mss: maxMss,
                windowScale: windowScaleEnabled ? rcvWndShift : nil,
                sackPermitted: true,
                tfoCookie: synAckCookie
            )
        )
    }

    func synOptions() -> TCPOptions {
        TCPOptions(mss: maxMss, windowScale: rcvWndShift, sackPermitted: true, tfoCookie: nil)
    }

    /// RTO: resend the oldest unacknowledged thing — SYN, SYN-ACK, data, or FIN.
    func retransmitOldest() -> [TCPAction] {
        switch state {
        case .synSent:
            return [.send(flags: .syn, seq: iss, ack: 0, window: synWindow, payload: Data(), options: synOptions())]
        case .synReceived:
            return [synAck()]
        default:
            break
        }
        rttProbeSeq = nil
        rttProbeTime = nil
        if (sendBuffer?.count ?? 0) > 0 {
            return emitData(retransmit: true)
        }
        if finSent, Seq.lt(sndUna, sndNxt) {
            return [
                .send(
                    flags: .fin.union(.ack),
                    seq: sndNxt &- 1,
                    ack: rcvNxt,
                    window: advertisedWindow,
                    payload: Data(),
                    options: ackOptions()
                ),
            ]
        }
        return []
    }

    /// Server TFO cookie: keyed by the client address with the per-process random hash seed.
    static func tfoCookie(for address: IPAddress) -> Data {
        var hasher = Hasher()
        hasher.combine(address)
        hasher.combine(0x5446_4F43 as UInt32) // domain separator
        var value = UInt64(bitPattern: Int64(hasher.finalize())).bigEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }

    func tfoCookieValid(_ cookie: Data?) -> Bool {
        guard tfoEnabled, let cookie, !cookie.isEmpty else { return false }
        return cookie == Self.tfoCookie(for: flow.src)
    }
}
