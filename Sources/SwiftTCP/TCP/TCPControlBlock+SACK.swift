import Foundation

extension TCPControlBlock {
    func ackOptions() -> TCPOptions {
        guard peerSackPermitted, !reassembly.holes.isEmpty else { return .empty }
        let blocks = reassembly.sackBlocks()
        guard !blocks.isEmpty else { return .empty }
        return TCPOptions(mss: nil, windowScale: nil, sackPermitted: false, tfoCookie: nil, sackBlocks: blocks)
    }

    func recoverLost() -> [TCPAction] {
        let unaLost = isLost(sndUna) || dupAcks >= Self.dupThresh
        if recoveryMark == nil, unaLost, Seq.lt(sndUna, sndNxt) {
            recoveryMark = sndNxt
            highRxt = sndUna
            congestion.onLoss()
        }
        guard recoveryMark != nil || unaLost else { return [] }
        var actions: [TCPAction] = []
        var pipe = recoveryPipe
        let cursor = highRxt ?? sndUna
        var nextSeq = cursor
        while actions.count < 4, pipe < congestion.cwnd {
            guard let hole = nextLostSegment(after: nextSeq) else { break }
            guard let rexmit = emitRetransmit(from: hole.seq, limit: hole.length) else { break }
            actions.append(rexmit)
            if case .sendFromBuffer(_, _, _, _, _, let length, _) = rexmit {
                nextSeq = hole.seq &+ UInt32(length)
                highRxt = nextSeq
                pipe &+= UInt32(length)
            } else {
                break
            }
        }
        return actions
    }

    func isCoveredBySack(_ seq: UInt32) -> Bool {
        sackScoreboard.contains { Seq.leq($0.left, seq) && Seq.lt(seq, $0.right) }
    }

    func sackedBytesAbove(_ seq: UInt32) -> UInt32 {
        var total: UInt32 = 0
        for block in sackScoreboard {
            if Seq.leq(block.right, seq) { continue }
            let left = Seq.lt(block.left, seq) ? seq : block.left
            if Seq.lt(left, block.right) {
                total &+= block.right &- left
            }
        }
        return total
    }

    func isLost(_ seq: UInt32) -> Bool {
        if Seq.leq(sndNxt, seq) || isCoveredBySack(seq) { return false }
        if dupAcks >= Self.dupThresh { return true }
        let need = UInt32(mss) &* (Self.dupThresh &- 1)
        return sackedBytesAbove(seq) >= need
    }

    func sackHoles() -> [(seq: UInt32, length: Int)] {
        let una = sndUna
        let nxt = sndNxt
        guard Seq.lt(una, nxt) else { return [] }
        if sackScoreboard.isEmpty {
            if dupAcks >= Self.dupThresh {
                return [(una, Int(min(UInt32(mss), nxt &- una)))]
            }
            return []
        }
        let ordered = sackScoreboard.sorted { Seq.lt($0.left, $1.left) }
        var holes: [(seq: UInt32, length: Int)] = []
        var cursor = una
        for block in ordered {
            if Seq.leq(block.right, cursor) { continue }
            if Seq.lt(cursor, block.left) {
                holes.append((cursor, Int(block.left &- cursor)))
            }
            if Seq.lt(cursor, block.right) { cursor = block.right }
        }
        return holes
    }

    func nextLostSegment(after: UInt32) -> (seq: UInt32, length: Int)? {
        let start = Seq.lt(after, sndUna) ? sndUna : after
        for hole in sackHoles() {
            let holeEnd = hole.seq &+ UInt32(hole.length)
            let seq = Seq.lt(hole.seq, start) ? start : hole.seq
            guard Seq.lt(seq, holeEnd) else { continue }
            if isLost(hole.seq) || isLost(seq) {
                return (seq, Int(holeEnd &- seq))
            }
        }
        return nil
    }

    var recoveryPipe: UInt32 {
        let flight = inflight
        var sacked: UInt32 = 0
        for block in sackScoreboard {
            let left = Seq.lt(block.left, sndUna) ? sndUna : block.left
            let right = Seq.lt(sndNxt, block.right) ? sndNxt : block.right
            if Seq.lt(left, right) { sacked &+= right &- left }
        }
        var lost: UInt32 = 0
        for hole in sackHoles() {
            if isLost(hole.seq) { lost &+= UInt32(hole.length) }
        }
        if flight > sacked &+ lost { return flight &- sacked &- lost }
        return 0
    }
    func emitRetransmit(from seq: UInt32, limit: Int) -> TCPAction? {
        guard Seq.leq(sndUna, seq), Seq.lt(seq, sndNxt) else { return nil }
        let offset = Int(seq &- sndUna)
        let buffered = sendBuffer?.count ?? 0
        guard offset < buffered else { return nil }
        let remaining = min(buffered - offset, Int(sndNxt &- seq))
        let budget = min(Int(mss), remaining, max(limit, 0), max(Int(sndWnd), 1))
        guard budget > 0 else { return nil }
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
}
