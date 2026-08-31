import Foundation

/// Jacobson/Karels RTT estimator with a tracked min-RTT for BBR.
/// RTO floor is ~20ms so local microVM loss recovers before delayed-ACK waits.
public struct RTTEstimator: Sendable {
    public var srtt: Duration
    public var rttvar: Duration
    public var minRTT: Duration
    public var rto: Duration
    public var sampled: Bool
    public var minRTO: Duration
    public var maxRTO: Duration

    public init(timers: TCPTimerConfig = .init()) {
        self.minRTO = timers.minRTO
        self.maxRTO = timers.maxRTO
        self.srtt = timers.initialRTO
        self.rttvar = timers.initialRTO / 2
        self.minRTT = .milliseconds(Int.max)
        self.rto = timers.initialRTO
        self.sampled = false
    }

    public mutating func sample(_ rtt: Duration) {
        let clamped = max(rtt, .microseconds(1))
        if !sampled {
            srtt = clamped
            rttvar = clamped / 2
            sampled = true
        } else {
            let diff = absDuration(srtt, clamped)
            rttvar = (rttvar * 3 + diff) / 4
            srtt = (srtt * 7 + clamped) / 8
        }
        if clamped < minRTT { minRTT = clamped }
        rto = clampRTO(srtt + rttvar * 4)
    }

    /// RFC 6298 exponential backoff. Call on retransmission timeout.
    public mutating func backoff() {
        rto = clampRTO(rto * 2)
    }

    private func clampRTO(_ value: Duration) -> Duration {
        min(max(value, minRTO), maxRTO)
    }
}

private func absDuration(_ a: Duration, _ b: Duration) -> Duration {
    a > b ? a - b : b - a
}

public protocol CongestionControl: Sendable {
    var cwnd: UInt32 { get }
    var ssthresh: UInt32 { get }
    var pacingRateBps: UInt64 { get }
    mutating func onAck(acked: UInt32, rtt: Duration, inflight: UInt32, now: ContinuousClock.Instant)
    mutating func onLoss()
    mutating func onTimeout()
}

/// Linux CUBIC (Reno-free). Window is in bytes.
public struct CUBIC: CongestionControl {
    public var cwnd: UInt32
    public var ssthresh: UInt32
    public var wMax: UInt32
    public var epochStart: ContinuousClock.Instant?
    public var mss: UInt32

    private let c: Double = 0.4
    private let beta: Double = 0.7

    public init(mss: UInt32 = 1460, initialCwnd: UInt32 = 10 * 1460) {
        self.mss = mss
        self.cwnd = initialCwnd
        self.ssthresh = .max
        self.wMax = initialCwnd
        self.epochStart = nil
    }

    public var pacingRateBps: UInt64 { 0 }

    public mutating func onAck(acked: UInt32, rtt: Duration, inflight: UInt32, now: ContinuousClock.Instant) {
        _ = inflight
        _ = rtt
        if cwnd < ssthresh {
            cwnd = min(cwnd &+ acked, 4_000_000)
            return
        }
        let t: Double
        if let start = epochStart {
            t = durationSeconds(start.duration(to: now))
        } else {
            epochStart = now
            t = 0
        }
        let wMaxSeg = Double(max(wMax / mss, 1))
        let k = cbrt(wMaxSeg * (1 - beta) / c)
        let dt = t - k
        let wCubic = c * dt * dt * dt + wMaxSeg
        let cubicCwnd = UInt32(max(wCubic, 2) * Double(mss))
        if cubicCwnd > cwnd {
            cwnd = cubicCwnd
        }
        cwnd = min(cwnd, 4_000_000)
    }

    public mutating func onLoss() {
        wMax = cwnd
        ssthresh = max(UInt32(Double(cwnd) * beta), 2 * mss)
        cwnd = ssthresh
        epochStart = ContinuousClock().now
    }

    public mutating func onTimeout() {
        onLoss()
        cwnd = 2 * mss
    }
}

/// BBR-inspired rate-based control: max-bandwidth filter + min-RTT, four phases.
public struct BBR: CongestionControl {
    public enum Phase: Sendable {
        case startup
        case drain
        case probeBW
        case probeRTT
    }

    public var cwnd: UInt32
    public var ssthresh: UInt32
    public var pacingRateBps: UInt64
    public var phase: Phase
    public var btlBw: UInt64
    public var minRTT: Duration
    public var mss: UInt32
    public var delivered: UInt64
    public var cycleIndex: Int
    public var probeRTTEnd: ContinuousClock.Instant?

    private static let pacingGainCycle: [Double] = [1.25, 0.75, 1, 1, 1, 1, 1, 1]
    private let startupGain: Double = 2.89

    public init(mss: UInt32 = 1460, initialCwnd: UInt32 = 10 * 1460) {
        self.mss = mss
        self.cwnd = initialCwnd
        self.ssthresh = .max
        self.pacingRateBps = 100_000
        self.phase = .startup
        self.btlBw = 100_000
        self.minRTT = .milliseconds(100)
        self.delivered = 0
        self.cycleIndex = 0
        self.probeRTTEnd = nil
    }

    public mutating func onAck(acked: UInt32, rtt: Duration, inflight: UInt32, now: ContinuousClock.Instant) {
        delivered &+= UInt64(acked)
        if rtt < minRTT { minRTT = rtt }
        let rttSec = max(durationSeconds(rtt), 0.000_001)
        let sample = UInt64(Double(acked) / rttSec)
        if sample > btlBw { btlBw = sample }

        let minRTTSec = max(durationSeconds(minRTT), 0.000_001)
        let bdp = UInt32(min(Double(btlBw) * minRTTSec, Double(UInt32.max)))

        switch phase {
        case .startup:
            let cap = bdp > UInt32.max / 2 ? UInt32.max : bdp * 2
            cwnd = max(cwnd, cap)
            pacingRateBps = UInt64(Double(btlBw) * startupGain)
            if inflight >= cwnd * 3 / 4 && sample < btlBw * 5 / 4 {
                phase = .drain
            }
        case .drain:
            pacingRateBps = UInt64(Double(btlBw) / startupGain)
            cwnd = max(bdp, 2 * mss)
            if inflight <= bdp {
                phase = .probeBW
            }
        case .probeBW:
            let gain = Self.pacingGainCycle[cycleIndex % Self.pacingGainCycle.count]
            pacingRateBps = UInt64(Double(btlBw) * gain)
            cwnd = max(UInt32(Double(bdp) * 2), 4 * mss)
            cycleIndex &+= 1
            if minRTT > .milliseconds(0), cycleIndex % 32 == 0 {
                phase = .probeRTT
                probeRTTEnd = now.advanced(by: .milliseconds(200))
                cwnd = 4 * mss
            }
        case .probeRTT:
            cwnd = 4 * mss
            pacingRateBps = btlBw
            if let end = probeRTTEnd, now >= end {
                phase = .probeBW
                probeRTTEnd = nil
            }
        }
    }

    public mutating func onLoss() {
        btlBw = max(btlBw / 2, 10_000)
        if phase == .startup { phase = .drain }
    }

    public mutating func onTimeout() {
        phase = .startup
        cwnd = 4 * mss
    }
}

public enum CongestionAlgorithm: Sendable {
    case cubic
    case bbr
}

public struct CongestionState: Sendable {
    public var cubic: CUBIC
    public var bbr: BBR
    public var algorithm: CongestionAlgorithm

    public init(algorithm: CongestionAlgorithm = .cubic, mss: UInt32 = 1460) {
        self.algorithm = algorithm
        self.cubic = CUBIC(mss: mss)
        self.bbr = BBR(mss: mss)
    }

    public var cwnd: UInt32 {
        switch algorithm {
        case .cubic: cubic.cwnd
        case .bbr: bbr.cwnd
        }
    }

    public var pacingRateBps: UInt64 {
        switch algorithm {
        case .cubic: cubic.pacingRateBps
        case .bbr: bbr.pacingRateBps
        }
    }

    public mutating func onAck(acked: UInt32, rtt: Duration, inflight: UInt32, now: ContinuousClock.Instant) {
        switch algorithm {
        case .cubic: cubic.onAck(acked: acked, rtt: rtt, inflight: inflight, now: now)
        case .bbr: bbr.onAck(acked: acked, rtt: rtt, inflight: inflight, now: now)
        }
    }

    public mutating func onLoss() {
        switch algorithm {
        case .cubic: cubic.onLoss()
        case .bbr: bbr.onLoss()
        }
    }

    public mutating func onTimeout() {
        switch algorithm {
        case .cubic: cubic.onTimeout()
        case .bbr: bbr.onTimeout()
        }
    }
}

private func durationSeconds(_ d: Duration) -> Double {
    Double(d.components.seconds) + Double(d.components.attoseconds) / 1e18
}
