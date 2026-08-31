import Foundation

extension TCPControlBlock {
    func orphanTimers() -> [TCPAction] {
        if let ttl = timerConfig.idleTTL(for: state) {
            return [.schedule(.idle, ttl)]
        }
        return [.cancel(.idle)]
    }

    func commitTimers(_ actions: [TCPAction], now: ContinuousClock.Instant = ContinuousClock().now) -> [TCPAction] {
        for action in actions {
            switch action {
            case .schedule(let kind, let delay):
                deadlines.arm(kind, at: now.advanced(by: delay))
            case .cancel(let kind):
                deadlines.clear(kind)
            case .closed:
                deadlines.clearAll()
            default:
                break
            }
        }
        return actions
    }

    func activityTimers() -> [TCPAction] {
        guard state == .established else { return [] }
        keepAliveProbesSent = 0
        return [.schedule(.keepAlive, timerConfig.keepAliveIdle)]
    }
}
