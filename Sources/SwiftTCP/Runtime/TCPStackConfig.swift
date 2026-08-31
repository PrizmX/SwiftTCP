import Foundation

public struct TCPStackConfig: Sendable {
    public var loopCount: Int
    public var algorithm: CongestionAlgorithm
    public var receiveWindow: Int
    public var tfo: Bool
    public var timers: TCPTimerConfig
    /// Hard cap on concurrent PCBs per EventLoop (SYN-flood / leak ceiling).
    public var maxConnections: Int
    /// Upper bound for our advertised MSS and the peer's SYN MSS option.
    public var maxMss: UInt16

    public init(
        loopCount: Int = max(1, ProcessInfo.processInfo.activeProcessorCount),
        algorithm: CongestionAlgorithm = .cubic,
        receiveWindow: Int = 64 * 1024,
        tfo: Bool = true,
        timers: TCPTimerConfig = .init(),
        maxConnections: Int = 8_192,
        maxMss: UInt16 = 1460
    ) {
        self.loopCount = loopCount
        self.algorithm = algorithm
        self.receiveWindow = receiveWindow
        self.tfo = tfo
        self.timers = timers
        self.maxConnections = maxConnections
        self.maxMss = max(1, maxMss)
    }
}
