#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import SwiftTCP

struct BenchConfig: Sendable {
    var scenario: String = "all"
    var duration: Duration = .seconds(5)
    var warmup: Duration = .seconds(1)
    var connections: Int = 8
    var payload: Int = 1460
    var batch: Int = 64
    var loops: Int = max(1, ProcessInfo.processInfo.activeProcessorCount)
    var window: Int = 64 * 1024
    var holdConnections: Int = 4_096
    var activeConnections: Int = 256
    var rpsBytes: Int = 8_192
    var lossPct: Double = 2
    var json: Bool = false
    var output: String?
    var stackName: String = "swifttcp"
    var algorithm: CongestionAlgorithm = .cubic
}

struct ExtraMetrics: Sendable {
    var rps: Double = 0
    var ingestP50Us: Double = 0
    var ingestP99Us: Double = 0
    var handshakeP50Us: Double = 0
    var handshakeP99Us: Double = 0
    var firstByteP50Us: Double = 0
    var firstByteP99Us: Double = 0
    var lossPct: Double = 0
}

struct BenchResult: Codable, Sendable {
    var stack: String
    var scenario: String
    var durationS: Double
    var warmupS: Double
    var connections: Int
    var payloadBytes: Int
    var batch: Int
    var loops: Int
    var windowBytes: Int
    var packetsIn: UInt64
    var bytesIn: UInt64
    var packetsOut: UInt64
    var bytesOut: UInt64
    var deliveredBytes: UInt64
    var established: UInt64
    var pps: Double
    var gbps: Double
    var appGbps: Double
    var cpuUserS: Double
    var cpuSysS: Double
    var cpuCores: Double
    var rssBeforeBytes: UInt64
    var rssAfterBytes: UInt64
    var rssDeltaBytes: UInt64
    var footprintBeforeBytes: UInt64
    var footprintAfterBytes: UInt64
    var bytesPerConnection: Double
    var rps: Double
    var ingestP50Us: Double
    var ingestP99Us: Double
    var handshakeP50Us: Double
    var handshakeP99Us: Double
    var firstByteP50Us: Double
    var firstByteP99Us: Double
    var lossPct: Double
    var notes: String

    static func make(
        scenario: String,
        config: BenchConfig,
        wall: Duration,
        packetsIn: UInt64,
        bytesIn: UInt64,
        packetsOut: UInt64,
        bytesOut: UInt64,
        deliveredBytes: UInt64,
        established: UInt64,
        cpuUser: Double,
        cpuSys: Double,
        rssBefore: UInt64,
        rssAfter: UInt64,
        footBefore: UInt64,
        footAfter: UInt64,
        notes: String = "",
        extra: ExtraMetrics = ExtraMetrics()
    ) -> BenchResult {
        let seconds = durationSeconds(wall)
        let safe = max(seconds, 1e-9)
        return BenchResult(
            stack: config.stackName,
            scenario: scenario,
            durationS: seconds,
            warmupS: durationSeconds(config.warmup),
            connections: config.connections,
            payloadBytes: config.payload,
            batch: config.batch,
            loops: config.loops,
            windowBytes: config.window,
            packetsIn: packetsIn,
            bytesIn: bytesIn,
            packetsOut: packetsOut,
            bytesOut: bytesOut,
            deliveredBytes: deliveredBytes,
            established: established,
            pps: Double(packetsIn) / safe,
            gbps: Double(bytesIn) * 8 / safe / 1_000_000_000,
            appGbps: Double(deliveredBytes) * 8 / safe / 1_000_000_000,
            cpuUserS: cpuUser,
            cpuSysS: cpuSys,
            cpuCores: (cpuUser + cpuSys) / safe,
            rssBeforeBytes: rssBefore,
            rssAfterBytes: rssAfter,
            rssDeltaBytes: rssAfter >= rssBefore ? rssAfter - rssBefore : 0,
            footprintBeforeBytes: footBefore,
            footprintAfterBytes: footAfter,
            bytesPerConnection: established > 0 && rssAfter >= rssBefore
                ? Double(rssAfter - rssBefore) / Double(established)
                : 0,
            rps: extra.rps,
            ingestP50Us: extra.ingestP50Us,
            ingestP99Us: extra.ingestP99Us,
            handshakeP50Us: extra.handshakeP50Us,
            handshakeP99Us: extra.handshakeP99Us,
            firstByteP50Us: extra.firstByteP50Us,
            firstByteP99Us: extra.firstByteP99Us,
            lossPct: extra.lossPct,
            notes: notes
        )
    }
}

enum ProcessMetrics {
    static func rssBytes() -> UInt64 {
        #if os(Linux)
        linuxRssBytes()
        #else
        darwinRssBytes()
        #endif
    }

    static func footprintBytes() -> UInt64 {
        #if os(Linux)
        linuxRssBytes()
        #else
        darwinFootprintBytes()
        #endif
    }

    static func cpuSeconds() -> (user: Double, system: Double) {
        var usage = rusage()
        #if os(Linux)
        _ = getrusage(0, &usage) // RUSAGE_SELF
        #else
        getrusage(RUSAGE_SELF, &usage)
        #endif
        func seconds(_ tv: timeval) -> Double {
            Double(tv.tv_sec) + Double(tv.tv_usec) / 1_000_000
        }
        return (seconds(usage.ru_utime), seconds(usage.ru_stime))
    }

    #if os(Linux)
    private static func linuxRssBytes() -> UInt64 {
        guard let text = try? String(contentsOfFile: "/proc/self/statm", encoding: .utf8) else {
            return 0
        }
        let parts = text.split(whereSeparator: { $0 == " " || $0 == "\n" })
        guard parts.count >= 2, let pages = UInt64(parts[1]) else { return 0 }
        let page = UInt64(sysconf(Int32(_SC_PAGESIZE)))
        return pages &* page
    }
    #else
    private static func darwinRssBytes() -> UInt64 {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(
            MemoryLayout<mach_task_basic_info>.stride / MemoryLayout<natural_t>.stride
        )
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }
        guard kr == KERN_SUCCESS else { return 0 }
        return UInt64(info.resident_size)
    }

    private static func darwinFootprintBytes() -> UInt64 {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<task_vm_info_data_t>.stride / MemoryLayout<natural_t>.stride
        )
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        guard kr == KERN_SUCCESS else { return 0 }
        return UInt64(info.phys_footprint)
    }
    #endif
}

func durationSeconds(_ duration: Duration) -> Double {
    let c = duration.components
    return Double(c.seconds) + Double(c.attoseconds) / 1e18
}

func durationMicroseconds(_ duration: Duration) -> Double {
    durationSeconds(duration) * 1_000_000
}

func percentile(_ values: [Double], _ p: Double) -> Double {
    guard !values.isEmpty else { return 0 }
    let sorted = values.sorted()
    let idx = min(sorted.count - 1, max(0, Int((Double(sorted.count - 1) * p).rounded())))
    return sorted[idx]
}

func percentilePair(_ values: [Double]) -> (p50: Double, p99: Double) {
    (percentile(values, 0.50), percentile(values, 0.99))
}

struct SampleBuf: Sendable {
    var values: [Double] = []
    let cap: Int

    init(cap: Int = 8_192) {
        self.cap = cap
        values.reserveCapacity(min(cap, 1_024))
    }

    mutating func add(_ v: Double) {
        if values.count < cap {
            values.append(v)
        }
    }

    func pair() -> (p50: Double, p99: Double) {
        percentilePair(values)
    }
}

func formatBytes(_ n: UInt64) -> String {
    if n >= 1 << 30 { return String(format: "%.2f GiB", Double(n) / Double(1 << 30)) }
    if n >= 1 << 20 { return String(format: "%.2f MiB", Double(n) / Double(1 << 20)) }
    if n >= 1 << 10 { return String(format: "%.1f KiB", Double(n) / Double(1 << 10)) }
    return "\(n) B"
}

func printHuman(_ results: [BenchResult]) {
    print()
    print(
        "scenario".padding(toLength: 14, withPad: " ", startingAt: 0)
            + "pps".padding(toLength: 14, withPad: " ", startingAt: 0)
            + "L3 Gbps".padding(toLength: 12, withPad: " ", startingAt: 0)
            + "app Gbps".padding(toLength: 12, withPad: " ", startingAt: 0)
            + "CPU cores".padding(toLength: 12, withPad: " ", startingAt: 0)
            + "RSS Δ".padding(toLength: 12, withPad: " ", startingAt: 0)
            + "B/conn"
    )
    print(String(repeating: "-", count: 90))
    for r in results {
        let row = [
            r.scenario.padding(toLength: 14, withPad: " ", startingAt: 0),
            String(format: "%.0f", r.pps).padding(toLength: 14, withPad: " ", startingAt: 0),
            String(format: "%.3f", r.gbps).padding(toLength: 12, withPad: " ", startingAt: 0),
            String(format: "%.3f", r.appGbps).padding(toLength: 12, withPad: " ", startingAt: 0),
            String(format: "%.2f", r.cpuCores).padding(toLength: 12, withPad: " ", startingAt: 0),
            formatBytes(r.rssDeltaBytes).padding(toLength: 12, withPad: " ", startingAt: 0),
            String(format: "%.0f", r.bytesPerConnection),
        ].joined()
        print(row)
        if r.rps > 0 || r.ingestP99Us > 0 || r.handshakeP99Us > 0 || r.firstByteP99Us > 0 {
            var extra: [String] = []
            if r.rps > 0 { extra.append(String(format: "rps=%.0f", r.rps)) }
            if r.handshakeP99Us > 0 {
                extra.append(String(format: "hs p50/p99=%.0f/%.0fµs", r.handshakeP50Us, r.handshakeP99Us))
            }
            if r.ingestP99Us > 0 {
                extra.append(String(format: "ingest p50/p99=%.0f/%.0fµs", r.ingestP50Us, r.ingestP99Us))
            }
            if r.firstByteP99Us > 0 {
                extra.append(String(format: "1st-byte p50/p99=%.0f/%.0fµs", r.firstByteP50Us, r.firstByteP99Us))
            }
            print("  \(extra.joined(separator: "  "))")
        }
        if !r.notes.isEmpty {
            print("  note: \(r.notes)")
        }
    }
    print()
}

func encodeJSON(_ results: [BenchResult]) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    return try encoder.encode(results)
}
