#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import Foundation
import SwiftTCP

@main
enum SwiftTCPBench {
    static let usage = """
    Usage: SwiftTCPBench [options]
      --scenario NAME     tcp-rx | tcp-tx | tcp-duplex | tcp-active | tcp-rps |
                          tcp-latency | tcp-loss | tcp-rx6 | tcp-scale | tcp-hold |
                          tcp-rx-small | tcp-cps | icmp-echo | all
      --duration SEC      timed window (default 5)
      --warmup SEC        warmup before measure (default 1; used by tcp-rx)
      --connections N     parallel flows for rx/tx (default 8)
      --payload BYTES     TCP payload (default 1460)
      --batch N           packets per ingestBatch (default 64)
      --loops N           TCPEventLoop count (default ncpu)
      --window BYTES      receive window (default 65536)
      --hold-conns N      idle connections for tcp-hold (default 4096)
      --active-conns N    live flows for tcp-active (default 256)
      --rps-bytes N       payload per short connection (default 8192)
      --loss PCT          drop percent for tcp-loss (default 2)
      --algorithm cubic|bbr
      --json              JSON to stdout (array of results)
      --output PATH       write JSON file
      --stack NAME        value of JSON "stack" field (default swifttcp)
    """

    static func writeErr(_ text: String) {
        FileHandle.standardError.write(Data(text.utf8))
    }

    static func main() async {
        do {
            let config = try parseArgs(Array(CommandLine.arguments.dropFirst()))
            let names = config.scenario == "all" ? allScenarios : [config.scenario]
            print(
                "SwiftTCP bench  loops=\(config.loops)  window=\(config.window)  "
                    + "conns=\(config.connections)  payload=\(config.payload)  "
                    + "batch=\(config.batch)  duration=\(durationSeconds(config.duration))s"
            )

            var results: [BenchResult] = []
            for name in names {
                writeErr("running \(name)...\n")
                let result = try await runScenario(name, config: config)
                results.append(result)
                if !config.json {
                    print(
                        "  \(result.scenario)  \(String(format: "%.0f", result.pps)) pps  "
                            + "\(String(format: "%.3f", result.gbps)) Gbps  "
                            + "CPU \(String(format: "%.2f", result.cpuCores)) cores  "
                            + "RSS Δ \(formatBytes(result.rssDeltaBytes))"
                    )
                }
            }

            if config.json {
                let data = try encodeJSON(results)
                if let path = config.output {
                    try data.write(to: URL(fileURLWithPath: path))
                } else {
                    FileHandle.standardOutput.write(data)
                    FileHandle.standardOutput.write(Data("\n".utf8))
                }
            } else {
                printHuman(results)
                if let path = config.output {
                    try encodeJSON(results).write(to: URL(fileURLWithPath: path))
                    print("wrote \(path)")
                }
            }
        } catch {
            writeErr("SwiftTCPBench: \(error)\n")
            writeErr(usage)
            writeErr("\n")
            exit(1)
        }
    }

    static func parseArgs(_ args: [String]) throws -> BenchConfig {
        var config = BenchConfig()
        var i = 0
        func takeValue(_ name: String) throws -> String {
            i += 1
            guard i < args.count else { throw BenchError.unknownScenario("missing value for \(name)") }
            return args[i]
        }
        while i < args.count {
            let arg = args[i]
            switch arg {
            case "--scenario": config.scenario = try takeValue(arg)
            case "--duration":
                let s = Double(try takeValue(arg)) ?? 5
                config.duration = .seconds(s)
            case "--warmup":
                let s = Double(try takeValue(arg)) ?? 1
                config.warmup = .seconds(s)
            case "--connections": config.connections = Int(try takeValue(arg)) ?? 8
            case "--payload": config.payload = Int(try takeValue(arg)) ?? 1460
            case "--batch": config.batch = Int(try takeValue(arg)) ?? 64
            case "--loops": config.loops = max(1, Int(try takeValue(arg)) ?? 1)
            case "--window": config.window = Int(try takeValue(arg)) ?? 65536
            case "--hold-conns": config.holdConnections = Int(try takeValue(arg)) ?? 4096
            case "--active-conns": config.activeConnections = Int(try takeValue(arg)) ?? 256
            case "--rps-bytes": config.rpsBytes = Int(try takeValue(arg)) ?? 8_192
            case "--loss": config.lossPct = Double(try takeValue(arg)) ?? 2
            case "--algorithm":
                switch try takeValue(arg) {
                case "bbr": config.algorithm = .bbr
                default: config.algorithm = .cubic
                }
            case "--json": config.json = true
            case "--output": config.output = try takeValue(arg)
            case "--stack": config.stackName = try takeValue(arg)
            case "-h", "--help":
                print(usage)
                exit(0)
            default:
                throw BenchError.unknownScenario("unknown flag \(arg)")
            }
            i += 1
        }
        return config
    }
}
