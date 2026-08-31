# Userspace TCP stack benchmark

In-process IP injection. No TUN, no NIC, no kernel forwarding. The numbers are the **CPU-fed ceiling of the stack itself**: delivered pps, L3 Gbps, CPU, RSS, and a few latency percentiles.

SwiftTCP and gVisor run the same default scenarios, the same CLI knobs, and the same JSON schema. smoltcp runs only the scenarios it can match (single-threaded, IPv4, no duplex / rps / latency / loss / scale suite).

| Stack | Ingest path | Parallelism |
| --- | --- | --- |
| SwiftTCP | `SwiftStack.ingestBatch` | `TCPEventLoop` × ncpu (default). `tcp-scale` sweeps loops = 1/2/4/8 |
| gVisor netstack | `channel.Endpoint.InjectInbound` (serial) | `GOMAXPROCS` = `--loops`. Inject is **one thread**; extra procs only help `drainConn` |
| smoltcp | `Interface::poll` | One thread. Legacy scenarios only |

Headline comparison is `swifttcp` (ncpu loops) vs `gvisor` (`GOMAXPROCS` = ncpu). `tcp-scale` is a **within-stack** curve: `swifttcp-Nloop` vs `gvisor-Np` share the label N, not the same kind of parallelism.

## Shared parameters

`run.sh` / `docker.sh` pass the same flags to every binary.

| Knob | Default | Meaning |
| --- | --- | --- |
| Client → server | `10.0.0.1` → `10.0.0.2:80` | Only the source port changes per flow |
| IPv6 | `2001:db8::1` → `2001:db8::2` | `tcp-rx6` |
| MTU | 1500 | gVisor channel MTU is 1500 |
| MSS / default payload | 1460 | IPv6 payload capped at 1440 so 40+20+payload ≤ 1500 |
| Receive window | 64 KiB | `--window` |
| Batch | 64 segments / round | `--batch` |
| Duration / warmup | 5 s / 1 s | `--duration` / `--warmup` (wall-clock warmup on every scenario) |
| Flows (rx/tx/duplex) | 8 | `--connections` |
| Live flows | 256 | `tcp-active` `--active-conns` |
| Idle hold | 4096 | `tcp-hold` `--hold-conns` |
| Short-conn payload | 8 KiB | `tcp-rps` `--rps-bytes` |
| Loss | 2% | `tcp-loss` `--loss` |
| SYN options | MSS 1460, WScale 7, SACK permitted | Same on all stacks |
| RX checksum | Not verified | gVisor `CapabilityRXChecksumOffload`, smoltcp `Checksum::Tx`, Swift parse path does not check |

Generator cost (build packet + checksum + ingest) is inside the timed window.

## How a round works

**RX path** (`tcp-rx`, `tcp-rx-small`, `tcp-rx6`, `tcp-active`, `tcp-loss`, `tcp-scale`, and the timed window of `tcp-latency`):

1. Handshake C connections.
2. Each round builds `batch` PSH segments, round-robin across flows, sequence numbers increasing.
3. Ingest the batch.
4. The application must **drain** before the next round, so a 64 KiB window is not filled by “inject without read”:
   - Swift: `DiscardStreamHandler.onData` runs inside `ingestBatch`.
   - smoltcp: `recv()` after `poll()`.
   - gVisor: `drainConn` plus `waitDelivered` (wait until this round’s payload shows up in `Read`, or 100 ms).
5. `pps` / `gbps` are computed from **delivered** bytes (`delivered / payload` segments, L3 = header + payload), not from how many packets were injected. If delivered is 0, gVisor prints a warning and reports 0 rather than substituting TX counts.

`tcp-loss` is the same RX loop with two extras (Swift and gVisor only):

- SplitMix64, seed `0xC0FFEE42`, drop when `(next() % 10000) / 100 < lossPct`. Dropped segments are replayed at the front of the **next** batch (delayed, not deleted).
- Every 5th batch is reversed.
- gVisor does **not** `waitDelivered` here: in-order holes mean delivered lags injected on purpose, and waiting would hit the 100 ms cap every round.

**TX path** (`tcp-tx`):

Each round queues `batch` application sends (round-robin, one MSS each). The peer ACKs every data segment. `pps` / `gbps` / `appGbps` count **payload segments only** (pure ACKs are excluded).

**Duplex** is **not** the same job on every stack — see [What you can compare](#what-you-can-compare).

## Scenarios

Default `SCENARIOS` in `run.sh`:

`tcp-rx tcp-tx tcp-duplex tcp-active tcp-rps tcp-latency tcp-loss tcp-rx6 tcp-scale tcp-hold`

Legacy (opt-in): `tcp-rx-small`, `tcp-cps`, `icmp-echo`. smoltcp only runs `tcp-rx tcp-rx-small tcp-tx tcp-cps tcp-hold icmp-echo`.

| Scenario | What it stresses | Driver |
| --- | --- | --- |
| `tcp-rx` | Bulk receive | 8 established flows, 1460 B PSH, app discards. Also records ingest p50/p99. `run.sh` adds a Swift `--loops 1` extra |
| `tcp-tx` | Send path | `sendBatch` / `gonet.Write` / `send_slice` of `batch` segments + peer ACK |
| `tcp-duplex` | Both directions | Swift: one round = `sendBatch(batch)` + ACK those TX packets + inbound PSH. gVisor: RX like `tcp-rx` plus **concurrent** `gonet.Write` (gonet cannot serialize Read+Write on one thread without stalling drain). Reported pps/appGbps are **RX** |
| `tcp-active` | Many live flows | Same as `tcp-rx` with 256 connections |
| `tcp-rps` | Short connections | Handshake + 8 KiB + FIN, serial. `rps` = connections started / s |
| `tcp-latency` | Percentiles | 256 handshake samples, 64 first-byte samples, then a timed RX window for ingest p50/p99. Close with RST |
| `tcp-loss` | Loss + reorder / SACK | RX + 2% delayed replay + reverse every 5th batch |
| `tcp-rx6` | IPv6 receive | Same as `tcp-rx`, 60 B IPv6+TCP header, payload ≤ 1440 |
| `tcp-scale` | Parallelism curve | Swift `loops` and gVisor `GOMAXPROCS` = 1/2/4/8. Inject stays serial on gVisor |
| `tcp-hold` | Idle memory | 4096 ESTABLISHED, 200 ms settle, B/conn = RSS Δ / established. gVisor does not start a read goroutine per conn |
| `tcp-rx-small` | Small-packet pps | payload = 64. If `WINDOW` is unset, `run.sh` uses 8 MiB so gVisor per-segment buffer accounting is not the bottleneck |
| `tcp-cps` | Handshake churn | SYN + ACK + RST |
| `icmp-echo` | Stateless fast path | Reused echo-request template |

## Metrics

JSON matches `BenchResult`. `compare.py` merges `Benchmarks/results/*.json` into a table and `comparison.md`.

| Field | Definition |
| --- | --- |
| `pps` | `packetsIn / durationS`. RX: delivered segments. TX: payload TX segments |
| `gbps` | `bytesIn * 8 / durationS / 1e9` (L3: IP+TCP header + payload) |
| `appGbps` | `deliveredBytes * 8 / …`. TX uses the same byte count as L3 payload path (TX bytes) |
| `cpuCores` | `(cpuUserS + cpuSysS) / durationS` from `getrusage` |
| `rssDeltaBytes` | Current RSS after − before. Linux: `/proc/self/statm` resident pages. Decrease is recorded as 0 (no wrap) |
| `bytesPerConnection` | `rssDeltaBytes / established` when established > 0 |
| `rps` | Short connections started per second (`tcp-rps`) |
| `ingestP50Us` / `ingestP99Us` | Time to ingest one batch (Swift: `ingestBatch`; gVisor: inject + wait-for-delivery) |
| `handshakeP50Us` / `handshakeP99Us` | See caveats below |
| `firstByteP50Us` / `firstByteP99Us` | See caveats below |
| `footprint*` | Swift/Linux = RSS; gVisor = `HeapAlloc`; smoltcp = RSS. **Not** cross-stack comparable |
| `durationS` | Actual timed wall clock (compare.py prints `dur` so mixed-length runs are visible) |

First 8192 ingest/handshake/first-byte samples only (no reservoir).

## What you can compare

Use this table before quoting a ratio.

| Question | Comparable? | Why |
| --- | --- | --- |
| Same stack, same harness, before vs after a code change | **Yes** | Workload unchanged |
| `tcp-rx` / `tcp-rx6` / `tcp-active` pps, L3 Gbps, appGbps across Swift ↔ gVisor ↔ smoltcp | **Yes, as delivered ingest** | Same packets, same drain-before-next-batch rule, same delivered accounting. Thread models still differ |
| `tcp-tx` L3 Gbps / appGbps | **Yes** | Same `batch` sends + peer ACK; payload-only bytes |
| `tcp-tx` pps | **Use with Gbps** | gVisor may emit smaller segments, so pps can look higher while bits are lower |
| `tcp-loss` Swift ↔ gVisor | **Yes, as delivered RX under the same drop sequence** | Shared SplitMix64 |
| `tcp-hold` B/conn | **Yes, as idle RSS / conn** | Current RSS, no per-conn drain goroutine on gVisor. smoltcp includes pre-allocated socket buffers — that is real idle footprint, not a bug |
| `tcp-cps` / `icmp-echo` | **Roughly** | Same driver; still different runtimes |
| `tcp-scale` **within one stack** (1 vs 2 vs 4 vs 8) | **Yes** | Swift: EventLoop count. gVisor: `GOMAXPROCS` only |
| `swifttcp-Nloop` vs `gvisor-Np` | **No** | N is not the same mechanism. gVisor inject is always serial and often **peaks at 1p** |
| `tcp-duplex` Swift ↔ gVisor | **No** | Swift serializes TX+ACK+RX in one round. gVisor RX is `tcp-rx`-like; TX is a background `Write`. gVisor RX pps will sit near its `tcp-rx`, Swift duplex will sit below its `tcp-rx` |
| `tcp-rps` | **Directionally** | Both count connections started / s. TIME_WAIT / PCB recycling differ (gVisor RSS often climbs) |
| Handshake p50/p99 across stacks | **No** | Swift: SYN ingest through third ACK (Established). gVisor: SYN through SYN-ACK + third ACK inject |
| First-byte p50/p99 across stacks | **No** | Swift: `onData`. gVisor: poll `delivered` (async `drainConn`) |
| Ingest p50/p99 across stacks | **Weak** | Swift is `ingestBatch` hop time. gVisor includes wait-for-`Read` |
| smoltcp absolute pps vs the other two | **Only as a tight-loop ceiling** | No actor, no goroutine, one `poll` |
| Traffic-scenario RSS Δ / B/conn | **No** | Thread pools and buffer caches move around. Use `tcp-hold` |
| `footprint*` | **No** | Different allocators |
| Docker (macOS VM) vs host `swift run SwiftTCPBench` | **No** | Different machine |

UDP is not in this suite: SwiftTCP UDP is `NWConnection` forwarding, not a terminating stack.

## How to run

Host needs Docker (Swift, Go, and Rust are in the image):

```bash
./Benchmarks/docker.sh

DURATION=3 SCENARIOS="tcp-rx tcp-tx tcp-rps tcp-latency" ./Benchmarks/docker.sh
LOOPS=1 SCENARIOS="tcp-rx" ./Benchmarks/docker.sh
```

The image is toolchain-only. Source is bind-mounted at `/src`, so code changes do not require an image rebuild. First `go` / `cargo` fetch is slow.

On a machine that already has the toolchains: `./Benchmarks/run.sh`.

Env knobs forwarded by `docker.sh`: `DURATION WARMUP CONNECTIONS PAYLOAD BATCH WINDOW HOLD ACTIVE RPS_BYTES LOSS LOOPS SCENARIOS RESULTS`.

If `WINDOW` is unset, `tcp-rx-small` gets `--window 8388608`. An explicit `WINDOW` is honored for every scenario.

## Environment

Injection never hits the container veth, so there is no NAT/bridge bandwidth tax. Cost is CPU and scheduling.

| Setup | Effect |
| --- | --- |
| Linux host, no `--cpus` / `--memory` | Usually &lt;5%. Stacks in the same container stay fair |
| macOS Docker Desktop / OrbStack | Extra Linux VM. Absolute pps/Gbps often 10–40% lower or noisier. **Do not** compare to host `swift run SwiftTCPBench` |
| `--cpus N` on the container | Caps the quota and distorts pps/Gbps. `docker.sh` does not pass it |

The Docker binary is Linux SwiftTCP (`ingestBatch`), not the Darwin `NetworkExtension` TUN path. Product latency/throughput on macOS/iOS is a different measurement. This suite is **stack vs stack**.

Give the VM all CPUs and ≥8 GiB RAM (`tcp-hold` at 4096 connections is hundreds of MiB if rings are allocated).

gVisor is the `go` branch (`go.mod`). If the Swift tag is missing locally: `SWIFT_IMAGE=swift:6.2 ./Benchmarks/docker.sh`.
