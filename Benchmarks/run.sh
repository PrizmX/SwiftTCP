#!/usr/bin/env bash
# Cross-stack bench: SwiftTCP vs gVisor netstack vs smoltcp.
# Usage:
#   ./Benchmarks/run.sh
#   DURATION=2 SCENARIOS="tcp-rx tcp-tx" ./Benchmarks/run.sh
#   LOOPS=1 ./Benchmarks/run.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RESULTS="${RESULTS:-$ROOT/Benchmarks/results}"
BIN="$ROOT/Benchmarks/.bin"
DURATION="${DURATION:-5}"
WARMUP="${WARMUP:-1}"
CONNECTIONS="${CONNECTIONS:-8}"
PAYLOAD="${PAYLOAD:-1460}"
BATCH="${BATCH:-64}"
WINDOW_FROM_USER="${WINDOW-}"
WINDOW="${WINDOW:-65536}"
HOLD="${HOLD:-4096}"
ACTIVE="${ACTIVE:-256}"
RPS_BYTES="${RPS_BYTES:-8192}"
LOSS="${LOSS:-2}"
LOOPS="${LOOPS:-}"
# gVisor-focused comparison set. Legacy: tcp-rx-small tcp-cps icmp-echo
SCENARIOS="${SCENARIOS:-tcp-rx tcp-tx tcp-duplex tcp-active tcp-rps tcp-latency tcp-loss tcp-rx6 tcp-scale tcp-hold}"
SMOLTCP_SCENARIOS="tcp-rx tcp-rx-small tcp-tx tcp-cps tcp-hold icmp-echo"

mkdir -p "$RESULTS" "$BIN"
cd "$ROOT"

echo "==> building SwiftTCPBench (release)"
swift build -c release --product SwiftTCPBench
SWIFT_BIN="$(swift build -c release --show-bin-path)/SwiftTCPBench"

if command -v go >/dev/null 2>&1; then
  echo "==> building gVisor bench"
  (cd "$ROOT/Benchmarks/gvisor" && go mod tidy && go build -o "$BIN/gvisor-bench" .)
else
  echo "skip gVisor: go not found" >&2
fi

if command -v cargo >/dev/null 2>&1; then
  echo "==> building smoltcp bench"
  (cd "$ROOT/Benchmarks/smoltcp" && cargo build --release)
  cp "$ROOT/Benchmarks/smoltcp/target/release/smoltcp-bench" "$BIN/smoltcp-bench"
else
  echo "skip smoltcp: cargo not found" >&2
fi

run_stack() {
  local stack="$1"
  local bin="$2"
  local scenario="$3"
  shift 3
  local out="$RESULTS/${stack}-${scenario}.json"
  echo "--> $stack $scenario"
  # rx-small is a small-packet pps test. gVisor accounts receive-buffer memory
  # per segment (segSize + packet size, ~570 B/segment), so 64-256 B payloads
  # saturate the default 64 KiB buffer in a few rounds and its receiver silently
  # drops segments — deliveredBytes collapses to ~0. Give all three stacks the
  # same large window for this scenario so it measures packet-processing headroom
  # instead of buffer accounting; an explicitly user-set WINDOW is honored.
  local eff_window="$WINDOW"
  if [[ "$scenario" == "tcp-rx-small" && -z "$WINDOW_FROM_USER" ]]; then
    eff_window=8388608
  fi
  local cmd=("$bin" --scenario "$scenario"
    --duration "$DURATION" --warmup "$WARMUP" --connections "$CONNECTIONS"
    --payload "$PAYLOAD" --batch "$BATCH" --window "$eff_window"
    --hold-conns "$HOLD" --active-conns "$ACTIVE" --rps-bytes "$RPS_BYTES"
    --loss "$LOSS" --json --output "$out")
  cmd+=("$@")
  if command -v timeout >/dev/null 2>&1; then
    timeout --signal=TERM 180 "${cmd[@]}" || echo "warn: $stack $scenario exited $?" >&2
  else
    "${cmd[@]}"
  fi
}

in_list() {
  local needle="$1"
  local hay="$2"
  for x in $hay; do
    [[ "$x" == "$needle" ]] && return 0
  done
  return 1
}

for scenario in $SCENARIOS; do
  if [[ "$scenario" == "tcp-scale" ]]; then
    for L in 1 2 4 8; do
      run_stack "swifttcp-${L}loop" "$SWIFT_BIN" tcp-scale --loops "$L" --stack "swifttcp-${L}loop"
      if [[ -x "$BIN/gvisor-bench" ]]; then
        run_stack "gvisor-${L}p" "$BIN/gvisor-bench" tcp-scale --loops "$L" --stack "gvisor-${L}p"
      fi
    done
    continue
  fi

  swift_extra=()
  if [[ -n "$LOOPS" ]]; then
    swift_extra+=(--loops "$LOOPS" --stack "swifttcp-${LOOPS}loop")
  fi
  run_stack swifttcp "$SWIFT_BIN" "$scenario" "${swift_extra[@]+"${swift_extra[@]}"}"

  if [[ -z "$LOOPS" && "$scenario" == "tcp-rx" ]]; then
    run_stack swifttcp-1loop "$SWIFT_BIN" "$scenario" --loops 1 --stack swifttcp-1loop
  fi

  if [[ -x "$BIN/gvisor-bench" ]]; then
    run_stack gvisor "$BIN/gvisor-bench" "$scenario"
  fi
  if [[ -x "$BIN/smoltcp-bench" ]] && in_list "$scenario" "$SMOLTCP_SCENARIOS"; then
    run_stack smoltcp "$BIN/smoltcp-bench" "$scenario"
  fi
done

python3 "$ROOT/Benchmarks/compare.py" "$RESULTS"
