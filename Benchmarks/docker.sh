#!/usr/bin/env bash
# Run the cross-stack bench inside Docker. Host only needs Docker.
#
#   ./Benchmarks/docker.sh
#   DURATION=3 SCENARIOS="tcp-rx icmp-echo" ./Benchmarks/docker.sh
#
# Do not pass --cpus: that caps the VM/cgroup and understates pps/Gbps.
# On Docker Desktop, give the Linux VM all cores and ≥8 GiB RAM (tcp-hold).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${IMAGE:-swifttcp-bench}"
SWIFT_IMAGE="${SWIFT_IMAGE:-swift:6.3}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found" >&2
  exit 1
fi

echo "==> building toolchain image (${IMAGE}, ${SWIFT_IMAGE})"
docker build \
  --build-arg "SWIFT_IMAGE=${SWIFT_IMAGE}" \
  -t "$IMAGE" \
  -f "$ROOT/Benchmarks/Dockerfile" \
  "$ROOT/Benchmarks"

mkdir -p "$ROOT/Benchmarks/results"

docker_args=(--rm -i --init)
if [[ -t 1 ]]; then
  docker_args+=(-t)
fi

# Forward the same knobs run.sh understands.
env_args=()
for key in DURATION WARMUP CONNECTIONS PAYLOAD BATCH WINDOW HOLD ACTIVE RPS_BYTES LOSS LOOPS SCENARIOS RESULTS; do
  if [[ -n "${!key-}" ]]; then
    env_args+=(-e "$key")
  fi
done

echo "==> running benches (bind-mount ${ROOT})"
docker run "${docker_args[@]}" \
  -v "$ROOT:/src" \
  -w /src \
  "${env_args[@]+"${env_args[@]}"}" \
  -e RESULTS=/src/Benchmarks/results \
  "$IMAGE"
