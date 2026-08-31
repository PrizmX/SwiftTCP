# Toolchain image only: Swift + Go + Rust + Python.
# Project is bind-mounted at /src so code changes don't require a rebuild.
#
#   ./Benchmarks/docker.sh
#
# Override the Swift tag if 6.3 isn't on the machine's registry:
#   SWIFT_IMAGE=swift:6.2 ./Benchmarks/docker.sh

ARG SWIFT_IMAGE=swift:6.3
FROM ${SWIFT_IMAGE}

ARG GO_VERSION=1.26.3
ARG RUST_VERSION=1.84.1

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl python3 build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN arch="$(dpkg --print-architecture)" \
    && curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" \
        | tar -C /usr/local -xz

ENV PATH="/usr/local/go/bin:/root/.cargo/bin:${PATH}" \
    GOPROXY="https://proxy.golang.org,direct" \
    CARGO_TERM_COLOR="never" \
    SWIFT_DETERMINISTIC_HASHING="1"

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain "${RUST_VERSION}" --profile minimal

WORKDIR /src
ENTRYPOINT ["./Benchmarks/run.sh"]
