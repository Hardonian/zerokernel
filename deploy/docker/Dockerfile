# Build stage
FROM rust:1.80-bullseye AS builder

WORKDIR /build

# Install BPF target dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libelf-dev \
    pkg-config \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Build release host binaries
RUN cargo build --release --bin zerokernel

# Runtime stage
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libelf1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/zerokernel /usr/local/bin/zerokernel

RUN mkdir -p /var/log/zerokernel/receipts

EXPOSE 9100

ENTRYPOINT ["/usr/local/bin/zerokernel"]
CMD ["monitor", "--window-size", "4096", "--max-windows", "0", "--metrics-port", "9100", "--output-dir", "/var/log/zerokernel/receipts"]

