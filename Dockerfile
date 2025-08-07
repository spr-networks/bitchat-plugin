FROM rust:1.88-slim-trixie AS builder

RUN apt-get update && \
    apt-get install -y pkg-config libdbus-1-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy only Cargo.toml and Cargo.lock first for dependency caching
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to satisfy cargo build for dependency compilation
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies only (this layer will be cached unless Cargo.toml changes)
RUN cargo build --release

# Copy the actual source code
COPY src/ ./src/

# Build the actual application (only this layer rebuilds when code changes)
ARG GIT_HASH
ENV GIT_HASH=${GIT_HASH:-unknown}
# Touch main.rs to ensure rebuild and explicitly build the binary
RUN touch src/main.rs && \
    cargo build --release --bin bitchat-rust && \
    ls -la target/release/bitchat-rust

# Runtime stage
FROM debian:trixie-slim

# Install runtime dependencies for Bluetooth support
RUN apt-get update && \
    apt-get install -y libdbus-1-3 ca-certificates tmux && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/bitchat-rust /app/

# Set environment variables for TUI
ENV TERM=xterm-256color
ENV RUST_LOG=warn
ENV RUST_BACKTRACE=0
ENV BLUETOOTHD_EXPERIMENTAL=0
ENV LANG="en_US.UTF-8"

# Run the TUI application under tmux
CMD ["tmux", "new-session",  "-s", "bitchat", "./bitchat-rust"]
