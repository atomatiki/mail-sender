# Builder stage
FROM rust:1.84-slim AS builder

# Install build dependencies
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy Cargo.toml and Cargo.lock files
COPY Cargo.toml Cargo.lock* ./

# Create a dummy main.rs for dependency caching
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs

# Build dependencies only - this is the caching Docker layer
RUN cargo build --release

# Remove the dummy source
RUN rm src/main.rs

# Now copy the real source code
COPY src src/

# Build the real application
RUN cargo build --release && \
    strip /app/target/release/mail-sender

# Runtime stage using distroless
FROM gcr.io/distroless/cc-debian12

# Copy SSL certificates for HTTPS support
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/mail-sender .

# Set environment variables
ENV RUST_LOG=info
ENV PORT=4500

# Expose port - match the port specified in the ENV
EXPOSE 4500

ENTRYPOINT ["./mail-sender"]