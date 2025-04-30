# Use the Rust official image
FROM rust:1.75 as builder

# Set the working directory
WORKDIR /app

# Copy the Cargo files first (for efficient caching)
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release

# Copy the actual source code
COPY . .

# Build the Rust application
RUN cargo build --release

# Use a minimal runtime environment
FROM debian:bullseye-slim

WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/target/release/password_manager /app/password_manager

# Set the command to run the application
CMD ["/app/password_manager"]
