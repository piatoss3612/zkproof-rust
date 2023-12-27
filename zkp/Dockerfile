FROM rust:latest as builder

WORKDIR /app

COPY . .

RUN apt update && apt install -y protobuf-compiler

RUN cargo build --release --bin server --bin client

FROM debian:stable-slim

RUN apt update \
    && apt install -y libssl-dev ca-certificates \
    && apt clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/server /app/server

COPY --from=builder /app/target/release/client /app/client