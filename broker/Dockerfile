# Builder MUST target the same Debian release as the runtime stage below:
# the binary links against the builder's glibc, and a newer builder glibc
# than the runtime's makes the container fail at exec ("GLIBC_X.YY not
# found"). rust:latest drifted to a newer Debian base and broke broker
# v1.12.0 exactly this way (built needing glibc 2.38, ran on bookworm's
# 2.36). If the runtime moves to debian:13-slim, move this to rust:1-trixie
# in the same commit.
FROM rust:1-bookworm AS build

COPY Cargo.lock /app/

RUN cargo new /app/broker

COPY Cargo.toml /app/broker/

RUN apt update && apt-get install protobuf-compiler -y

WORKDIR /app/broker

COPY src /app/broker/src
COPY db  /app/broker/db

RUN --mount=type=cache,target=/usr/local/cargo/registry  cargo build --release

FROM debian:13.6-slim AS app

# ca-certificates: root store for the outbound HTTPS version check-in.
RUN apt update && apt install -y libpq5 ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/broker/target/release/broker /broker

EXPOSE 9090

CMD ["/broker"]
