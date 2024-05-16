FROM rust:latest  AS build

COPY Cargo.lock /app/

RUN cargo new /app/broker

COPY Cargo.toml /app/broker/

RUN apt update && apt-get install protobuf-compiler -y

WORKDIR /app/broker

COPY src /app/broker/src
COPY db  /app/broker/db

RUN --mount=type=cache,target=/usr/local/cargo/registry  cargo build --release

FROM debian:bookworm-slim AS app

RUN apt update && apt install libpq5 -y

COPY --from=build /app/broker/target/release/broker /broker

EXPOSE 9090

CMD ["/broker"]
