# A Rust binary built with cargo-auditable (its dependency list embedded in
# the binary), on distroless/cc.
FROM rust:1-slim AS build
RUN cargo install cargo-auditable --locked
WORKDIR /src
RUN cargo new --bin hello \
 && cd hello \
 && echo 'itoa = "1"' >> Cargo.toml \
 && printf 'fn main() { let mut b = itoa::Buffer::new(); println!("{}", b.format(42)); }\n' > src/main.rs \
 && cargo auditable build --release

FROM gcr.io/distroless/cc-debian12
COPY --from=build /src/hello/target/release/hello /usr/local/bin/hello
ENTRYPOINT ["/usr/local/bin/hello"]
