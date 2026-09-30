# A Rust binary built with cargo-auditable (its dependency list embedded in
# the binary), on distroless/cc.
FROM rust:1-slim AS build
RUN cargo install cargo-auditable --locked
WORKDIR /src
RUN cargo new --bin hello
WORKDIR /src/hello
RUN echo 'itoa = "1"' >> Cargo.toml \
 && printf 'fn main() { let mut b = itoa::Buffer::new(); println!("{}", b.format(42)); }\n' > src/main.rs \
 && cargo auditable build --release

# The nonroot tag carries the same packages as latest (only the default
# user differs), so the differential test sees the same image content.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/hello/target/release/hello /usr/local/bin/hello
# A test fixture that is only ever unpacked, never run: no health check.
USER 65532:65532
HEALTHCHECK NONE
ENTRYPOINT ["/usr/local/bin/hello"]
