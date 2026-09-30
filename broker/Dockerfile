# Builder MUST target the same Debian release as the runtime stage below:
# the binary links against the builder's glibc, and a newer builder glibc
# than the runtime's makes the container fail at exec ("GLIBC_X.YY not
# found"). rust:latest drifted to a newer Debian base and broke broker
# v1.12.0 exactly this way (built needing glibc 2.38, ran on bookworm's
# 2.36). Paired with the debian:13-slim (trixie) runtime below — keep both
# on the same release when either moves.
FROM rust:1-trixie AS build

RUN apt update && apt-get install protobuf-compiler -y

WORKDIR /app/broker

# Compile dependencies against the real manifest but placeholder sources, so
# this layer is keyed on Cargo.toml + Cargo.lock alone and survives every
# change that does not touch them.
#
# Previously src/ was copied in before the only cargo build, which put the
# sources and the dependency compile in the same layer: every source edit
# recompiled all ~300 dependency crates, and the buildx cache exported by CI
# had no dependency layer to restore. Cargo.lock also landed in /app/ rather
# than the crate root, so the pinned versions were never actually used.
#
# Both targets declared in Cargo.toml need a file to exist, or this build
# fails before it reaches the dependencies.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && : > src/lib.rs
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo build --release

# Discard the placeholders' own artifacts and fingerprints so the real sources
# are compiled rather than judged up to date. Dependencies stay in target/.
#
# Both crate names need both spellings: the library is emitted as
# deps/libapi-<hash>.rlib, so a deps/api-* glob alone leaves it in place and
# the real bin then compiles against the empty placeholder lib, failing with
# "cannot find <module> in `api`".
RUN rm -rf src \
    target/release/broker \
    target/release/deps/broker* \
    target/release/deps/api* \
    target/release/deps/libapi* \
    target/release/.fingerprint/broker-* \
    target/release/.fingerprint/api-*

COPY src ./src
COPY db  ./db

RUN --mount=type=cache,target=/usr/local/cargo/registry cargo build --release

FROM debian:13.7-slim AS app

# ca-certificates: root store for the outbound HTTPS version check-in.
RUN apt update && apt install -y libpq5 ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/broker/target/release/broker /broker

# Two glibc malloc arenas instead of up to 8 per core. Every read runs on
# a tokio blocking thread (web::block; the pool grows to hundreds), each
# thread got its own arena, and each arena kept its high-water mark: ten
# one-at-a-time SBOM exports left 736 MiB resident, 717 MiB of it in 38
# arenas of ~64 MiB. With 2 arenas and the cheaper export (#1723) the same
# run stays at 68 MiB, and 18 concurrent reads of every kind at 92 MiB
# (5 256 MiB before); #1723 has the harness. A pod can still override it.
ENV MALLOC_ARENA_MAX=2

EXPOSE 9090

CMD ["/broker"]
