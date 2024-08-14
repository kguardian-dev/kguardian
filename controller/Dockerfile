ARG DEBIAN_VERSION="11.7"

FROM --platform=$BUILDPLATFORM ubuntu:24.04 as builder

RUN mkdir -p \
    /artifacts/localbin

COPY localbin/rust-libbpf /artifacts/localbin

FROM debian:${DEBIAN_VERSION}-slim

RUN apt update -y && apt install libelf-dev -y

ARG TARGETPLATFORM

COPY --from=builder /artifacts/localbin/rust-libbpf /usr/local/bin

RUN chmod +x /usr/local/bin/rust-libbpf

RUN LD_LIBRARY_PATH=/usr/local/lib

ENTRYPOINT ["/usr/local/bin/rust-libbpf"]
