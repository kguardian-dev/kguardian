# renovate: datasource=docker depName=debian
ARG DEBIAN_VERSION="13.7"

FROM --platform=$BUILDPLATFORM ubuntu:26.04 AS builder

# Set the working directory to /artifacts
WORKDIR /artifacts

# Create the subdirectories for amd64 and arm64 in a single RUN command
RUN mkdir -p linux/amd64 linux/arm64

COPY linux/amd64/kguardian linux/amd64/
COPY linux/arm64/kguardian linux/arm64/

FROM debian:${DEBIAN_VERSION}-slim

ARG TARGETPLATFORM

ENV DEBIAN_FRONTEND=noninteractive

# RUN rm /var/lib/dpkg/info/libc-bin.*
# RUN apt-get clean && apt-get update &&  apt-get install libc-bin -y
# libelf1t64, not libelf-dev: the binary is prebuilt and its eBPF objects
# are compiled at build time and embedded, so at runtime it only needs
# libelf.so.1 (libbpf). libelf-dev pulled in libc6-dev and linux-libc-dev,
# which nothing here uses.
RUN apt-get update \
    && apt-get install -y --no-install-recommends util-linux iproute2 libelf1t64 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder --chown=root:root --chmod=0755 /artifacts/$TARGETPLATFORM/kguardian /usr/local/bin

ENTRYPOINT ["/usr/local/bin/kguardian"]
