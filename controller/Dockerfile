ARG DEBIAN_VERSION="11.7"

FROM --platform=$BUILDPLATFORM ubuntu:24.04 as builder

# Set the working directory to /artifacts
WORKDIR /artifacts

# Create the subdirectories for amd64 and arm64 in a single RUN command
RUN mkdir -p linux/amd64 linux/arm64

COPY linux/amd64/kube-guardian linux/amd64/
COPY linux/arm64/kube-guardian linux/arm64/

FROM debian:${DEBIAN_VERSION}-slim

ARG TARGETPLATFORM

RUN apt-get update && apt-get install -y libc-bin util-linux iproute2 libelf-dev

COPY --from=builder --chown=root:root --chmod=0755 /artifacts/$TARGETPLATFORM/kube-guardian /usr/local/bin

ENTRYPOINT ["/usr/local/bin/kube-guardian"]
