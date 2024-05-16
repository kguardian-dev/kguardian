ARG DEBIAN_VERSION="11.7"

FROM --platform=$BUILDPLATFORM ubuntu:24.04 as builder

RUN mkdir -p \
    /artifacts/linux/amd64 \
    /artifacts/linux/arm64

COPY linux/amd64/kube-guardian /artifacts/linux/amd64
COPY linux/arm64/kube-guardian /artifacts/linux/arm64

FROM debian:${DEBIAN_VERSION}-slim

ARG TARGETPLATFORM

COPY --from=builder /artifacts/$TARGETPLATFORM/kube-guardian /usr/local/bin

RUN apt update
RUN apt-get install -y util-linux iproute2
RUN chmod +x /usr/local/bin/kube-guardian

ENTRYPOINT ["/usr/local/bin/kube-guardian"]
