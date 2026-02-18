FROM debian:13-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends util-linux iproute2 libelf-dev && \
    rm -rf /var/lib/apt/lists/*

COPY kguardian /usr/local/bin/kguardian

ENTRYPOINT ["/usr/local/bin/kguardian"]
