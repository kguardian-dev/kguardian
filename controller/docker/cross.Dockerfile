ARG ARCH

FROM ghcr.io/cross-rs/${ARCH}:edge

ARG DEBIAN_FRONTEND=noninteractive
ARG DPKG_ARCH

RUN dpkg --add-architecture ${DPKG_ARCH} && \
    apt-get update && \
    apt-get install -y software-properties-common wget apt-transport-https ca-certificates

RUN wget https://apt.llvm.org/llvm.sh

RUN chmod +x llvm.sh

RUN ./llvm.sh 16 all

RUN apt update && apt install -y libbpf0 libcli1.10 iproute2 protobuf-compiler libprotobuf-dev

RUN ln -s /usr/bin/llvm-config-16 /usr/local/bin/llvm-config

RUN llvm-config --version
