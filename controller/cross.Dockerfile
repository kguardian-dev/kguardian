ARG ARCH

FROM ghcr.io/cross-rs/${ARCH}:edge

ARG DEBIAN_FRONTEND=noninteractive
ARG DPKG_ARCH

RUN dpkg --add-architecture ${DPKG_ARCH} && \
    apt-get update && \
    apt-get install -y software-properties-common wget apt-transport-https ca-certificates

RUN apt-get update -y && apt-get install --assume-yes zlib1g-dev \
libelf-dev\
 clang\
  libc6\
   build-essential\
    libbpf-dev gcc-multilib\
     protobuf-compiler\
      libprotobuf-dev\ 
      pkgconf\
       rustfmt 
