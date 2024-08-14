FROM ghcr.io/cross-rs/x86_64-unknown-linux-gnu:main

RUN apt-get update -y && apt-get install --assume-yes zlib1g-dev \
libelf-dev\
 clang\
  libc6\
   build-essential\
    libbpf-dev gcc-multilib\
     protobuf-compiler\
      libprotobuf-dev