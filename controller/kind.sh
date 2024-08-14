#!/bin/bash
set -eou pipefail

# cargo install bpf-linker

cargo install cross --git https://github.com/cross-rs/cross

# generate bindings(task_struct)
# cargo xtask codegen 

# build ebpf byte code

export CROSS_CONTAINER_ENGINE_NO_BUILDKIT=1

cross build --target x86_64-unknown-linux-gnu --release

mkdir -p localbin

cp ./target/x86_64-unknown-linux-gnu/release/rust-libbpf ./localbin/

DOCKER_BUILDKIT=1 docker build . -f Dockerfile -t maheshrayas/ebpf-libbpf-syscalls:v0.1.62

#docker push maheshrayas/ebpf-libbpf-syscalls:v0.1.48

kind load docker-image maheshrayas/ebpf-libbpf-syscalls:v0.1.62

kubectl apply -f kubernetes.yaml
