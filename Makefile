CONTROLLER_IMAGE_NAME = ghcr.io/xentra-ai/images/guardian-controller
BROKER_IMAGE_NAME = ghcr.io/xentra-ai/images/guardian-broker
IMAGE_VERSION = local

# Define the target architecture (e.g., amd-> x86_64-unknown-linux-gnu, arm -> aarch64-unknown-linux-gnu)
TARGET = x86_64-unknown-linux-gnu

all: kind build controller broker install

kind:
	kind delete cluster && kind create cluster

build:
	cd controller && cargo xtask build-ebpf --release
	cd controller && cross build --release --target $(TARGET)

controller:
	mkdir -p localbin
	cp controller/target/${TARGET}/release/kube-guardian localbin
	docker build -t $(CONTROLLER_IMAGE_NAME):$(IMAGE_VERSION) . -f controller/docker/local.Dockerfile
	kind load docker-image $(CONTROLLER_IMAGE_NAME):$(IMAGE_VERSION)
	rm -rf localbin

broker:
	docker build -t $(BROKER_IMAGE_NAME):$(IMAGE_VERSION) broker -f broker/broker.Dockerfile
		kind load docker-image $(BROKER_IMAGE_NAME):$(IMAGE_VERSION)

install:
	kubectl create ns kube-guardian
	kubectl apply -f yaml/db.yaml
	kubectl apply -f yaml/install.yaml

clean:
	cargo clean


.PHONY: all kind build controller broker install clean
