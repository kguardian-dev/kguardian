# Variables
CLANG_FLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86
RUST_TARGET := release
BPF_OBJECT := syscall.o
C_SOURCE := syscall.bpf.c
RUST_SOURCE := src/main.rs
RUST_BINARY := target/$(RUST_TARGET)/example_bpf_loader

# Default target
all: $(BPF_OBJECT) $(RUST_BINARY)

# Compile the eBPF program
$(BPF_OBJECT): $(C_SOURCE)
	clang $(CLANG_FLAGS) -c $(C_SOURCE) -o $(BPF_OBJECT)

# Compile the Rust userspace program
$(RUST_BINARY): $(RUST_SOURCE)
	cargo build --release

# Clean build artifacts
clean:
	cargo clean
	rm -f $(BPF_OBJECT)

.PHONY: all clean
