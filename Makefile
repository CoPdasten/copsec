# ==============================================================================
#  CoPSeC Pro - Distributed Enterprise eBPF/XDP Intrusion Prevention System
#  Makefile
# ==============================================================================

CC := clang
GO ?= go
CLANG_BPF_FLAGS ?= -target bpf -O2 -g -Wall

BPF_DIR := bpf
BIN_DIR := bin
PROTO_DIR := proto

BPF_SOURCES := $(BPF_DIR)/copsec_xdp.bpf.c $(BPF_DIR)/copsec_kprobe.bpf.c $(BPF_DIR)/copsec_ringbuf.bpf.c
BPF_OBJECTS := $(BPF_DIR)/copsec_xdp.bpf.o $(BPF_DIR)/copsec_kprobe.bpf.o $(BPF_DIR)/copsec_ringbuf.bpf.o

.PHONY: all bpf collector controller test proto clean help

all: bpf collector controller

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

bpf: $(BPF_OBJECTS)

$(BPF_DIR)/copsec_xdp.bpf.o: $(BPF_DIR)/copsec_xdp.bpf.c $(BPF_DIR)/xdp_copsec_filter.c
	@echo "==> Compiling eBPF/XDP telemetry ring buffer target..."
	$(CC) $(CLANG_BPF_FLAGS) -c $< -o $@

$(BPF_DIR)/copsec_kprobe.bpf.o: $(BPF_DIR)/copsec_kprobe.bpf.c
	@echo "==> Compiling eBPF kprobe telemetry target..."
	$(CC) $(CLANG_BPF_FLAGS) -c $< -o $@

$(BPF_DIR)/copsec_ringbuf.bpf.o: $(BPF_DIR)/copsec_ringbuf.bpf.c
	@echo "==> Compiling eBPF ring buffer event target..."
	$(CC) $(CLANG_BPF_FLAGS) -c $< -o $@

proto:
	@echo "==> Generating Protobuf / gRPC bindings..."
	@mkdir -p collector/proto/management
	export PATH=$$PATH:$$(go env GOPATH)/bin && \
	protoc --proto_path=$(PROTO_DIR) \
		--go_out=collector/proto/management --go_opt=paths=source_relative \
		--go-grpc_out=collector/proto/management --go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/management.proto

collector: $(BIN_DIR)
	@echo "==> Building copsec-collector binary into $(BIN_DIR)/copsec-collector..."
	(cd collector && $(GO) build -ldflags="-s -w" -o ../$(BIN_DIR)/copsec-collector .)

controller: $(BIN_DIR)
	@echo "==> Building copsec-controller binary into $(BIN_DIR)/copsec-controller..."
	(cd controller && $(GO) build -ldflags="-s -w" -o ../$(BIN_DIR)/copsec-controller .)

test:
	@echo "==> Executing test suites with -race across all packages..."
	(cd collector && $(GO) test -race ./...)
	(cd controller && $(GO) test -race ./...)

clean:
	@echo "==> Cleaning build artifacts..."
	rm -rf $(BIN_DIR) $(BPF_DIR)/*.o
