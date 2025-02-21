CUR_DIR := $(shell pwd)
BPF_DIR := $(realpath $(CUR_DIR)/bpf)
generate:
	clang -g -O2 -I/usr/include/linux -c -target bpf -o $(BPF_DIR)/ebpf_prog.o $(BPF_DIR)/prog.c

build: generate
	# paths set according to debian
	CC=clang CGO_CFLAGS="-I /usr/include/bpf" CGO_LDFLAGS="-lelf -lz /usr/lib/x86_64-linux-gnu/libbpf.a" go build -o ./bin/ecni -ldflags="-w -extldflags "-static"" $(CUR_DIR)/cmd/


docker-run-host: docker-build
	docker run -it --rm -v /var/run/docker.sock:/var/run/docker.sock --pid=host --privileged=true --network=host --name=ecni revoly/ecni:latest

docker-build:
	docker build -t revoly/ecni:latest .
