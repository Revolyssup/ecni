build-bpf:
	clang -O2 -target bpf -c bpf_program.c -o bpf_program.o

build:
	go build -o ./bin/ecni ./cmd/
