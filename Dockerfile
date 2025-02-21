FROM golang:1.23 as build

COPY . /usr


WORKDIR /usr
RUN apt update -y; apt install -y build-essential clang libbpf-dev bpftool linux-headers-generic gcc-multilib docker.io sudo
RUN  ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
WORKDIR /build
ADD . .
RUN make build
ENTRYPOINT ["./test.sh"]
