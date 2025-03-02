FROM ubuntu:latest

RUN apt-get update && apt-get install -y \
		curl iproute2 inetutils-ping


