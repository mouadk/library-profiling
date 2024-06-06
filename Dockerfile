ARG KERNEL_VERSION
ARG PYTHON_VERSION
FROM linuxkit/kernel:${KERNEL_VERSION} as kernel
FROM ubuntu:latest AS build

WORKDIR /
COPY --from=kernel /kernel-dev.tar .
RUN tar xf kernel-dev.tar

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /workspace

RUN echo "Installing prerequisites" && \
    apt-get update && apt-get install nano sudo build-essential libsqlite3-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev curl wget auditd vim tmux git binutils unzip gcc jq python3-pip python3-pandas systemtap-sdt-dev cmake zlib1g-dev -y

RUN echo "installing bpftrace" && \
  apt-get update && apt-get install -y bpfcc-tools bpftrace

WORKDIR /workspace

RUN echo "installing and compiling python with dtrace enabled" && \
    curl -o Python-${PYTHON_VERSION}.tgz https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz && tar -xzf Python-${PYTHON_VERSION}.tgz && \
    cd Python-${PYTHON_VERSION} && ./configure --with-dtrace --prefix=/usr/local/openssl --prefix=$(pwd) --with-ensurepip=install && make && make install && \
    rm -rf $WORKDIR/Python-${PYTHON_VERSION}.tgz
