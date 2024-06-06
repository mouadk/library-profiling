#!/bin/bash

echo "Building docker image for testing eBPF with python...";

# KERNEL_VERSION=`docker run --rm -it alpine uname -r | cut -d'-' -f1`
KERNEL_VERSION="5.10.76"
PYTHON_VERSION=${PYTHON_VERSION:-"3.10.0"}

docker build --build-arg KERNEL_VERSION=${KERNEL_VERSION} \
    --build-arg PYTHON_VERSION="${PYTHON_VERSION}" \
    -t python-ebpf  .

echo "Run now ./run.sh script to try ebpf. You will prompted with a shell and more info"
