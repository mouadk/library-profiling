#!/bin/bash

echo "🔍🛡️SysGuardian testing...";
docker run -ti --rm  -v "$(pwd)/bcc":"/workspace/bcc/" -v "$(pwd)/bpftrace":"/workspace/bpftrace/"  -v /lib/modules:/lib/modules:ro --privileged -v debugfs:/sys/kernel/debug:rw python-ebpf sh

# debugfs:/sys/kernel/debug is needed for tracepoint.
# /lib/modules:/lib/modules:ro is needed for kernel headers.