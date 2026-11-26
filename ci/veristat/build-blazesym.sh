#!/bin/bash
set -euo pipefail

wprof=$1
output=$2

mkdir -p "$output"
"${CLANG:-clang}" -g -O2 -target bpf -c -D__TARGET_ARCH_x86 \
    -I "$wprof/vmlinux.h/include/x86" -I "$wprof/src/.output" \
    "$wprof/blazesym/tests/bpf/src/getpid.bpf.c" -o "$output/getpid.bpf.o"
