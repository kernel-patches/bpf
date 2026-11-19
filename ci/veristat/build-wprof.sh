#!/bin/bash
set -euo pipefail

wprof=$1
output=$2

make -C "$wprof/src" -j"$(nproc)" .output/wprof.skel.h .output/wprof_query.skel.h
mkdir -p "$output"
cp "$wprof/src/.output/wprof-final.bpf.o" "$wprof/src/.output/wprof_query.bpf.o" "$output/"
