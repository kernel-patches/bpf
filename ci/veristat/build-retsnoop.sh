#!/bin/bash
set -euo pipefail

retsnoop=$1
output=$2

make -C "$retsnoop/src" -j"$(nproc)" \
    .output/retsnoop.skel.h .output/calib_feat.skel.h .output/kmem_reader.skel.h
mkdir -p "$output"
for name in retsnoop calib_feat kmem_reader; do
    cp "$retsnoop/src/.output/$name.bpfo" "$output/$name.bpf.o"
done
