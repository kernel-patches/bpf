#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source ./benchs/run_common.sh

set -eufo pipefail

for b in bpf-arraymap-mmap file-mmap; do
for t in 1 4 8 16; do
for s in 1048576 8388608 67108864; do
subtitle "bench: $b, nr_threads: $t, map_size: $s"
	summarize_ops "$b: " \
	    "$($RUN_BENCH --nr-threads $t --map-size $s $b)"
	printf "\n"
done
done
done
