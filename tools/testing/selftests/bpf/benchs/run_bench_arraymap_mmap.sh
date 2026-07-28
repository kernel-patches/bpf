#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source ./benchs/run_common.sh

set -eufo pipefail

for t in 1 4 8 16; do
for s in 1048576 8388608 67108864; do
subtitle "nr_threads: $t, map_size: $s"
	summarize_ops "arraymap-mmap: " \
	    "$($RUN_BENCH -p $t --map-size $s arraymap-mmap)"
	printf "\n"
done
done
