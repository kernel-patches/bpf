#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source ./benchs/run_common.sh

set -eufo pipefail

for t in 1 4 8 12 16; do
printf "\n"
for i in 1 10 100 500 1000 5000 10000 50000 100000 500000 1000000; do
subtitle "nr_iterations: $i, nr_threads: $t"
	summarize "bpf_for_each helper - total callbacks called: " \
	    "$($RUN_BENCH -p $t --nr_iters $i for-each-helper)"
	printf "\n"
done
done
