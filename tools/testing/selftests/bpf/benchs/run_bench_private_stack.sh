#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source ./benchs/run_common.sh

set -eufo pipefail

for b in 1 8 64 512 2048 4096; do
    summarize "no-private-stack-${b}: " "$($RUN_BENCH --nr-batch-iters=${b} no-private-stack)"
    summarize "private-stack-${b}: " "$($RUN_BENCH --nr-batch-iters=${b} private-stack)"
done
