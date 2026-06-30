#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# 1. Load the official common benchmark utilities
source ./benchs/run_common.sh

# 2. Strict error handling configurations
set -eufo pipefail

# 3. Use default bench binary path if not exported by the framework
BENCH_BIN=${BENCH:-./bench}

# 4. Run with strict core affinity and isolation for reliable profiling
RUN_BENCH="numactl --physcpubind=0,2 --membind=0 nice -n -20 $BENCH_BIN -w5 -d20 -a"

# 5. Capture the output string and pass it straight into summarize_ops
# This satisfies the framework's internal parameter bounds without triggering set -u.
summarize_ops "tailcall" "$($RUN_BENCH tailcall)"
