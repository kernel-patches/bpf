#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source ./benchs/run_common.sh

set -eufo pipefail

for s in 4 8 16 20 40 64 512; do
	summarize ${s} "$($RUN_BENCH --buff-len=$s csum-diff-helper)"
done
