#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source ./benchs/run_common.sh

set -eufo pipefail

for ks in 64 128 256 512 1024 2048 4096; do
	for tp in bytes str; do
		for op in lookup update; do
			summarize ${ks}-${tp}-${op} "$($RUN_BENCH --key-size=$ks htab-${tp}-${op})"
		done
	done
done
