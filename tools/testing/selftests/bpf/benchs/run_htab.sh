#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source ./benchs/run_common.sh

set -eufo pipefail

for tp in byte str int-byte int-str int-bytes int-strs; do
	name=htab-${tp}-lookup
	summarize ${name} "$($RUN_BENCH ${name})"
done
