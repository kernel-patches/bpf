#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source ./benchs/run_common.sh

set -eufo pipefail

header "Local Storage"
for i in 10 100 1000; do
subtitle "num_maps: $i"
	summarize_local_storage "local_storage cache sequential  get: "\
		"$(./bench --nr_maps $i local-storage-cache-seq-get)"
	summarize_local_storage "local_storage cache interleaved get: "\
		"$(./bench --nr_maps $i local-storage-cache-interleaved-get)"
	printf "\n"
done
