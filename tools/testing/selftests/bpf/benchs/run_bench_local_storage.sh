#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source ./benchs/run_common.sh

set -eufo pipefail

header "Local Storage"
subtitle "Hashmap Control w/ 500 maps"
	summarize_local_storage "hashmap (control) sequential    get: "\
		"$(./bench --nr_maps 500 local-storage-cache-hashmap-control)"
	printf "\n"

for i in 1 10 16 17 24 32 100 1000; do
subtitle "num_maps: $i"
	summarize_local_storage "local_storage cache sequential  get: "\
		"$(./bench --nr_maps $i local-storage-cache-seq-get)"
	summarize_local_storage "local_storage cache interleaved get: "\
		"$(./bench --nr_maps $i local-storage-cache-int-get)"
	printf "\n"
done
