#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source ./benchs/run_common.sh

set -eufo pipefail

header "Bloom filter map"
for t in 1 4 8; do
for h in {1..10}; do
subtitle "# threads: $t, # hashes: $h"
	for e in 10000 50000 75000 100000 250000 500000 750000 1000000 2500000 5000000; do
		printf "%'d entries -\n" $e
		printf "\t"
		summarize "Total operations: " \
			"$($RUN_BENCH -p $t --nr_hashes $h --nr_entries $e bloom-filter-map)"
		printf "\t"
		summarize_percentage "False positive rate: " \
			"$($RUN_BENCH -p $t --nr_hashes $h --nr_entries $e bloom-filter-false-positive)"
	done
	printf "\n"
done
done

header "Bloom filter map, multi-producer contention"
for t in 1 2 3 4 8 12 16 20 24 28 32 36 40 44 48 52; do
	summarize "$t threads - " "$($RUN_BENCH -p $t bloom-filter-map)"
done

header "Hashmap without bloom filter vs. hashmap with bloom filter (throughput, 8 threads)"
for h in {1..10}; do
subtitle "# hashes: $h"
	for e in 10000 50000 75000 100000 250000 500000 750000 1000000 2500000 5000000; do
		printf "%'d entries -\n" $e
		printf "\t"
		summarize_total "Hashmap without bloom filter: " \
			"$($RUN_BENCH --nr_hashes $h --nr_entries $e -p 8 hashmap-without-bloom-filter)"
		printf "\t"
		summarize_total "Hashmap with bloom filter: " \
			"$($RUN_BENCH --nr_hashes $h --nr_entries $e -p 8 hashmap-with-bloom-filter)"
	done
	printf "\n"
done
