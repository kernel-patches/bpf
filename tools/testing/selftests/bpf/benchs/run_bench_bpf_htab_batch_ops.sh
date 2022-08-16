#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source ./benchs/run_common.sh

set -eufo pipefail

map_capacity=40000
header "bpf_get_next_key & bpf_map_lookup_elem"
for t in 40000 10000 2500; do
subtitle "map capacity: $map_capacity, num_entries: $t"
        summarize_ops "bpf_element_ops: " \
                "$($RUN_BENCH -p 1 --num_entries $t htab-element-ops)"
        printf "\n"
done

header "bpf_map_lookup_batch with prefetch"
for t in 40000 10000 2500; do
for n in {0..20}; do
#this range of n_prefetch shows the speedup and subsequent
#deterioration as n_prefetch grows larger
subtitle "map capacity: $map_capacity, num_entries: $t, n_prefetch: $n"
        echo $n > /sys/module/hashtab/parameters/n_prefetch
        summarize_ops "bpf_batch_ops: " \
                "$($RUN_BENCH -p 1 --num_entries $t htab-batch-ops)"
        printf "\n"
done
done
