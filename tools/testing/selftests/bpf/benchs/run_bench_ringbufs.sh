#!/bin/bash

source ./benchs/run_common.sh

set -eufo pipefail

RUN_RB_BENCH="$RUN_BENCH -c1"

header "Parallel producer"
for b in rb-libbpf rb-custom pb-libbpf pb-custom; do
	summarize $b "$($RUN_RB_BENCH $b)"
done

header "Parallel producer, sampled notifications"
for b in rb-libbpf rb-custom pb-libbpf pb-custom; do
	summarize $b "$($RUN_RB_BENCH --rb-sampled $b)"
done

header "Back-to-back producer"
for b in rb-libbpf rb-custom pb-libbpf pb-custom; do
	summarize $b "$($RUN_RB_BENCH --rb-b2b $b)"
	summarize $b-sampled "$($RUN_RB_BENCH --rb-sampled --rb-b2b $b)"
done

header "Back-to-back producer, varying sample rate"
for b in rb-custom pb-custom; do
  for r in 1 5 10 25 50 100 250 500 1000 2000 3000; do
	  summarize "$b-$r" "$($RUN_RB_BENCH --rb-b2b --rb-batch-cnt $r --rb-sampled --rb-sample-rate $r $b)"
  done
done

header "Back-to-back producer, rb-custom reserve+commit vs output"
summarize "reserve" "$($RUN_RB_BENCH --rb-b2b                 rb-custom)"
summarize "output"  "$($RUN_RB_BENCH --rb-b2b --rb-use-output rb-custom)"

header "Parallel producer, rb-custom reserve+commit vs output, sampled notifications"
summarize "reserve-sampled" "$($RUN_RB_BENCH --rb-sampled                 rb-custom)"
summarize "output-sampled"  "$($RUN_RB_BENCH --rb-sampled --rb-use-output rb-custom)"

header "Concurrent producer (same CPU as consumer), low batch count"
for b in rb-libbpf rb-custom pb-libbpf pb-custom; do
	summarize $b "$($RUN_RB_BENCH --rb-batch-cnt 1 --rb-sample-rate 1 --prod-affinity 0 --cons-affinity 0 $b)"
done

header "Parallel producers (multiple, contention)"
for n in 1 2 3 4 8 12 16 20 24 28 32 36 40 44 48 52; do
	summarize "rb-libbpf nr_prod $n" "$($RUN_RB_BENCH -p$n --rb-batch-cnt 50 rb-libbpf)"
done

