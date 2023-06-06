#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source ./benchs/run_common.sh

set -eufo pipefail

htab_mem()
{
	echo -n "loop : "
	echo -n "$*" | sed -E "s/.* loop\s+([0-9]+\.[0-9]+ ± [0-9]+\.[0-9]+k\/s).*/\1/"
	echo -n -e ", avg mem: "
	echo -n "$*" | sed -E "s/.* memory usage\s+([0-9]+\.[0-9]+ ± [0-9]+\.[0-9]+MiB).*/\1/"
	echo -n ", peak mem: "
	echo "$*" | sed -E "s/.* peak memory usage\s+([0-9]+\.[0-9]+MiB).*/\1/"
}

summarize_htab_mem()
{
	local bench="$1"
	local summary=$(echo $2 | tail -n1)

	printf "%-20s %s\n" "$bench" "$(htab_mem $summary)"
}

htab_mem_bench()
{
	local name

	for name in no_op overwrite batch_add_batch_del add_del_on_diff_cpu
	do
		summarize_htab_mem "$name" "$(sudo ./bench htab-mem --use-case $name \
			--max-entries 16384 --full 50 -d 10 \
			--producers=8 --prod-affinity=0-7 "$@")"
	done
}

header "preallocated"
htab_mem_bench "--preallocated"

header "normal bpf ma"
htab_mem_bench
