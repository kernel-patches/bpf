#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source ./benchs/run_common.sh

set -eufo pipefail

prod_list=${PROD_LIST:-"1 2 4 8"}
entries=${ENTRIES:-8192}
max_size=${MAX_SIZE:-256}
str_file=${STR_FILE:-}

summarize_rate_and_mem()
{
	local bench="$1"
	local mem=$(echo $2 | grep Slab: | \
		sed -E "s/.*Slab:\s+([0-9]+\.[0-9]+ MiB).*/\1/")
	local summary=$(echo $2 | tail -n1)

	printf "%-20s %s (drops %s, mem %s)\n" "$bench" "$(hits $summary)" \
		"$(drops $summary)" "$mem"
}

htab_bench()
{
	local opts="--entries ${entries} --max_size ${max_size}"
	local desc="${entries}"
	local name
	local prod

	if test -n "${str_file}" && test -f "${str_file}"
	then
		opts="--file ${str_file}"
		desc="${str_file}"
	fi

	for name in htab-lookup htab-update
	do
		for prod in ${prod_list}
		do
			summarize_rate_and_mem "${name}-p${prod}-${desc}" \
				"$($RUN_BENCH -p${prod} ${1}-${name} ${opts})"
		done
	done
}

header "normal hash map"
htab_bench norm

header "dynptr-keyed hash map"
htab_bench dynkey
