#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2022. Huawei Technologies Co., Ltd

source ./benchs/run_common.sh

set -eufo pipefail

mem()
{
	echo "$*" | sed -E "s/.*Slab: ([0-9]+\.[0-9]+ MiB).*/\1/"
}

run_qp_trie_bench()
{
	local title=$1
	local summary

	shift 1
	summary=$($RUN_BENCH "$@" | grep "Summary\|Slab:")
	printf "%s %20s (drops %-16s mem %s)\n" "$title" "$(hits $summary)" \
		"$(drops $summary)" "$(mem $summary)"
}

run_qp_trie_benchs()
{
	local p
	local m
	local b
	local title

	for m in htab qp-trie
	do
		for b in lookup update
		do
			for p in 1 2 4 8 16
			do
				title=$(printf "%-16s (%-2d thread)" "$m $b" $p)
				run_qp_trie_bench "$title" ${m}-${b} -p $p "$@"
			done
		done
	done
	echo
}

echo "Randomly-generated binary data (16K)"
run_qp_trie_benchs --entries 16384

echo "Strings in /proc/kallsyms"
TMP_FILE=/tmp/kallsyms.txt
SRC_FILE=/proc/kallsyms
trap 'rm -f $TMP_FILE' EXIT
wc -l $SRC_FILE | awk '{ print $1}' > $TMP_FILE
awk '{ print $3 }' $SRC_FILE >> $TMP_FILE
run_qp_trie_benchs --file $TMP_FILE
