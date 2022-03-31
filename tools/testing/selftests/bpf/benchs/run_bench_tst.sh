#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2022. Huawei Technologies Co., Ltd

source ./benchs/run_common.sh

set -eufo pipefail

mem()
{
	echo "$*" | sed -E "s/.*Memory: ([0-9]+\.[0-9]+ MiB).*/\1/"
}

run_test()
{
	local title=$1
	local summary

	shift 1
	summary=$(sudo ./bench -w1 -d4 -a "$@" | grep "Summary\|Memory:")
	printf "%-25s %s (drops %s, mem %s)\n" "$title" "$(hits $summary)" \
		"$(drops $summary)" "$(mem $summary)"
}

run_tests()
{
	local name=$1
	local map
	local nr
	local s

	shift 1
	for map in tst htab
	do
		nr=1000
		for s in $(seq 1 5)
		do
			run_test "$map-$nr-$name" $map-lookup --tst-entries $nr $@
			let "nr *= 10"
		done
		echo
	done
}

for key in hk fk
do
	opts=""
	[ $key == "fk" ] && opts="--flat-key"
	for len in dl sl
	do
		[ $len == "sl" ] && opts="$opts --same-len"
		run_tests "$key-$len" "$opts"
	done
done
