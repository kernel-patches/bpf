#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source ./benchs/run_common.sh

set -eufo pipefail

header "strlen/strnlen"
for s in 1 8 64 512 2048 4095; do
	for b in strlen strnlen; do
		summarize ${b}-${s} "$($RUN_BENCH --str-len=$s string-kfuncs-${b})"
	done
done

header "strchr/strnchr"
for s in 1 8 64 512 2048 4095; do
	for b in strchr strnchr; do
		summarize ${b}-${s} "$($RUN_BENCH --str-len=$s string-kfuncs-${b})"
	done
done

header "strchrnul/strnchrnul"
for s in 1 8 64 512 2048 4095; do
	for b in strchrnul strnchrnul; do
		summarize ${b}-${s} "$($RUN_BENCH --str-len=$s string-kfuncs-${b})"
	done
done

header "strstr/strnstr"
for s in 8 64 512 2048 4095; do
	for b in strstr strnstr; do
		summarize ${b}-${s} "$($RUN_BENCH --str-len=$s string-kfuncs-${b})"
	done
done
