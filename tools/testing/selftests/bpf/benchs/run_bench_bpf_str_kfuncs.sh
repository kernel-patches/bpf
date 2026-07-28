#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

set -euo pipefail

cpu=${CPU:-1}
report=${REPORT:-bench_bpf_str_kfuncs.tmp}

if [[ -z "$report" ]]; then
	echo "Report file must not be empty" >&2
	exit 2
fi

tmp=$(mktemp "${report}.tmp.XXXXXX")
trap 'rm -f "$tmp"' EXIT

sudo taskset -c "$cpu" ./bench bpf-str-kfuncs "$@" > "$tmp"

if [[ ! -e "$report" ]]; then
	mv "$tmp" "$report"
	trap - EXIT
	cat "$report"
	printf '\nSaved baseline report to %s\n' "$report"
	exit
fi

awk '
function fail(message)
{
	print "Invalid benchmark comparison: " message > "/dev/stderr"
	failed = 1
	exit 1
}

FNR == 1 {
	file++
	kind = ""
}

$1 ~ /^kernel=/ {
	if (file == 1) {
		baseline_kernel = $0
		baseline_params = $2 " " $3 " " $4 " " $5
	} else {
		current_kernel = $0
		current_params = $2 " " $3 " " $4 " " $5
		if (baseline_params != current_params)
			fail("architecture or run parameters differ")
		print "BPF string kfunc benchmark comparison"
		print "baseline " baseline_kernel
		print "current  " current_kernel
	}
	next
}

$0 ~ /^[[:alpha:]]+ \(bpf_[[:alnum:]_]+\)$/ {
	kind = $1
	kfunc = $2
	gsub(/[()]/, "", kfunc)
	next
}

$1 ~ /^(first|middle|late|absent|equal)$/ && $2 ~ /^[0-9]+$/ {
	key = kind SUBSEP $1
	if (!kind)
		fail("result row without benchmark name")

	if (file == 1) {
		baseline[key] = $3
		baseline_bytes[key] = $2
		baseline_count++
	} else {
		if (!(key in baseline))
			fail("baseline is missing " kind "/" $1)
		if (baseline_bytes[key] != $2)
			fail("byte count differs for " kind "/" $1)
		if (kind != last_kind) {
			last_kind = kind
			printf "\n%s (%s)\n", kind, kfunc
			printf "%-9s %5s %15s %14s %9s\n", "Scenario",
			       "Bytes", "Baseline ns/op", "Current ns/op",
			       "Speedup"
		}
		printf "%-9s %5d %15.1f %14.1f %8.2fx\n",
		       $1, $2, baseline[key], $3, baseline[key] / $3
		current_count++
	}
}

END {
	if (failed)
		exit 1
	if (!baseline_kernel || !current_kernel)
		fail("missing benchmark metadata")
	if (baseline_count != current_count)
		fail("different number of result rows")
}
' "$report" "$tmp"
