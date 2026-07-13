#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

set -eu

ksft_skip=4
obj_dir="lightswitch_bpf"

if [ ! -d "$obj_dir" ]; then
	echo "lightswitch BPF build output not found"
	exit "$ksft_skip"
fi

set -- "$obj_dir"/*.bpf.o
if [ ! -e "$1" ]; then
	echo "no lightswitch BPF objects were built"
	exit 1
fi

for obj in "$@"; do
	if [ ! -s "$obj" ]; then
		echo "empty lightswitch BPF object: $obj"
		exit 1
	fi
	echo "built $obj"
done

exit 0
