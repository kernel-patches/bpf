#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

if ! command -v python3 > /dev/null; then
	echo "SKIP: missing python3"
	exit 4
fi

exec python3 -B "$(dirname "$0")/hsr_gro_superpacket.py" ordered "$@"
