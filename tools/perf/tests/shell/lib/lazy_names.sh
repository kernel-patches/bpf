#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# lazy_names_disabled FILE...
# Return whether one of FILE has a PPC64 ELFv1 .opd, a .gnu_debugdata symbol
# table or a compressed .strtab, for which perf loads symbol names eagerly.
lazy_names_disabled() {
	local f

	command -v readelf > /dev/null || return 1
	for f in "$@"; do
		[ -e "${f}" ] || continue
		if readelf -SW "${f}" 2> /dev/null |
		   grep -Eq ' \.(opd|gnu_debugdata) | \.strtab +STRTAB( +[0-9a-f]+){4} +[A-Z]*C'
		then
			return 0
		fi
	done
	return 1
}
