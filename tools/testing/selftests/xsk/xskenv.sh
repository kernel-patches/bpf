#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2020 Intel Corporation.

. prereqs.sh

XSKDIR=xdpprogs
XSKOBJ=xdpxceiver
NUMPKTS=10000

validate_veth_spec_file

VETH0=$(cat ${SPECFILE} | cut -d':' -f 1)
VETH1=$(cat ${SPECFILE} | cut -d':' -f 2 | cut -d',' -f 1)
NS1=$(cat ${SPECFILE} | cut -d':' -f 2 | cut -d',' -f 2)

execxdpxceiver()
{
	local -a 'paramkeys=("${!'"$1"'[@]}")' copy
	paramkeysstr=${paramkeys[*]}

	for index in $paramkeysstr;
		do
			current=$1"[$index]"
			copy[$index]=${!current}
		done

	if [ -f ./${XSKOBJ} ]; then
		./${XSKOBJ} -i ${VETH0} -i ${VETH1},${NS1} ${copy[*]} -C ${NUMPKTS}
	else
		./${XSKDIR}/${XSKOBJ} -i ${VETH0} -i ${VETH1},${NS1} ${copy[*]} -C ${NUMPKTS}
	fi
}
