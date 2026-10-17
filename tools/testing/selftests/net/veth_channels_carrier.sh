#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

require_command ip
require_command ethtool

if [ "$EUID" -ne 0 ]; then
	echo "SKIP: root privileges are required"
	exit "$ksft_skip"
fi

trap cleanup_all_ns EXIT
setup_ns ns || exit $?

check_carrier()
{
	local dev=$1
	local expected=$2
	local carrier=0
	local link

	link=$(ip -n "$ns" -o link show dev "$dev")
	check_err $? "Failed to read $dev link state"
	[[ $link == *LOWER_UP* ]] && carrier=1
	[ "$carrier" -eq "$expected" ]
	check_err $? "$dev carrier is $carrier, expected $expected"
}

check_state()
{
	local left=$1
	local right=$2
	local gro=$3
	local expected=0
	local count dev

	RET=0
	if ! ip -n "$ns" link add vca numtxqueues 2 numrxqueues 2 \
		type veth peer name vcb numtxqueues 2 numrxqueues 2; then
		RET=$ksft_skip
		log_test "veth carrier: $left/$right, GRO $gro"
		return
	fi

	ip -n "$ns" link set vca "$left"
	check_err $? "Failed to configure vca"
	ip -n "$ns" link set vcb "$right"
	check_err $? "Failed to configure vcb"
	ip netns exec "$ns" ethtool -K vca gro "$gro" >/dev/null
	check_err $? "Failed to configure GRO"
	ip netns exec "$ns" ethtool -K vcb gro "$gro" >/dev/null
	check_err $? "Failed to configure peer GRO"

	[ "$left" = up ] && [ "$right" = up ] && expected=1
	check_carrier vca "$expected"
	check_carrier vcb "$expected"

	for dev in vca vcb; do
		for count in 1 2; do
			ip netns exec "$ns" ethtool -L "$dev" \
				rx "$count" tx "$count"
			check_err $? "Failed to resize $dev channels"
			check_carrier vca "$expected"
			check_carrier vcb "$expected"
		done

		ip netns exec "$ns" ethtool -L "$dev" rx 3 tx 3 \
			>/dev/null 2>&1
		check_fail $? "Out-of-range channel counts were accepted"
		check_carrier vca "$expected"
		check_carrier vcb "$expected"
	done

	ip -n "$ns" link del vca
	check_err $? "Failed to delete the veth pair"
	log_test "veth carrier: $left/$right, GRO $gro"
}

for gro in off on; do
	for left in down up; do
		for right in down up; do
			check_state "$left" "$right" "$gro"
		done
	done
done

exit "$EXIT_STATUS"
