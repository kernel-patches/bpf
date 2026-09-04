#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

readonly NS="ns1-$(mktemp -u XXXXXX)"
readonly V0_IP4=10.10.0.11
readonly V1_IP4=10.10.0.1
readonly V0_IP6=2001:db8::11
readonly V1_IP6=2001:db8::1

ret=1
dut_pid=""

setup() {
	{
		ip netns add ${NS}

		ip link add v1 type veth peer name v0 netns ${NS}

		ip link set v1 up
		ip addr add $V1_IP4/24 dev v1
		ip addr add $V1_IP6/64 nodad dev v1
		ip -n ${NS} link set dev v0 up
		ip -n ${NS} addr add $V0_IP4/24 dev v0
		ip -n ${NS} addr add $V0_IP6/64 nodad dev v0

		# Enable XDP mode and disable checksum offload
		ethtool -K v1 gro on
		ethtool -K v1 tx-checksumming off
		ip netns exec ${NS} ethtool -K v0 gro on
		ip netns exec ${NS} ethtool -K v0 tx-checksumming off
	} > /dev/null 2>&1
}

terminate_dut_server() {
	[ -z "$dut_pid" ] && return

	# Use the shell job instead of a PID which may have been reused.
	if [ "$(jobs -pr %% 2> /dev/null)" = "$dut_pid" ]; then
		kill -KILL %% 2> /dev/null || true
	fi

	wait "$dut_pid" 2> /dev/null || true
	dut_pid=""
}

cleanup() {
	terminate_dut_server
	ip link del v1 2> /dev/null || true
	ip netns del "${NS}" 2> /dev/null || true
}

wait_for_dut_server() {
	local i

	for ((i = 0; i < 10; i++)); do
		if [ "$(jobs -pr %% 2> /dev/null)" != "$dut_pid" ]; then
			echo "xdp_features server $dut_pid exited before accepting connections" >&2
			return 1
		fi

		if ss -tlp 2> /dev/null | grep -q "pid=$dut_pid,"; then
			return 0
		fi

		sleep 1
	done

	echo "Timed out waiting for xdp_features server $dut_pid" >&2
	return 1
}

start_dut_server() {
	./xdp_features "$@" &
	dut_pid=$!
	wait_for_dut_server
}

reap_dut_server() {
	local status=0

	wait "$dut_pid" || status=$?
	dut_pid=""
	return "$status"
}

test_xdp_features() {
	setup

	## XDP_PASS
	start_dut_server -f XDP_PASS -D $V1_IP6 -T $V0_IP6 v1
	ip netns exec ${NS} ./xdp_features -t -f XDP_PASS \
					   -D $V1_IP6 -C $V1_IP6 \
					   -T $V0_IP6 v0
	[ $? -ne 0 ] && exit
	reap_dut_server

	## XDP_DROP
	start_dut_server -f XDP_DROP -D ::ffff:$V1_IP4 -T ::ffff:$V0_IP4 v1
	ip netns exec ${NS} ./xdp_features -t -f XDP_DROP \
					   -D ::ffff:$V1_IP4 \
					   -C ::ffff:$V1_IP4 \
					   -T ::ffff:$V0_IP4 v0
	[ $? -ne 0 ] && exit
	reap_dut_server

	## XDP_ABORTED
	start_dut_server -f XDP_ABORTED -D $V1_IP6 -T $V0_IP6 v1
	ip netns exec ${NS} ./xdp_features -t -f XDP_ABORTED \
					   -D $V1_IP6 -C $V1_IP6 \
					   -T $V0_IP6 v0
	[ $? -ne 0 ] && exit
	reap_dut_server

	## XDP_TX
	start_dut_server -f XDP_TX -D ::ffff:$V1_IP4 -T ::ffff:$V0_IP4 v1
	ip netns exec ${NS} ./xdp_features -t -f XDP_TX \
					   -D ::ffff:$V1_IP4 \
					   -C ::ffff:$V1_IP4 \
					   -T ::ffff:$V0_IP4 v0
	[ $? -ne 0 ] && exit
	reap_dut_server

	## XDP_REDIRECT
	start_dut_server -f XDP_REDIRECT -D $V1_IP6 -T $V0_IP6 v1
	ip netns exec ${NS} ./xdp_features -t -f XDP_REDIRECT \
					   -D $V1_IP6 -C $V1_IP6 \
					   -T $V0_IP6 v0
	[ $? -ne 0 ] && exit
	reap_dut_server

	## XDP_NDO_XMIT
	start_dut_server -f XDP_NDO_XMIT -D ::ffff:$V1_IP4 -T ::ffff:$V0_IP4 v1
	ip netns exec ${NS} ./xdp_features -t -f XDP_NDO_XMIT \
					   -D ::ffff:$V1_IP4 \
					   -C ::ffff:$V1_IP4 \
					   -T ::ffff:$V0_IP4 v0
	ret=$?
	reap_dut_server
}

set -e
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

test_xdp_features

exit $ret
