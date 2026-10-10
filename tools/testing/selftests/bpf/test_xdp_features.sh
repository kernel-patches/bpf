#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

readonly NS="ns1-$(mktemp -u XXXXXX)"
readonly DUT_NS="dut-${NS}"
readonly V0_IP4=10.10.0.11
readonly V1_IP4=10.10.0.1
readonly V0_IP6=2001:db8::11
readonly V1_IP6=2001:db8::1

ret=1
dut_pid=""
peer_created=false
dut_created=false
setup_in_progress=true
pending_signal=0

setup() {
	{
		ip netns add "${NS}"
		peer_created=true
		ip netns add "${DUT_NS}"
		dut_created=true

		ip -n "$DUT_NS" link add v1 type veth peer name v0 netns ${NS}

		ip -n "$DUT_NS" link set v1 up
		ip -n "$DUT_NS" addr add $V1_IP4/24 dev v1
		ip -n "$DUT_NS" addr add $V1_IP6/64 nodad dev v1
		ip -n ${NS} link set dev v0 up
		ip -n ${NS} addr add $V0_IP4/24 dev v0
		ip -n ${NS} addr add $V0_IP6/64 nodad dev v0

		# Enable XDP mode and disable checksum offload
		ip netns exec "$DUT_NS" ethtool -K v1 gro on
		ip netns exec "$DUT_NS" ethtool -K v1 tx-checksumming off
		ip netns exec ${NS} ethtool -K v0 gro on
		ip netns exec ${NS} ethtool -K v0 tx-checksumming off
	} > /dev/null 2>&1
	setup_in_progress=false
	[ "$pending_signal" -eq 0 ] || exit "$pending_signal"
}

terminate_dut_server() {
	local pid

	# Use the shell job instead of dut_pid, which may not have been assigned
	# yet if a signal arrived immediately after the server was started.
	pid=$(jobs -pr %% 2> /dev/null) || true
	if [ -z "$pid" ]; then
		dut_pid=""
		return
	fi

	kill -KILL %% 2> /dev/null || true
	wait "$pid" 2> /dev/null || true
	dut_pid=""
}

cleanup() {
	trap - EXIT
	trap '' HUP INT QUIT ABRT TERM
	terminate_dut_server
	if "$dut_created"; then
		ip netns del "$DUT_NS" 2> /dev/null || true
	fi
	if "$peer_created"; then
		ip netns del "$NS" 2> /dev/null || true
	fi
}

wait_for_dut_server() {
	while true; do
		if [ "$(jobs -pr %% 2> /dev/null)" != "$dut_pid" ]; then
			echo "xdp_features server $dut_pid exited before readiness" >&2
			return 1
		fi

		if ip netns exec "$DUT_NS" ss -tlp 2> /dev/null |
		   grep -q "pid=$dut_pid,"; then
			return 0
		fi

		sleep 1
	done
}

start_dut_server() {
	ip netns exec "$DUT_NS" ./xdp_features "$@" &
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

handle_signal() {
	if "$setup_in_progress"; then
		pending_signal=$1
	else
		exit "$1"
	fi
}

set -e
trap cleanup EXIT
trap 'handle_signal 129' HUP
trap 'handle_signal 130' INT
trap 'handle_signal 131' QUIT
trap 'handle_signal 134' ABRT
trap 'handle_signal 143' TERM

test_xdp_features

exit $ret
