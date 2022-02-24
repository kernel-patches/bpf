#!/bin/bash
# SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
# Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

set -e

PORT=8080

DIR="$(dirname "$0")"
SERVER_PID=

fail() {
	echo 'test_xdp_synproxy: [FAIL]'
	exit 1
}

cleanup() {
	set +e

	ip link del tmp0
	ip netns del synproxy

	# Kill background jobs, if any.
	kill "$(jobs -p)"
}

trap cleanup SIGINT SIGTERM EXIT

[ -d /sys/module/nf_conntrack ] || modprobe nf_conntrack
ip netns add synproxy
ip netns exec synproxy ip link set lo up
ip link add tmp0 type veth peer name tmp1
sleep 1 # Wait, otherwise the IP address is not applied to tmp0.
ip link set tmp1 netns synproxy
ip link set tmp0 up
ip addr replace 198.18.0.1/24 dev tmp0
ip netns exec synproxy ip link set tmp1 up
ip netns exec synproxy ip addr replace 198.18.0.2/24 dev tmp1
ip netns exec synproxy sysctl -w net.ipv4.tcp_syncookies=2
ip netns exec synproxy sysctl -w net.ipv4.tcp_timestamps=1
ip netns exec synproxy sysctl -w net.netfilter.nf_conntrack_tcp_loose=0
ip netns exec synproxy iptables -t raw -I PREROUTING \
	-i tmp1 -p tcp -m tcp --syn --dport "$PORT" -j CT --notrack
ip netns exec synproxy iptables -t filter -A INPUT \
	-i tmp1 -p tcp -m tcp --dport "$PORT" -m state --state INVALID,UNTRACKED \
	-j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
ip netns exec synproxy iptables -t filter -A INPUT \
	-i tmp1 -m state --state INVALID -j DROP
# When checksum offload is enabled, the XDP program sees wrong checksums and
# drops packets.
ethtool -K tmp0 tx off
# Workaround required for veth.
ip link set tmp0 xdp object "$DIR/xdp_dummy.o" section xdp 2> /dev/null

SYNACKS="$(ip netns exec synproxy "$DIR/xdp_synproxy" --iface tmp1 \
	--ports "$PORT" --mss4 1460 --mss6 1440 --wscale 7 --ttl 64 --single | \
	cut -d: -f2)"
[ "$SYNACKS" -eq 0 ] || fail

# Different nc implementations accept different parameters.
{ ip netns exec synproxy nc -l -p "$PORT" || ip netns exec synproxy nc -l "$PORT"; } &
SERVER_PID="$!"
sleep 1 # Wait for the server to start.

echo -n > /dev/tcp/198.18.0.2/"$PORT"

SYNACKS="$(ip netns exec synproxy "$DIR/xdp_synproxy" --iface tmp1 --single | \
	cut -d: -f2)"
[ "$SYNACKS" -eq 1 ] || fail

echo 'test_xdp_synproxy: ok'
