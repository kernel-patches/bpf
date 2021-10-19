#!/bin/sh
# SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
# Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.

set -e

PORT=8080

DIR="$(dirname "$0")"
SERVER_PID=
MONITOR_PID=

cleanup() {
	set +e
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID"
	[ -n "$MONITOR_PID" ] && kill "$MONITOR_PID"
	ip link del tmp0
	ip netns del synproxy
}

trap cleanup EXIT

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
ip link set tmp0 xdp object "$DIR/syncookie_kern.o" section xdp/dummy
ip netns exec synproxy "$DIR/syncookie" --iface tmp1 --ports "$PORT" \
	--mss4 1460 --mss6 1440 --wscale 7 --ttl 64 &
MONITOR_PID="$!"
ip netns exec synproxy python3 -m http.server "$PORT" &
SERVER_PID="$!"
echo "Waiting a few seconds for the server to start..."
sleep 5
wget 'http://198.18.0.2:8080/' -O /dev/null -o /dev/null
sleep 1 # Wait for stats to appear.
