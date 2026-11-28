#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Test net.ipv4.tcp_l3mdev_exempt_ports.
#
# With tcp_l3mdev_accept=1, a listener that is not bound to a device also
# matches connections that arrive in a VRF. For a port listed in
# tcp_l3mdev_exempt_ports it must not: only a listener bound to the VRF
# or to the receiving device may take such a connection. Connections in
# the default VRF are not affected.
#
#  ns_c (client in VRF)       ns_s (server)       ns_d (client, default VRF)
#      veth0 ------------- veth_vrf [vrf red]
#                             veth_def ----------------- veth0

# ns_s, ns_c and ns_d are assigned by setup_ns, and the test functions
# are called through ALL_TESTS.
# shellcheck disable=SC2154,SC2329

source lib.sh

PORT=12345
OTHER_PORT=23456
VRF=red
VRF_TABLE=1000

VRF_SRV4=172.16.1.1
VRF_CLI4=172.16.1.2
DEF_SRV4=172.16.2.1
DEF_CLI4=172.16.2.2
VRF_SRV6=2001:db8:1::1
VRF_CLI6=2001:db8:1::2
DEF_SRV6=2001:db8:2::1
DEF_CLI6=2001:db8:2::2

# Servers that must not get a connection are stopped by the test, so this
# only needs to be longer than any wait before the client connects.
SRV_TIMEOUT=20

ALL_TESTS="
	unbound_listener
	vrf_and_unbound_listeners
	slave_and_unbound_listeners
	default_vrf_unaffected
"

cleanup()
{
	cleanup_all_ns
}

setup_fail()
{
	echo "FAIL: setup"
	exit "$ksft_fail"
}

setup()
{
	setup_ns ns_s ns_c ns_d || exit "$ksft_skip"

	if ! ip -n "$ns_s" link add "$VRF" type vrf table "$VRF_TABLE"; then
		echo "SKIP: VRF not supported"
		exit "$ksft_skip"
	fi

	if ! ip netns exec "$ns_s" \
	     test -e /proc/sys/net/ipv4/tcp_l3mdev_exempt_ports; then
		echo "SKIP: net.ipv4.tcp_l3mdev_exempt_ports not supported"
		exit "$ksft_skip"
	fi

	ip -n "$ns_s" -batch - <<-EOF || setup_fail
		link set $VRF up
		link add veth_vrf type veth peer name veth0 netns $ns_c
		link set veth_vrf master $VRF
		link set veth_vrf up
		addr add $VRF_SRV4/24 dev veth_vrf
		addr add $VRF_SRV6/64 dev veth_vrf nodad
		link add veth_def type veth peer name veth0 netns $ns_d
		link set veth_def up
		addr add $DEF_SRV4/24 dev veth_def
		addr add $DEF_SRV6/64 dev veth_def nodad
	EOF

	ip -n "$ns_c" -batch - <<-EOF || setup_fail
		link set veth0 up
		addr add $VRF_CLI4/24 dev veth0
		addr add $VRF_CLI6/64 dev veth0 nodad
	EOF

	ip -n "$ns_d" -batch - <<-EOF || setup_fail
		link set veth0 up
		addr add $DEF_CLI4/24 dev veth0
		addr add $DEF_CLI6/64 dev veth0 nodad
	EOF

	ip netns exec "$ns_s" sysctl -wq net.ipv4.tcp_l3mdev_accept=1 ||
		setup_fail
}

set_exempt()
{
	ip netns exec "$ns_s" sysctl -wq net.ipv4.tcp_l3mdev_exempt_ports="$1"
}

# Start a server in the background. nettest sets SO_REUSEPORT on its
# listeners, so an unbound and a device-bound listener can share the port.
# $1: IP version, $2: device to bind to, or "unbound"
start_server()
{
	local args=()

	[ "$1" = 6 ] && args+=(-6)
	[ "$2" != unbound ] && args+=(-I "$2")
	ip netns exec "$ns_s" nettest "${args[@]}" -s -p "$PORT" \
		-t "$SRV_TIMEOUT" -q &
}

# Stop a server, ignoring its exit code.
stop_server()
{
	kill "$1" 2>/dev/null
	wait "$1" 2>/dev/null
}

# Stop a server that must not have received a connection. It must still
# be running: had it accepted the connection or timed out, it would have
# exited.
# $1: pid, $2: name for the error message
stop_idle_server()
{
	kill -0 "$1" 2>/dev/null
	check_err $? "$2 exited, expected it to still be waiting"
	stop_server "$1"
}

# $1: client netns, $2: IP version, $3: server address
connect()
{
	local args=()

	[ "$2" = 6 ] && args+=(-6)
	ip netns exec "$1" nettest "${args[@]}" -r "$3" -p "$PORT" -t 2 -q
}

listeners_are()
{
	local n

	n=$(ip netns exec "$ns_s" ss -Hltn "sport = :$PORT" | wc -l)
	[ "$n" -eq "$1" ]
}

# $1: number of listeners to wait for on $PORT
wait_listeners()
{
	slowwait 2 listeners_are "$1"
}

unbound_listener()
{
	local ver addr pid

	for ver in 4 6; do
		addr=$VRF_SRV4
		[ "$ver" = 6 ] && addr=$VRF_SRV6

		RET=0
		set_exempt "$OTHER_PORT"
		start_server "$ver" unbound
		pid=$!
		if wait_listeners 1; then
			connect "$ns_c" "$ver" "$addr"
			check_err $? "VRF connection failed"
			wait "$pid"
			check_err $? "unbound listener did not get the conn"
		else
			check_err 1 "listener did not start"
			stop_server "$pid"
		fi
		log_test "IPv$ver: not exempt, unbound listener gets VRF conn"

		RET=0
		set_exempt "$PORT"
		start_server "$ver" unbound
		pid=$!
		if wait_listeners 1; then
			connect "$ns_c" "$ver" "$addr"
			check_fail $? "VRF connection succeeded"
			stop_idle_server "$pid" "unbound listener"
		else
			check_err 1 "listener did not start"
			stop_server "$pid"
		fi
		log_test "IPv$ver: exempt, unbound listener gets no VRF conn"
	done
	set_exempt ""
}

# An unbound listener and a listener bound to $1 on the port. The VRF
# connection must reach the bound one, whichever was created first.
# $1: the VRF device, or the VRF slave device the connection arrives on
bound_and_unbound_listeners()
{
	local dev=$1
	local ver addr order first second pid_first pid_second
	local pid_bound pid_unbound

	set_exempt "$PORT"
	for ver in 4 6; do
		addr=$VRF_SRV4
		[ "$ver" = 6 ] && addr=$VRF_SRV6

		for order in "unbound $dev" "$dev unbound"; do
			read -r first second <<< "$order"
			RET=0

			pid_second=
			start_server "$ver" "$first"
			pid_first=$!
			if wait_listeners 1; then
				start_server "$ver" "$second"
				pid_second=$!
			fi
			if [ -z "$pid_second" ] || ! wait_listeners 2; then
				check_err 1 "listeners did not start"
				stop_server "$pid_first"
				[ -n "$pid_second" ] &&
					stop_server "$pid_second"
				log_test "IPv$ver: exempt, $first first"
				continue
			fi

			if [ "$first" = unbound ]; then
				pid_unbound=$pid_first
				pid_bound=$pid_second
			else
				pid_bound=$pid_first
				pid_unbound=$pid_second
			fi

			connect "$ns_c" "$ver" "$addr"
			check_err $? "VRF connection failed"
			wait "$pid_bound"
			check_err $? "$dev listener did not get the connection"
			stop_idle_server "$pid_unbound" "unbound listener"

			log_test "IPv$ver: exempt, $first first, $dev wins"
		done
	done
	set_exempt ""
}

vrf_and_unbound_listeners()
{
	bound_and_unbound_listeners "$VRF"
}

slave_and_unbound_listeners()
{
	bound_and_unbound_listeners veth_vrf
}

default_vrf_unaffected()
{
	local ver addr pid

	set_exempt "$PORT"
	for ver in 4 6; do
		addr=$DEF_SRV4
		[ "$ver" = 6 ] && addr=$DEF_SRV6

		RET=0
		start_server "$ver" unbound
		pid=$!
		if wait_listeners 1; then
			connect "$ns_d" "$ver" "$addr"
			check_err $? "default VRF connection failed"
			wait "$pid"
			check_err $? "unbound listener did not get the conn"
		else
			check_err 1 "listener did not start"
			stop_server "$pid"
		fi
		log_test "IPv$ver: exempt, unbound listener gets default conn"
	done
	set_exempt ""
}

trap cleanup EXIT

check_gen_prog nettest
setup
tests_run

exit "$EXIT_STATUS"
