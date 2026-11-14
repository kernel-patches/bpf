#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Check that a learning VXLAN device fully updates a remote when snooping
# moves a known MAC to another VTEP:
#
# - The route cached for the old remote is dropped. The old remote is
#   on-link and the new one is behind a router, so a stale cached route
#   blackholes traffic to the moved MAC.
# - The output interface follows the new remote. The MAC moves from a
#   global IPv6 address to a link-local one, which needs an interface.

# shellcheck disable=SC2154,SC2329 # setup_ns sets the ns names; tests_run calls the tests
source lib.sh

ALL_TESTS="
	test_move_behind_router
	test_move_to_link_local
"

MAC=02:00:c0:a8:00:0a

ping_from_cpu0()
{
	local ns=$1; shift

	taskset -c 0 ip netns exec "$ns" ping -c 3 -W 1 -i 0.2 "$@" &> /dev/null
}

add_sw_port()
{
	local ns=$1; shift
	local dev=$1; shift
	local port=$1; shift

	ip link add "$dev" netns "$ns" type veth peer name "$port" netns "$sw"
	ip -n "$sw" link set "$port" master br0 up
	ip -n "$ns" link set "$dev" up
}

test_move_behind_router()
{
	RET=0

	setup_ns sw ex a r b
	defer cleanup_ns "$sw" "$ex" "$a" "$r" "$b"

	ip -n "$sw" link add br0 up type bridge
	add_sw_port "$ex" e0 s-e
	add_sw_port "$a" a0 s-a
	add_sw_port "$r" r0 s-r
	ip link add r1 netns "$r" type veth peer name b0 netns "$b"
	ip -n "$r" link set r1 up
	ip -n "$b" link set b0 up

	ip -n "$ex" addr add 10.0.1.1/24 dev e0
	ip -n "$ex" route add default via 10.0.1.254
	ip -n "$a" addr add 10.0.1.2/24 dev a0
	ip -n "$r" addr add 10.0.1.254/24 dev r0
	ip -n "$r" addr add 10.0.2.254/24 dev r1
	ip netns exec "$r" sysctl -wq net.ipv4.ip_forward=1
	ip -n "$b" addr add 10.0.2.2/24 dev b0
	ip -n "$b" route add default via 10.0.2.254

	ip -n "$ex" link add vx0 type vxlan id 42 dstport 4789 \
		local 10.0.1.1 learning
	bridge -n "$ex" fdb append 00:00:00:00:00:00 dev vx0 dst 10.0.1.2
	bridge -n "$ex" fdb append 00:00:00:00:00:00 dev vx0 dst 10.0.2.2
	ip -n "$ex" addr add 192.168.0.1/24 dev vx0
	ip -n "$ex" link set vx0 up

	ip -n "$a" link add vx0 address "$MAC" type vxlan id 42 dstport 4789 \
		local 10.0.1.2 remote 10.0.1.1
	ip -n "$b" link add vx0 address "$MAC" type vxlan id 42 dstport 4789 \
		local 10.0.2.2 remote 10.0.1.1
	ip -n "$a" addr add 192.168.0.10/24 dev vx0
	ip -n "$b" addr add 192.168.0.10/24 dev vx0
	ip -n "$a" link set vx0 up

	ping_from_cpu0 "$ex" 192.168.0.10
	check_err $? "ping before the move failed"

	ip -n "$a" link set vx0 down
	ip -n "$b" link set vx0 up
	ip netns exec "$b" ping -c 1 -W 1 192.168.0.1 &> /dev/null

	bridge -n "$ex" fdb show dev vx0 | grep -q "$MAC dst 10.0.2.2 "
	check_err $? "fdb entry did not move to the new remote"

	ping_from_cpu0 "$ex" 192.168.0.10
	check_err $? "ping after the move failed"

	log_test "IPv4 move to a remote behind a router"
}

test_move_to_link_local()
{
	local ns

	RET=0

	setup_ns sw ex a b
	defer cleanup_ns "$sw" "$ex" "$a" "$b"

	for ns in "$sw" "$ex" "$a" "$b"; do
		ip netns exec "$ns" sysctl -wq net.ipv6.conf.all.accept_dad=0
		ip netns exec "$ns" sysctl -wq net.ipv6.conf.default.accept_dad=0
	done

	ip -n "$sw" link add br0 up type bridge
	add_sw_port "$ex" e0 s-e
	add_sw_port "$a" a0 s-a
	add_sw_port "$b" b0 s-b

	ip -n "$ex" addr add 2001:db8:1::1/64 dev e0 nodad
	ip -n "$ex" addr add fe80::1/64 dev e0 nodad
	ip -n "$a" addr add 2001:db8:1::2/64 dev a0 nodad
	ip -n "$b" addr add fe80::b/64 dev b0 nodad

	ip -n "$ex" link add vx0 type vxlan id 42 dstport 4789 \
		local 2001:db8:1::1 learning
	bridge -n "$ex" fdb append 00:00:00:00:00:00 dev vx0 dst 2001:db8:1::2
	bridge -n "$ex" fdb append 00:00:00:00:00:00 dev vx0 dst fe80::b via e0
	ip -n "$ex" addr add 192.168.0.1/24 dev vx0
	ip -n "$ex" link set vx0 up

	ip -n "$a" link add vx0 address "$MAC" type vxlan id 42 dstport 4789 \
		local 2001:db8:1::2 remote 2001:db8:1::1
	ip -n "$b" link add vx0 address "$MAC" type vxlan id 42 dstport 4789 \
		local fe80::b remote fe80::1 dev b0 nolearning
	ip -n "$a" addr add 192.168.0.10/24 dev vx0
	ip -n "$b" addr add 192.168.0.10/24 dev vx0
	ip -n "$a" link set vx0 up

	ping_from_cpu0 "$ex" 192.168.0.10
	check_err $? "ping before the move failed"

	ip -n "$a" link set vx0 down
	ip -n "$b" link set vx0 up
	ip netns exec "$b" ping -c 1 -W 1 192.168.0.1 &> /dev/null

	bridge -n "$ex" fdb show dev vx0 | grep -q "$MAC dst fe80::b via e0 "
	check_err $? "fdb entry did not move to the new remote and interface"

	ping_from_cpu0 "$ex" 192.168.0.10
	check_err $? "ping after the move failed"

	log_test "IPv6 move from a global to a link-local remote"
}

cleanup()
{
	defer_scopes_cleanup
}

require_command taskset

trap cleanup EXIT
tests_run

exit "$EXIT_STATUS"
