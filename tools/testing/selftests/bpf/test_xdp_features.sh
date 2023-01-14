#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# Create 2 namespaces with two veth peers, and
# check reported and detected XDP capabilities
#
#   NS0(v00)              NS1(v11)
#       |                     |
#       |                     |
# (v01, id:111)  ------  (v10,id:222)

readonly NS0="ns1-$(mktemp -u XXXXXX)"
readonly NS1="ns2-$(mktemp -u XXXXXX)"
ret=1

setup() {
	{
		ip netns add ${NS0}
		ip netns add ${NS1}

		ip link add v01 index 111 type veth peer name v00 netns ${NS0}
		ip link add v10 index 222 type veth peer name v11 netns ${NS1}

		ip link set v01 up
		ip addr add 10.10.0.1/24 dev v01
		ip link set v01 address 00:11:22:33:44:55
		ip -n ${NS0} link set dev v00 up
		ip -n ${NS0} addr add 10.10.0.11/24 dev v00
		ip -n ${NS0} route add default via 10.10.0.1
		ip -n ${NS0} link set v00 address 00:12:22:33:44:55

		ip link set v10 up
		ip addr add 10.10.1.1/24 dev v10
		ip link set v10 address 00:13:22:33:44:55
		ip -n ${NS1} link set dev v11 up
		ip -n ${NS1} addr add 10.10.1.11/24 dev v11
		ip -n ${NS1} route add default via 10.10.1.1
		ip -n ${NS1} link set v11 address 00:14:22:33:44:55

		sysctl -w net.ipv4.ip_forward=1
		# Enable XDP mode
		ethtool -K v01 gro on
		ethtool -K v01 tx-checksumming off
		ip netns exec ${NS0} ethtool -K v00 gro on
		ip netns exec ${NS0} ethtool -K v00 tx-checksumming off
		ethtool -K v10 gro on
		ethtool -K v10 tx-checksumming off
		ip netns exec ${NS1} ethtool -K v11 gro on
		ip netns exec ${NS1} ethtool -K v11 tx-checksumming off
	} > /dev/null 2>&1
}

cleanup() {
	ip link del v01 2> /dev/null
	ip link del v10 2> /dev/null
	ip netns del ${NS0} 2> /dev/null
	ip netns del ${NS1} 2> /dev/null
	[ "$(pidof xdp_features)" = "" ] || kill $(pidof xdp_features) 2> /dev/null
}

test_xdp_features() {
	setup

	## XDP_PASS
	ip netns exec ${NS1} ./xdp_features -f XDP_PASS -D 10.10.1.11 -T 10.10.0.11 v11 &
	ip netns exec ${NS0} ./xdp_features -t -f XDP_PASS -D 10.10.1.11 -C 10.10.1.11 -T 10.10.0.11 v00

	[ $? -ne 0 ] && exit

	# XDP_DROP
	ip netns exec ${NS1} ./xdp_features -f XDP_DROP -D 10.10.1.11 -T 10.10.0.11 v11 &
	ip netns exec ${NS0} ./xdp_features -t -f XDP_DROP -D 10.10.1.11 -C 10.10.1.11 -T 10.10.0.11 v00

	[ $? -ne 0 ] && exit

	## XDP_TX
	./xdp_features -f XDP_TX -D 10.10.0.1 -T 10.10.0.11 v01 &
	ip netns exec ${NS0} ./xdp_features -t -f XDP_TX -D 10.10.0.1 -C 10.10.0.1 -T 10.10.0.11 v00

	## XDP_REDIRECT
	ip netns exec ${NS1} ./xdp_features -f XDP_REDIRECT -D 10.10.1.11 -T 10.10.0.11 v11 &
	ip netns exec ${NS0} ./xdp_features -t -f XDP_REDIRECT -D 10.10.1.11 -C 10.10.1.11 -T 10.10.0.11 v00

	[ $? -ne 0 ] && exit

	## XDP_NDO_XMIT
	./xdp_features -f XDP_NDO_XMIT -D 10.10.0.1 -T 10.10.0.11 v01 &
	ip netns exec ${NS0} ./xdp_features -t -f XDP_NDO_XMIT -D 10.10.0.1 -C 10.10.0.1 -T 10.10.0.11 v00

	ret=$?
	cleanup
}

set -e
trap cleanup 2 3 6 9

test_xdp_features

exit $ret
