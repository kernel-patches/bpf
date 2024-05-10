#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

readonly NS0="ns0-$(mktemp -u XXXXXX)"
readonly NS1="ns1-$(mktemp -u XXXXXX)"
readonly infile="$(mktemp)"
readonly outfile="$(mktemp)"

xdp_flowtable_pid=""
ret=1

setup_flowtable() {
nft -f /dev/stdin <<EOF
table inet nat {
	chain postrouting {
		type nat hook postrouting priority filter; policy accept;
		meta oif v10 masquerade
	}
}
table inet filter {
	flowtable ft {
		hook ingress priority filter
		devices = { v01, v10 }
	}
	chain forward {
		type filter hook forward priority filter
		meta l4proto { tcp, udp } flow add @ft
	}
}
EOF
}

setup() {
	sysctl -w net.ipv4.ip_forward=1
	sysctl -w net.ipv6.conf.all.forwarding=1

	ip netns add ${NS0}
	ip netns add ${NS1}

	ip link add v01 type veth peer name v00 netns ${NS0}
	ip link add v10 type veth peer name v11 netns ${NS1}

	ip -n ${NS0} addr add 192.168.0.1/24 dev v00
	ip -6 -n ${NS0} addr add 2001:db8::1/64 dev v00
	ip -n ${NS0} link set dev v00 up
	ip -n ${NS0} route add default via 192.168.0.2
	ip -6 -n ${NS0} route add default via 2001:db8::2

	ip addr add 192.168.0.2/24 dev v01
	ip -6 addr add 2001:db8::2/64 dev v01
	ip link set dev v01 up
	ip addr add 192.168.1.1/24 dev v10
	ip -6 addr add 2001:db8:1::1/64 dev v10
	ip link set dev v10 up

	ip -n ${NS1} addr add 192.168.1.2/24 dev v11
	ip -6 -n ${NS1} addr add 2001:db8:1::2/64 dev v11
	ip -n ${NS1} link set dev v11 up
	ip -n ${NS1} route add default via 192.168.1.1
	ip -6 -n ${NS1} route add default via 2001:db8:1::1

	# Load XDP program
	./xdp_flowtable v01 &
	xdp_flowtable_pid=$!

	setup_flowtable

	dd if=/dev/urandom of="${infile}" bs=8192 count=16 status=none
}

wait_for_nc_server() {
	while sleep 1; do
		ip netns exec ${NS1} ss -nutlp | grep -q ":$1"
		[ $? -eq 0 ] && break
	done
}

cleanup() {
	{
		rm -f "${infile}" "${outfile}"

		nft delete table inet filter
		nft delete table inet nat

		ip link del v01
		ip link del v10

		ip netns del ${NS0}
		ip netns del ${NS1}
	} >/dev/null 2>/dev/null
}

test_xdp_flowtable_lookup() {
	## Run IPv4 test
	ip netns exec ${NS1} nc -4 --no-shutdown -l 8084 > ${outfile} &
	wait_for_nc_server 8084
	ip netns exec ${NS0} timeout 2 nc -4 192.168.1.2 8084 < ${infile}

	## Run IPv6 test
	ip netns exec ${NS1} nc -6 --no-shutdown -l 8086 > ${outfile} &
	wait_for_nc_server 8086
	ip netns exec ${NS0} timeout 2 nc -6 2001:db8:1::2 8086 < ${infile}

	wait $xdp_flowtable_pid && ret=0
}

trap cleanup 0 2 3 6 9
setup

test_xdp_flowtable_lookup

exit $ret
