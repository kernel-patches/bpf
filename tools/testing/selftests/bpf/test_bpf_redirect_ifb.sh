#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#

# Topology:
# ---------
#      n1 namespace    |     n2 namespace
#                      |
#      -----------     |     ----------------
#      |  veth0  | --------- |  veth1, ifb1 |
#      -----------   peer    ----------------
#

readonly prefix="ns-$$-"
readonly ns1="${prefix}1"
readonly ns2="${prefix}2"
readonly ns1_addr=192.168.1.1
readonly ns2_addr=192.168.1.2

setup() {
	echo "Load ifb module"
	if ! /sbin/modprobe -q -n ifb; then
		echo "test_bpf_redirect ifb: module ifb is not found [SKIP]"
		exit 4
	fi

	modprobe -q ifb numifbs=0

	ip netns add "${ns1}"
	ip netns add "${ns2}"

	ip link add dev veth0 mtu 1500 netns "${ns1}" type veth \
	      peer name veth1 mtu 1500 netns "${ns2}"
	# ifb1 created after veth1
	ip link add dev ifb1 mtu 1500 netns "${ns2}" type ifb

	ip -netns "${ns1}" link set veth0 up
	ip -netns "${ns2}" link set veth1 up
	ip -netns "${ns2}" link set ifb1 up
	ip -netns "${ns1}" -4 addr add "${ns1_addr}/24" dev veth0
	ip -netns "${ns2}" -4 addr add "${ns2_addr}/24" dev veth1

	ip netns exec "${ns2}" tc qdisc add dev veth1 clsact
}

cleanup() {
	ip netns del "${ns2}" &>/dev/null
	ip netns del "${ns1}" &>/dev/null
	modprobe -r ifb
}

trap cleanup EXIT

setup

ip netns exec "${ns2}" tc filter add dev veth1 \
	ingress bpf direct-action obj test_bpf_redirect_ifb.o sec redirect_ifb
ip netns exec "${ns1}" ping -W 2 -c 2 -i 0.2 -q "${ns2_addr}" &>/dev/null
if [ $? -ne 0 ]; then
	echo "bpf redirect to ifb on ingress path [FAILED]"
	exit 1
fi

ip netns exec "${ns2}" tc filter del dev veth1 ingress
ip netns exec "${ns2}" tc filter add dev veth1 \
	egress bpf direct-action obj test_bpf_redirect_ifb.o sec redirect_ifb
ip netns exec "${ns1}" ping -W 2 -c 2 -i 0.2 -q "${ns2_addr}" &>/dev/null
if [ $? -ne 0 ]; then
	echo "bpf redirect to ifb on egress path [FAILED]"
	exit 1
fi

echo OK
