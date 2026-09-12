#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Runtime test for per-service secure_tcp (IP_VS_SVC_F_SECURE_TCP).
#
# Sets up the same 3-namespace topology as ipvs.sh
# but checks the TCP state machine, not data forwarding.  Two
# identical TCP services are added on the same VIP on different ports,
# one is marked secure_tcp, the other is not. For each a bare SYN is
# followed by a bare ACK (no SYN-ACK / no data).  IPVS classifies the
# connection from the flag bits:
#   * normal service:  SYN -> SYN_RECV, ACK -> ESTABLISHED
#   * secure_tcp service:  SYN -> SYN_RECV, ACK -> SYN_RECV
# This test checks that this is the case via `ipvsadm -Lnc`.
#
# Requires root, netns, ipvsadm, nft, and the built helpers
# ipvs_secure_tcp_mln and gen_tcp_probe.

source lib.sh

ret=0
readonly vip="207.175.44.110"
readonly gip="10.0.0.1"
readonly dip="172.16.0.1"
readonly rip="172.16.0.2"
readonly cip="10.0.0.2"
readonly sip="10.0.0.3"
readonly port_secure=8081
readonly port_plain=8080

GREEN='\033[0;92m'
RED='\033[0;31m'
NC='\033[0m'

checktool "ipvsadm -v" "run test without ipvsadm"
checktool "nft --version" "run test without nft"

setup() {
	setup_ns ns0 ns1 ns2

	ip link add veth01 netns "${ns0}" type veth peer name veth10 netns "${ns1}"
	ip link add veth02 netns "${ns0}" type veth peer name veth20 netns "${ns2}"
	ip link add veth12 netns "${ns1}" type veth peer name veth21 netns "${ns2}"

	ip netns exec "${ns0}" ip link set veth01 up
	ip netns exec "${ns0}" ip link set veth02 up
	ip netns exec "${ns0}" ip link add br0 type bridge
	ip netns exec "${ns0}" ip link set veth01 master br0
	ip netns exec "${ns0}" ip link set veth02 master br0
	ip netns exec "${ns0}" ip link set br0 up
	ip netns exec "${ns0}" ip addr add "${cip}/24" dev br0

	ip netns exec "${ns1}" ip link set veth10 up
	ip netns exec "${ns1}" ip addr add "${gip}/24" dev veth10
	ip netns exec "${ns1}" ip link set veth12 up
	ip netns exec "${ns1}" ip addr add "${dip}/24" dev veth12
	ip netns exec "${ns1}" ip link set lo up
	ip netns exec "${ns1}" ip addr add "${vip}/32" dev lo:1
	ip netns exec "${ns1}" sysctl -qw net.ipv4.ip_forward=1

	ip netns exec "${ns2}" ip link set veth20 up
	ip netns exec "${ns2}" ip addr add "${sip}/24" dev veth20
	ip netns exec "${ns2}" ip link set veth21 up
	ip netns exec "${ns2}" ip addr add "${rip}/24" dev veth21

	ip netns exec "${ns2}" ip addr add "${vip}/32" dev lo:1

	ip netns exec "${ns0}" ip route add "${vip}/32" via "${gip}" dev br0

	# load ipvs, then the rr scheduler (separate calls: modprobe treats
	# the second name as a module parameter, not a second module)
	ip netns exec "${ns1}" modprobe ip_vs
	ip netns exec "${ns1}" modprobe ip_vs_rr

	sleep 1
}

cleanup() {
	cleanup_all_ns
}

# State of the connection to the VIP:port, from `ipvsadm -Lnc`.
# Fields: pro  expire  state  source  virtual  destination
conn_state() {
	local vport=$1
	ip netns exec "${ns1}" ipvsadm -Lnc 2>/dev/null |
		awk -v vt="${vip}:${vport}" '$5==vt { print $3; exit }'
}

assert_state() {
	local port=$1 want=$2
	local got
	got="$(conn_state "$port")"
	echo "  vip ${vip}:${port}: state=${got:-?}"
	if [ "${got:-}" != "$want" ]; then
		echo -e "${RED}FAIL${NC}: vip ${vip}:${port} expected state" \
			"${want}, got ${got:-none}"
		ret=1
	fi
}

test_secure() {
	local bin probe

	# Register the two services (secure_tcp on the secure port)
	bin="$(pwd)/ipvs_secure_tcp_mln"
	probe="$(pwd)/gen_tcp_probe"
	ip netns exec "${ns1}" "$bin" add "${vip}" "${port_secure}" secure
	ip netns exec "${ns1}" "$bin" add "${vip}" "${port_plain}" plain

	# Add a real server to both services.  Use NAT (-m): in DR the conn gets
	# IP_VS_CONN_F_NOOUTPUT, which makes the client ACK an INPUT_ONLY event
	# and even tcp_states_dos promotes to ESTABLISHED, hiding the difference.
	ip netns exec "${ns1}" ipvsadm -a -m -t "${vip}:${port_secure}" -r "${rip}:${port_secure}"
	ip netns exec "${ns1}" ipvsadm -a -m -t "${vip}:${port_plain}" -r "${rip}:${port_plain}"

	# verify the flag was actually set
	local got
	got="$(ip netns exec "${ns1}" "$bin" get "${vip}" "${port_secure}")"
	echo "  secured service reports: ${got}"
	echo "${got}" | grep -q "secure_tcp=1" ||
		{ echo -e "${RED}FAIL${NC}: flag not set"; ret=1; }
	got="$(ip netns exec "${ns1}" "$bin" get "${vip}" "${port_plain}")"
	echo "${got}" | grep -q "secure_tcp=0" ||
		{ echo -e "${RED}FAIL${NC}: flag unexpectedly set"; ret=1; }

	# Drop any SYN on the real server so it stays silent (no RST that
	# would interfere with the state-machine observation).
	ip netns exec "${ns2}" nft add table inet filter
	ip netns exec "${ns2}" nft add chain inet filter probe \
		'{ type filter hook input priority 0; }'
	ip netns exec "${ns2}" nft add rule inet filter probe \
		tcp dport '{ '"${port_secure}"', '"${port_plain}"' }' drop

	# Push SYN then ACK to each service from the client
	ip netns exec "${ns0}" "$probe" "${cip}" 40000 "${vip}" "${port_secure}"
	ip netns exec "${ns0}" "$probe" "${cip}" 40001 "${vip}" "${port_plain}"
	sleep 1

	echo "Testing per-service secure_tcp..."
	echo "  --- connection table (ipvsadm -Lnc) ---"
	ip netns exec "${ns1}" ipvsadm -Lnc 2>/dev/null
	echo "  --- end connection table ---"
	assert_state "${port_plain}" ESTABLISHED
	assert_state "${port_secure}" SYN_RECV
}

trap cleanup EXIT

setup
test_secure

if [ "$ret" -ne 0 ]; then
	echo -e "$(basename $0): ${RED}FAIL${NC}"
	exit 1
fi
echo -e "$(basename $0): ${GREEN}PASS${NC}"
exit 0
