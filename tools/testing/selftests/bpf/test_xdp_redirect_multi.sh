#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Test topology:
#     - - - - - - - - - - - - - - - - - - - - - - - - -
#    | veth1         veth2         veth3         veth4 |  ... init net
#     - -| - - - - - - | - - - - - - | - - - - - - | - -
#    ---------     ---------     ---------     ---------
#    | veth0 |     | veth0 |     | veth0 |     | veth0 |  ...
#    ---------     ---------     ---------     ---------
#       ns1           ns2           ns3           ns4
#
# Forward maps:
#     map_all has interfaces: veth1, veth2, veth3, veth4, ... (All traffic except IPv4)
#     map_v4 has interfaces: veth1, veth3, veth4, ... (For IPv4 traffic only)
#     map_egress has all interfaces and redirect all pkts
# Map type:
#     map_v4 use DEVMAP, others use DEVMAP_HASH
#
# Test modules:
# XDP modes: generic, native, native + egress_prog
#
# Test cases:
#     ARP:
#        ns1 -> gw: ns2, ns3, ns4 should receive the arp request
#     IPv4:
#        ping test: ns1 -> ns2 (block), ns1 -> ns3 (pass), ns1 -> ns4 (pass)
#     egress_prog:
#        all src mac should be egress interface's mac
#


# netns numbers
NUM=4
IFACES=""
DRV_MODE="xdpgeneric xdpdrv xdpegress"
PASS=0
FAIL=0

test_pass()
{
	echo "Pass: $@"
	PASS=$((PASS + 1))
}

test_fail()
{
	echo "fail: $@"
	FAIL=$((FAIL + 1))
}

clean_up()
{
	for i in $(seq $NUM); do
		ip link del veth$i 2> /dev/null
		ip netns del ns$i 2> /dev/null
	done
}

# Kselftest framework requirement - SKIP code is 4.
check_env()
{
	ip link set dev lo xdpgeneric off &>/dev/null
	if [ $? -ne 0 ];then
		echo "selftests: [SKIP] Could not run test without the ip xdpgeneric support"
		exit 4
	fi

	which tcpdump &>/dev/null
	if [ $? -ne 0 ];then
		echo "selftests: [SKIP] Could not run test without tcpdump"
		exit 4
	fi
}

setup_ns()
{
	local mode=$1
	IFACES=""

	if [ "$mode" = "xdpegress" ]; then
		mode="xdpdrv"
	fi

	for i in $(seq $NUM); do
	        ip netns add ns$i
	        ip link add veth$i type veth peer name veth0 netns ns$i
		ip link set veth$i up
		ip -n ns$i link set veth0 up

		ip -n ns$i addr add 192.0.2.$i/24 dev veth0
		ip -n ns$i addr add 2001:db8::$i/64 dev veth0
		ip -n ns$i link set veth0 $mode obj \
			xdp_dummy.o sec xdp_dummy &> /dev/null || \
			{ test_fail "Unable to load dummy xdp" && exit 1; }
		IFACES="$IFACES veth$i"
		veth_mac[$i]=$(ip link show veth$i | awk '/link\/ether/ {print $2}')
	done
}

do_egress_tests()
{
	local mode=$1

	# mac test
	ip netns exec ns2 tcpdump -e -i veth0 -nn -l -e &> mac_ns1-2_${mode}.log &
	ip netns exec ns3 tcpdump -e -i veth0 -nn -l -e &> mac_ns1-3_${mode}.log &
	ip netns exec ns4 tcpdump -e -i veth0 -nn -l -e &> mac_ns1-4_${mode}.log &
	ip netns exec ns1 ping 192.0.2.254 -c 4 &> /dev/null
	sleep 2
	pkill -9 tcpdump

	# mac check
	grep -q "${veth_mac[2]} > ff:ff:ff:ff:ff:ff" mac_ns1-2_${mode}.log && \
	       test_pass "$mode mac ns1-2" || test_fail "$mode mac ns1-2"
	grep -q "${veth_mac[3]} > ff:ff:ff:ff:ff:ff" mac_ns1-3_${mode}.log && \
		test_pass "$mode mac ns1-3" || test_fail "$mode mac ns1-3"
	grep -q "${veth_mac[4]} > ff:ff:ff:ff:ff:ff" mac_ns1-4_${mode}.log && \
		test_pass "$mode mac ns1-4" || test_fail "$mode mac ns1-4"
}

do_ping_tests()
{
	local mode=$1

	# arp test
	ip netns exec ns2 tcpdump -i veth0 -nn -l -e &> arp_ns1-2_${mode}.log &
	ip netns exec ns3 tcpdump -i veth0 -nn -l -e &> arp_ns1-3_${mode}.log &
	ip netns exec ns4 tcpdump -i veth0 -nn -l -e &> arp_ns1-4_${mode}.log &
	ip netns exec ns1 ping 192.0.2.254 -c 4 &> /dev/null
	sleep 2
	pkill -9 tcpdump
	grep -q "Request who-has 192.0.2.254 tell 192.0.2.1" arp_ns1-2_${mode}.log && \
		test_pass "$mode arp ns1-2" || test_fail "$mode arp ns1-2"
	grep -q "Request who-has 192.0.2.254 tell 192.0.2.1" arp_ns1-3_${mode}.log && \
		test_pass "$mode arp ns1-3" || test_fail "$mode arp ns1-3"
	grep -q "Request who-has 192.0.2.254 tell 192.0.2.1" arp_ns1-4_${mode}.log && \
		test_pass "$mode arp ns1-4" || test_fail "$mode arp ns1-4"

	# ping test
	ip netns exec ns1 ping 192.0.2.2 -c 4 &> /dev/null && \
		test_fail "$mode ping ns1-2" || test_pass "$mode ping ns1-2"
	ip netns exec ns1 ping 192.0.2.3 -c 4 &> /dev/null && \
		test_pass "$mode ping ns1-3" || test_pass "$mode ping ns1-3"
	ip netns exec ns1 ping 192.0.2.4 -c 4 &> /dev/null && \
		test_pass "$mode ping ns1-4" || test_fail "$mode ping ns1-4"
}

do_tests()
{
	local mode=$1
	local drv_p

	case ${mode} in
		xdpdrv)  drv_p="-N";;
		xdpegress) drv_p="-X";;
		xdpgeneric) drv_p="-S";;
	esac

	./xdp_redirect_multi $drv_p $IFACES &> xdp_redirect_${mode}.log &
	xdp_pid=$!
	sleep 10

	if [ "$mode" = "xdpegress" ]; then
		do_egress_tests $mode
	else
		do_ping_tests $mode
	fi

	kill $xdp_pid
}

trap clean_up 0 2 3 6 9

check_env
rm -f xdp_redirect_*.log arp_ns*.log mac_ns*.log

for mode in ${DRV_MODE}; do
	setup_ns $mode
	do_tests $mode
	sleep 10
	clean_up
	sleep 5
done

echo "Summary: PASS $PASS, FAIL $FAIL"
[ $FAIL -eq 0 ] && exit 0 || exit 1
