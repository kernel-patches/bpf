#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# @author:  Rumen Telbizov <telbizov@gmail.com> <rumen.telbizov@menlosecurity.com>
# @created: Wed Jun 23 17:33:19 UTC 2021
# @description:
# Test coverage for bpf_fib_lookup():
#  * IPv4 route match according to ip rule fwmark
#  * IPv6 route match according to ip rule fwmark
#

#
# Global Variables
#
PASS=0
FAIL=0

CYAN='\033[0;36m'
GREEN='\033[0;92m'
RED='\033[0;31m'
NC='\033[0m'

#
# Functions
#
setup() {
    ip netns add ns1
    ip netns add ns2

    ip link add veth1 index 100 type veth peer name veth2 index 200
    ip link set veth1 netns ns1 up
    ip link set veth2 netns ns2 up

    ip netns exec ns1 sysctl net.ipv4.ip_forward=1 >/dev/null
    ip netns exec ns1 sysctl net.ipv6.conf.all.forwarding=1 >/dev/null

    ip netns exec ns1 ip addr  add dev veth1 192.168.0.100/24
    ip netns exec ns2 ip addr  add dev veth2 192.168.0.1/24
    ip netns exec ns2 ip addr  add dev veth2 192.168.0.2/24

    ip netns exec ns1 ip route add default via 192.168.0.1
    ip netns exec ns1 ip route add default via 192.168.0.2 table 2


    ip netns exec ns1 ip -6 addr add dev veth1 fd00::100/64 nodad
    ip netns exec ns2 ip -6 addr add dev veth2 fd00::1/64   nodad
    ip netns exec ns2 ip -6 addr add dev veth2 fd00::2/64   nodad

    ip netns exec ns1 ip -6 route add default via fd00::1
    ip netns exec ns1 ip -6 route add default via fd00::2 table 2

    ip netns exec ns1 ip    rule add prio 2 fwmark 2 lookup 2
    ip netns exec ns1 ip -6 rule add prio 2 fwmark 2 lookup 2

    ip netns exec ns1 tc qdisc  add dev veth1 clsact
}


cleanup() {
    echo > /sys/kernel/debug/tracing/trace
    ip netns del ns1 2>/dev/null
    ip netns del ns2 2>/dev/null
}


test_egress_ipv4_fwmark() {
    echo -e "- Running ${CYAN}${FUNCNAME[0]}${NC}"
    ip netns exec ns1 tc filter del dev veth1 egress
    ip netns exec ns1 tc filter add dev veth1 egress \
	bpf da obj test_bpf_fib_lookup.o sec test_egress_ipv4_fwmark

    echo -n "  * mark 0: "
    echo > /sys/kernel/debug/tracing/trace
    ip netns exec ns1 ping -W 0.1 -c 1 1.2.3.4 >/dev/null
    grep -q '<test_bpf_fib_lookup: test_egress_ipv4_fwmark> fib.ipv4_dst: <c0a80001> mark: <0>' \
        /sys/kernel/debug/tracing/trace
    if [ $? -eq 0 ]; then
        PASS=$(($PASS+1))
        echo -e ${GREEN}"PASS"${NC}
    else
        FAIL=$(($FAIL+1))
        echo -e ${RED}"FAIL"${NC}
    fi

    echo -n "  * mark 2: "
    echo > /sys/kernel/debug/tracing/trace
    ip netns exec ns1 ping -W 0.1 -c 1 1.2.3.4 -m 2 >/dev/null
    grep -q '<test_bpf_fib_lookup: test_egress_ipv4_fwmark> fib.ipv4_dst: <c0a80002> mark: <2>' \
        /sys/kernel/debug/tracing/trace
    if [ $? -eq 0 ]; then
        PASS=$(($PASS+1))
        echo -e ${GREEN}"PASS"${NC}
    else
        FAIL=$(($FAIL+1))
        echo -e ${RED}"FAIL"${NC}
    fi
}


test_egress_ipv6_fwmark() {
    echo -e "- Running ${CYAN}${FUNCNAME[0]}${NC}"
    ip netns exec ns1 tc filter del dev veth1 egress
    ip netns exec ns1 tc filter add dev veth1 egress \
	bpf da obj test_bpf_fib_lookup.o sec test_egress_ipv6_fwmark

    echo -n "  * mark 0: "
    echo > /sys/kernel/debug/tracing/trace
    ip netns exec ns1 ping -6 -W 0.1 -c 1 2000::2000 >/dev/null
    grep -q '<test_bpf_fib_lookup - egress_IPv6> fib.ipv6_dst<0-2>: <fd00:0000:0000>' \
        /sys/kernel/debug/tracing/trace
    rc1=$?
    grep -q '<test_bpf_fib_lookup - egress_IPv6> fib.ipv6_dst<3-5>: <0000:0000:0000>' \
        /sys/kernel/debug/tracing/trace
    rc2=$?
    grep -q '<test_bpf_fib_lookup - egress_IPv6> fib.ipv6_dst<6-7>: <0000:0001> mark: <0>' \
        /sys/kernel/debug/tracing/trace
    rc3=$?
    if [ $rc1 -eq 0 ] && [ $rc2 -eq 0 ] && [ $rc3 -eq 0 ]; then
        PASS=$(($PASS+1))
        echo -e ${GREEN}"PASS"${NC}
    else
        FAIL=$(($FAIL+1))
        echo -e ${RED}"FAIL"${NC}
    fi

    echo -n "  * mark 2: "
    echo > /sys/kernel/debug/tracing/trace
    ip netns exec ns1 ping -6 -W 0.1 -c 1 2000::2000 -m 2 >/dev/null
    grep -q '<test_bpf_fib_lookup - egress_IPv6> fib.ipv6_dst<0-2>: <fd00:0000:0000>' \
        /sys/kernel/debug/tracing/trace
    rc1=$?
    grep -q '<test_bpf_fib_lookup - egress_IPv6> fib.ipv6_dst<3-5>: <0000:0000:0000>' \
        /sys/kernel/debug/tracing/trace
    rc2=$?
    grep -q '<test_bpf_fib_lookup - egress_IPv6> fib.ipv6_dst<6-7>: <0000:0002> mark: <2>' \
        /sys/kernel/debug/tracing/trace
    rc3=$?
    if [ $rc1 -eq 0 ] && [ $rc2 -eq 0 ] && [ $rc3 -eq 0 ]; then
        PASS=$(($PASS+1))
        echo -e ${GREEN}"PASS"${NC}
    else
        FAIL=$(($FAIL+1))
        echo -e ${RED}"FAIL"${NC}
    fi
}

#
# MAIN
#

trap cleanup 0 3 6 2 9
echo "[$(basename $0)] START"

cleanup
setup

test_egress_ipv4_fwmark
test_egress_ipv6_fwmark

cleanup

echo "[$(basename $0)] PASS: $PASS -- FAIL: $FAIL"
if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
