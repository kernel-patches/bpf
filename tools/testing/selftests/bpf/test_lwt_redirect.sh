#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# This regression test checks basic lwt redirect functionality,
# making sure the kernel would not crash when redirecting packets
# to a device, regardless its administration state:
#
# 1. redirect to a device egress/ingress should work normally
# 2. redirect to a device egress/ingress should not panic when target is down
# 3. redirect to a device egress/ingress should not panic when target carrier is down
#
# All test setup are simple: redirect ping packet via lwt xmit to cover above
# situations. We do not worry about specific device type, except for the two
# categories of devices that require MAC header and not require MAC header. For
# carrier down situation, we use a vlan device as upper link, and bring down its
# lower device.
#
# Kselftest framework requirement - SKIP code is 4.
ksft_skip=4
BPF_FILE="test_lwt_redirect.bpf.o"
INGRESS_REDIR_IP=2.2.2.2
EGRESS_REDIR_IP=3.3.3.3
INGRESS_REDIR_IP_NOMAC=4.4.4.4
EGRESS_REDIR_IP_NOMAC=5.5.5.5
PASS=0
FAIL=0

readonly NS1="ns1-$(mktemp -u XXXXXX)"

msg="skip all tests:"
if [ $UID != 0 ]; then
	echo $msg please run this as root >&2
	exit $ksft_skip
fi

get_ip_direction()
{
	case $1 in
		$INGRESS_REDIR_IP|$INGRESS_REDIR_IP_NOMAC)
			echo ingress
			;;
		$EGRESS_REDIR_IP|$EGRESS_REDIR_IP_NOMAC)
			echo egress
			;;
		*)
			echo bug
			;;
	esac
}

test_pass()
{
	local testname=$1
	local direction=`get_ip_direction $2`
	shift 2
	echo "Pass: $testname $direction $@"
	PASS=$((PASS + 1))
}

test_fail()
{
	local testname=$1
	local direction=`get_ip_direction $2`
	shift 2
	echo "Fail: $testname $direction $@"
	FAIL=$((FAIL + 1))
}

setup()
{
	ip netns add $NS1

	ip -n $NS1 link set lo up
	ip -n $NS1 link add link_err type dummy
	ip -n $NS1 link add link_w_mac type dummy
	ip -n $NS1 link add link link_w_mac link_upper type vlan id 1
	ip -n $NS1 link add link_wo_mac type gre remote 4.3.2.1 local 1.2.3.4
	ip -n $NS1 link set link_err up
	ip -n $NS1 link set link_w_mac up
	ip -n $NS1 link set link_upper up
	ip -n $NS1 link set link_wo_mac up

	ip -n $NS1 addr add dev lo 1.1.1.1/32

	# link_err is only used to make sure packets are redirected instead of
	# being routed
	ip -n $NS1 route add $INGRESS_REDIR_IP encap bpf xmit \
		obj $BPF_FILE sec redir_ingress dev link_err
	ip -n $NS1 route add $EGRESS_REDIR_IP encap bpf xmit \
		obj $BPF_FILE sec redir_egress dev link_err
	ip -n $NS1 route add $INGRESS_REDIR_IP_NOMAC encap bpf xmit \
		obj $BPF_FILE sec redir_ingress_nomac dev link_err
	ip -n $NS1 route add $EGRESS_REDIR_IP_NOMAC encap bpf xmit \
		obj $BPF_FILE sec redir_egress_nomac dev link_err
}

cleanup_and_summary()
{
	ip netns del $NS1
	echo PASSED:$PASS FAILED:$FAIL
	if [ $FAIL -ne 0 ]; then
		exit 1
	else
		exit 0
	fi
}

test_redirect_normal()
{
	local test_name=${FUNCNAME[0]}
	local link_name=$1
	local link_id=`ip netns exec $NS1 cat /sys/class/net/${link_name}/ifindex`
	local dest=$2

	ip netns exec $NS1 timeout 2 tcpdump -i ${link_name} -c 1 -n -p icmp >/dev/null 2>&1 &
	local jobid=$!
	sleep 1

	# hack: mark indicates the link to redirect to
	ip netns exec $NS1 ping -m $link_id $dest -c 1 -w 1  > /dev/null 2>&1
	wait $jobid

	if [ $? -ne 0 ]; then
		test_fail $test_name $dest $link_name
	else
		test_pass $test_name $dest $link_name
	fi
}

test_redirect_no_panic_on_link_down()
{
	local test_name=${FUNCNAME[0]}
	local link_name=$1
	local link_id=`ip netns exec $NS1 cat /sys/class/net/${link_name}/ifindex`
	local dest=$2

	ip -n $NS1 link set $link_name down
	# hack: mark indicates the link to redirect to
	ip netns exec $NS1 ping -m $link_id $dest -c 1 -w 1 >/dev/null 2>&1

	test_pass $test_name $dest to $link_name
	ip -n $NS1 link set $link_name up
}

test_redirect_no_panic_on_link_carrier_down()
{
	local test_name=${FUNCNAME[0]}
	local link_id=`ip netns exec $NS1 cat /sys/class/net/link_upper/ifindex`
	local dest=$1

	ip -n $NS1 link set link_w_mac down
	# hack: mark indicates the link to redirect to
	ip netns exec $NS1 ping -m $link_id $dest -c 1 -w 1 >/dev/null 2>&1

	test_pass $test_name $dest to link_upper
	ip -n $NS1 link set link_w_mac up
}

setup

echo "Testing lwt redirect to devices requiring MAC header"
for dest in $INGRESS_REDIR_IP $EGRESS_REDIR_IP; do
	test_redirect_normal link_w_mac $dest
	test_redirect_no_panic_on_link_down link_w_mac $dest
	test_redirect_no_panic_on_link_carrier_down $dest
done

echo "Testing lwt redirect to devices not requiring MAC header"
for dest in $INGRESS_REDIR_IP_NOMAC $EGRESS_REDIR_IP_NOMAC; do
	test_redirect_normal link_wo_mac $dest
	test_redirect_no_panic_on_link_down link_wo_mac $dest
done

cleanup_and_summary
