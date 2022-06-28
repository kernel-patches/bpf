#!/bin/sh

# Kselftest framework requirement - SKIP code is 4.
readonly KSFT_SKIP=4
readonly NS1="ns1-$(mktemp -u XXXXXX)"
readonly NS2="ns2-$(mktemp -u XXXXXX)"

# We need a persistent BPF FS mointpoint. `ip netns exec` prepares a different
# temporary one on each invocation
readonly FS="$(mktemp -d XXXXXX)"
mount -t bpf bpffs ${FS}

cleanup()
{
	if [ "$?" = "0" ]; then
		echo "selftests: test_xdp_meta [PASS]";
	else
		echo "selftests: test_xdp_meta [FAILED]";
	fi

	set +e

	ip netns exec ${NS1} ./test_xdp_meta detach -d veth1 -f ${FS} -m skb 2> /dev/null
	ip netns exec ${NS2} ./test_xdp_meta detach -d veth2 -f ${FS} -m skb 2> /dev/null

	ip link del veth1 2> /dev/null
	ip netns del ${NS1} 2> /dev/null
	ip netns del ${NS2} 2> /dev/null

	umount ${FS}
	rm -fr ${FS}
}

ip link set dev lo xdp off 2>/dev/null > /dev/null
if [ $? -ne 0 ];then
	echo "selftests: [SKIP] Could not run test without the ip xdp support"
	exit $KSFT_SKIP
fi
set -e

ip netns add ${NS1}
ip netns add ${NS2}

trap cleanup 0 2 3 6 9

ip link add veth1 type veth peer name veth2

ip link set veth1 netns ${NS1}
ip link set veth2 netns ${NS2}

ip netns exec ${NS1} ip addr add 10.1.1.11/24 dev veth1
ip netns exec ${NS2} ip addr add 10.1.1.22/24 dev veth2

ip netns exec ${NS1} tc qdisc add dev veth1 clsact
ip netns exec ${NS2} tc qdisc add dev veth2 clsact

ip netns exec ${NS1} tc filter add dev veth1 ingress bpf da obj test_xdp_meta.o sec tc
ip netns exec ${NS2} tc filter add dev veth2 ingress bpf da obj test_xdp_meta.o sec tc

ip netns exec ${NS1} ip link set dev veth1 xdp obj test_xdp_meta.o sec xdp
ip netns exec ${NS2} ip link set dev veth2 xdp obj test_xdp_meta.o sec xdp

ip netns exec ${NS1} ip link set dev veth1 up
ip netns exec ${NS2} ip link set dev veth2 up

ip netns exec ${NS1} ping -c 1 10.1.1.22
ip netns exec ${NS2} ping -c 1 10.1.1.11

#
# Generic metadata part
#

# Cleanup
ip netns exec ${NS1} ip link set dev veth1 xdp off
ip netns exec ${NS2} ip link set dev veth2 xdp off

ip netns exec ${NS1} tc filter del dev veth1 ingress
ip netns exec ${NS2} tc filter del dev veth2 ingress

# Enable metadata generation for every frame
ip netns exec ${NS1} ./test_xdp_meta attach -d veth1 -f ${FS} -m skb -M
ip netns exec ${NS2} ./test_xdp_meta attach -d veth2 -f ${FS} -m skb -M

# Those two must fail: XDP prog drops packets < 128 bytes with metadata
set +e

ip netns exec ${NS1} ping -c 1 10.1.1.22 -W 0.2
if [ "$?" = "0" ]; then
	exit 1
fi
ip netns exec ${NS2} ping -c 1 10.1.1.11 -W 0.2
if [ "$?" = "0" ]; then
	exit 1
fi

set -e

# Enable metadata only for frames >= 128 bytes
ip netns exec ${NS1} ./test_xdp_meta update -d veth1 -f ${FS} -m skb -M 128
ip netns exec ${NS2} ./test_xdp_meta update -d veth2 -f ${FS} -m skb -M 128

# Must succeed
ip netns exec ${NS1} ping -c 1 10.1.1.22
ip netns exec ${NS2} ping -c 1 10.1.1.11
ip netns exec ${NS1} ping -c 1 10.1.1.22 -s 128
ip netns exec ${NS2} ping -c 1 10.1.1.11 -s 128

exit 0
