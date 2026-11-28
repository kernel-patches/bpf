#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Testing for IPv4 and IPv6 BIG TCP over VXLAN, GENEVE and bareudp tunnels,
# and over ipip, gre, gretap, sit, ip6tnl, ip6gre and ip6gretap tunnels,
# without encapsulation and with FOU and GUE.

source "$(dirname "$0")/lib.sh"

SERVER_NS=$(mktemp -u server-XXXXXXXX)
SERVER_IP4="192.168.1.1"
SERVER_IP6="2001:db8::1:1"
SERVER_IP4_TUN="192.168.2.1"
SERVER_IP6_TUN="2001:db8::2:1"

CLIENT_NS=$(mktemp -u client-XXXXXXXX)
CLIENT_IP4="192.168.1.2"
CLIENT_IP6="2001:db8::1:2"
CLIENT_IP4_TUN="192.168.2.2"
CLIENT_IP6_TUN="2001:db8::2:2"

FOU_PORT=5555

# Kselftest framework requirement - SKIP code is 4.
ksft_skip=4

if [ -z "$PACKETS_THRESHOLD" ]; then
	if [ "$KSFT_MACHINE_SLOW" = yes ]; then
		echo 'Debug kernel detected, lowering the default threshold'
		PACKETS_THRESHOLD=100
	else
		PACKETS_THRESHOLD=1000
	fi
fi

setup() {
	ip netns add "$SERVER_NS"
	ip netns add "$CLIENT_NS"
	ip -netns "$SERVER_NS" link add link1 type veth peer name link0 netns "$CLIENT_NS"

	ip -netns "$CLIENT_NS" link set link0 up
	ip -netns "$CLIENT_NS" addr replace "$CLIENT_IP4/24" dev link0
	ip -netns "$CLIENT_NS" addr replace "$CLIENT_IP6/112" dev link0 nodad
	ip -netns "$CLIENT_NS" link set link0 \
		gso_max_size 196608 gso_ipv4_max_size 196608 \
		gro_max_size 196608 gro_ipv4_max_size 196608
	ip -netns "$SERVER_NS" link set link1 up
	ip -netns "$SERVER_NS" addr replace "$SERVER_IP4/24" dev link1
	ip -netns "$SERVER_NS" addr replace "$SERVER_IP6/112" dev link1 nodad
	ip -netns "$SERVER_NS" link set link1 \
		gso_max_size 196608 gso_ipv4_max_size 196608 \
		gro_max_size 196608 gro_ipv4_max_size 196608

	ip netns exec "$SERVER_NS" netserver >/dev/null
	wait_local_port_listen "$SERVER_NS" 12865 tcp

	DEFAULT_TCP_MIN_TSO_SEGS=$(ip netns exec "$CLIENT_NS" sysctl -n net.ipv4.tcp_min_tso_segs)
}

# Create a bareudp device. bareudp only works in external mode: attach the
# tunnel metadata to all packets sent through the device. Its MTU does not
# account for the encapsulation either, so leave room for IPv6 and UDP
# headers.
# $1: netns, $2: device, $3: local underlay address, $4: remote one
setup_bareudp() {
	ip -netns "$1" link add "$2" type bareudp \
		dstport 6635 ethertype ipv4 multiproto &&
	ip -netns "$1" link set "$2" mtu 1452 &&
	tc -netns "$1" qdisc add dev "$2" clsact &&
	tc -netns "$1" filter add dev "$2" egress matchall \
		action tunnel_key set src_ip "$3" dst_ip "$4" id 0 ttl 64 &&
	return 0

	echo "Failed to set up bareudp device $2" >&2
	return 1
}

# $1: tunnel type, $2: traffic family
# Prints the IP protocol carried by FOU for this tunnel.
fou_ipproto() {
	case "$1" in
	ipip)
		echo 4
		;;
	sit)
		echo 41
		;;
	ip6tnl)
		if [ "$2" = 4 ]; then
			echo 4
		else
			echo 41
		fi
		;;
	*)
		echo 47
		;;
	esac
}

# Create an IP tunnel device, with FOU or GUE encapsulation if requested.
# $1: netns, $2: device, $3: tunnel type, $4: tunnel family,
# $5: traffic family, $6: encapsulation (none, fou or gue),
# $7: local underlay address, $8: remote one
setup_ip_tunnel() {
	local encap_args=()
	local fou_args=()
	local mode=()

	if [ "$4" = 6 ]; then
		fou_args=(-6)
	fi
	if [ "$6" = fou ]; then
		ip -netns "$1" fou add port "$FOU_PORT" \
			ipproto "$(fou_ipproto "$3" "$5")" "${fou_args[@]}" ||
			return 1
	elif [ "$6" = gue ]; then
		ip -netns "$1" fou add port "$FOU_PORT" gue "${fou_args[@]}" ||
			return 1
	fi
	if [ "$6" != none ]; then
		encap_args=(encap "$6" encap-sport auto encap-dport "$FOU_PORT")
		# Check the outer UDP checksum too
		if [ "$4" = 4 ]; then
			encap_args+=(encap-csum)
		else
			encap_args+=(encap-udp6-csum)
		fi
	fi
	if [ "$3" = ip6tnl ]; then
		if [ "$5" = 4 ]; then
			mode=(mode ipip6)
		else
			mode=(mode ip6ip6)
		fi
	fi

	ip -netns "$1" link add "$2" type "$3" "${mode[@]}" \
		local "$7" remote "$8" "${encap_args[@]}"
}

# $1: tunnel type, $2: tunnel family, $3: veth tx csum offload,
# and for IP tunnels: $4: traffic family, $5: encapsulation
setup_tunnel() {
	local name="${1^^}"

	if [ "${5:-none}" != none ]; then
		name="$name/${5^^}"
	fi
	if [ "$2" = 4 ]; then
		SERVER_IP="$SERVER_IP4"
		CLIENT_IP="$CLIENT_IP4"
		echo "Setting up $name over IPv4, veth tx csum offload $3"
	else
		SERVER_IP="$SERVER_IP6"
		CLIENT_IP="$CLIENT_IP6"
		echo "Setting up $name over IPv6, veth tx csum offload $3"
	fi

	case "$1" in
	vxlan)
		ip -netns "$CLIENT_NS" link add tun0 type vxlan \
			id 5001 remote "$SERVER_IP" local "$CLIENT_IP" dev link0 dstport 4789
		;;
	geneve)
		ip -netns "$CLIENT_NS" link add tun0 type geneve \
			id 5001 remote "$SERVER_IP"
		;;
	bareudp)
		setup_bareudp "$CLIENT_NS" tun0 "$CLIENT_IP" "$SERVER_IP" ||
			return 1
		;;
	*)
		setup_ip_tunnel "$CLIENT_NS" tun0 "$1" "$2" "$4" "$5" \
			"$CLIENT_IP" "$SERVER_IP" || return 1
		;;
	esac
	ip -netns "$CLIENT_NS" link set tun0 up
	ip -netns "$CLIENT_NS" addr replace "$CLIENT_IP4_TUN/24" dev tun0
	ip -netns "$CLIENT_NS" addr replace "$CLIENT_IP6_TUN/112" dev tun0 nodad
	ip -netns "$CLIENT_NS" link set tun0 \
		gso_max_size 196608 gso_ipv4_max_size 196608 \
		gro_max_size 196608 gro_ipv4_max_size 196608
	case "$1" in
	vxlan)
		ip -netns "$SERVER_NS" link add tun1 type vxlan \
			id 5001 remote "$CLIENT_IP" local "$SERVER_IP" dev link1 dstport 4789
		;;
	geneve)
		ip -netns "$SERVER_NS" link add tun1 type geneve \
			id 5001 remote "$CLIENT_IP"
		;;
	bareudp)
		setup_bareudp "$SERVER_NS" tun1 "$SERVER_IP" "$CLIENT_IP" ||
			return 1
		;;
	*)
		setup_ip_tunnel "$SERVER_NS" tun1 "$1" "$2" "$4" "$5" \
			"$SERVER_IP" "$CLIENT_IP" || return 1
		;;
	esac
	ip -netns "$SERVER_NS" link set tun1 up
	ip -netns "$SERVER_NS" addr replace "$SERVER_IP4_TUN/24" dev tun1
	ip -netns "$SERVER_NS" addr replace "$SERVER_IP6_TUN/112" dev tun1 nodad
	ip -netns "$SERVER_NS" link set tun1 \
		gso_max_size 196608 gso_ipv4_max_size 196608 \
		gro_max_size 196608 gro_ipv4_max_size 196608

	ip netns exec "$CLIENT_NS" ethtool -K link0 tx-checksumming "$3" > /dev/null
	ip netns exec "$SERVER_NS" ethtool -K link1 tx-checksumming "$3" > /dev/null
}

# For IP tunnels: $1: tunnel family, $2: encapsulation
cleanup_tunnel() {
	local fou_args=()
	local ns

	ip -netns "$CLIENT_NS" link del tun0
	ip -netns "$SERVER_NS" link del tun1
	if [ "${2:-none}" = none ]; then
		return 0
	fi
	if [ "$1" = 6 ]; then
		fou_args=(-6)
	fi
	for ns in "$CLIENT_NS" "$SERVER_NS"; do
		ip -netns "$ns" fou del port "$FOU_PORT" "${fou_args[@]}"
	done
}

cleanup() {
	ip netns pids "$SERVER_NS" | xargs -r kill
	ip netns pids "$CLIENT_NS" | xargs -r kill
	ip netns del "$SERVER_NS"
	ip netns del "$CLIENT_NS"
	rm -rf "$WORKDIR"
}

do_test() {
	local packets_threshold="$PACKETS_THRESHOLD"

	# When tx csum offload is off, software GSO is performed before passing the
	# packet to veth. Check BIG TCP packets inside the tunnel to verify
	# the software checksum path: if the checksum code is broken, these packets
	# will be dropped.
	if [ "$3" = on ]; then
		CAPTURE_IFACE='link'
		if [ "$1" = 4 ]; then
			IPTABLES=iptables
		else
			IPTABLES=ip6tables
		fi
	else
		CAPTURE_IFACE='tun'
		if [ "$2" = 4 ]; then
			IPTABLES=iptables
		else
			IPTABLES=ip6tables
		fi
		packets_threshold=$(( PACKETS_THRESHOLD / 10 ))
	fi
	if [ "$2" = 4 ]; then
		IPTABLES_SACK=iptables
	else
		IPTABLES_SACK=ip6tables
	fi

	if [ "$3" != 'on' ] && [ "$KSFT_MACHINE_SLOW" = yes ]; then
		echo 'Slow configuration; increasing net.ipv4.tcp_min_tso_segs and initcwnd'
		ip netns exec "$CLIENT_NS" sysctl -w net.ipv4.tcp_min_tso_segs=52
		if [ "$2" = 4 ]; then
			ip -netns "$CLIENT_NS" \
			    route change 192.168.2.0/24 dev tun0 initcwnd 100
		else
			ip -netns "$CLIENT_NS" -6 \
			    route change 2001:db8::2:0/112 dev tun0 initcwnd 100 \
			    metric 256
		fi
	else
		ip netns exec "$CLIENT_NS" \
		    sysctl -w net.ipv4.tcp_min_tso_segs="$DEFAULT_TCP_MIN_TSO_SEGS"
	fi

	ip netns exec "$SERVER_NS" "$IPTABLES" -w -t raw -I PREROUTING -i "${CAPTURE_IFACE}1" -m length ! --length 0:65535 -m comment --comment "bigtcp"
	ip netns exec "$CLIENT_NS" "$IPTABLES" -w -t raw -I OUTPUT -o "${CAPTURE_IFACE}0" -m length ! --length 0:65535 -m comment --comment "bigtcp"
	ip netns exec "$SERVER_NS" "$IPTABLES_SACK" -w -t raw -I OUTPUT -o "tun1" -p tcp -m tcp --tcp-flags ACK ACK --tcp-option 5 -m comment --comment "sack"

	if [ "$2" = 4 ]; then
		SERVER_IP="$SERVER_IP4_TUN"
		echo "Running IPv4 traffic in the tunnel"
	else
		SERVER_IP="$SERVER_IP6_TUN"
		echo "Running IPv6 traffic in the tunnel"
	fi

	ip netns exec "$CLIENT_NS" netperf -t TCP_STREAM -l 5 -H "$SERVER_IP" -- \
		-m 80000 > /dev/null

	PACKETS_SERVER=$(ip netns exec "$SERVER_NS" "$IPTABLES-save" -c -t raw | sed -rn '/ --comment bigtcp/{s/^\[([0-9]+):.*/\1/p;q}')
	PACKETS_CLIENT=$(ip netns exec "$CLIENT_NS" "$IPTABLES-save" -c -t raw | sed -rn '/ --comment bigtcp/{s/^\[([0-9]+):.*/\1/p;q}')
	PACKETS_SACK=$(ip netns exec "$SERVER_NS" "$IPTABLES_SACK-save" -c -t raw | sed -rn '/ --comment sack/{s/^\[([0-9]+):.*/\1/p;q}')
	ip netns exec "$SERVER_NS" "$IPTABLES" -w -t raw -D PREROUTING -i "${CAPTURE_IFACE}1" -m length ! --length 0:65535 -m comment --comment "bigtcp"
	ip netns exec "$CLIENT_NS" "$IPTABLES" -w -t raw -D OUTPUT -o "${CAPTURE_IFACE}0" -m length ! --length 0:65535 -m comment --comment "bigtcp"
	ip netns exec "$SERVER_NS" "$IPTABLES_SACK" -w -t raw -D OUTPUT -o "tun1" -p tcp -m tcp --tcp-flags ACK ACK --tcp-option 5 -m comment --comment "sack"

	echo "Captured BIG TCP RX packets: $PACKETS_SERVER"
	echo "Captured BIG TCP TX packets: $PACKETS_CLIENT"
	echo "Captured TCP SACK packets: $PACKETS_SACK"
	[ "$PACKETS_SERVER" -gt "$packets_threshold" ] || return 1
	[ "$PACKETS_CLIENT" -gt "$packets_threshold" ] || return 1
	[ "$PACKETS_SACK" -lt "$(( PACKETS_CLIENT / 2 ))" ] || return 1
}

if ! netperf -V &> /dev/null; then
	echo "SKIP: Could not run test without netperf tool"
	exit "$ksft_skip"
fi

if ! iptables --version &> /dev/null; then
	echo "SKIP: Could not run test without iptables tool"
	exit "$ksft_skip"
fi

if ! tc -V &> /dev/null; then
	echo "SKIP: Could not run test without tc tool"
	exit "$ksft_skip"
fi

if ! ethtool --version &> /dev/null; then
	echo "SKIP: Could not run test without ethtool tool"
	exit "$ksft_skip"
fi

if ! ip link help 2>&1 | grep gso_ipv4_max_size &> /dev/null; then
	echo "SKIP: Could not run test without gso/gro_ipv4_max_size supported in ip-link"
	exit "$ksft_skip"
fi

# $1: tunnel type, $2: tunnel family, $3: traffic family, $4: encapsulation
run_ip_tunnel() {
	local csum_offload

	for csum_offload in on off; do
		# sit does not use gro_cells on receive, so with software GSO
		# on the sender there is nothing big to receive.
		if [ "$1" = sit ] && [ "$csum_offload" = off ]; then
			continue
		fi
		setup_tunnel "$1" "$2" "$csum_offload" "$3" "$4" || exit "$?"
		do_test "$2" "$3" "$csum_offload" || exit "$?"
		cleanup_tunnel "$2" "$4"
	done
}

# fou is not loaded on demand when built as a module
ENCAPS=(none)
if modprobe -q fou && modprobe -q fou6; then
	ENCAPS+=(fou gue)
else
	echo "SKIP: FOU and GUE tests, could not load fou and fou6"
fi

WORKDIR=$(mktemp -d)
trap cleanup EXIT
setup
for tunnel in vxlan geneve bareudp; do
	for tun_family in 4 6; do
		for traffic_family in 4 6; do
			for csum_offload in on off; do
				setup_tunnel "$tunnel" "$tun_family" "$csum_offload" || exit "$?"
				do_test "$tun_family" "$traffic_family" "$csum_offload" || exit "$?"
				cleanup_tunnel
			done
		done
	done
done
for encap in "${ENCAPS[@]}"; do
	run_ip_tunnel ipip 4 4 "$encap"
	for traffic_family in 4 6; do
		run_ip_tunnel gre 4 "$traffic_family" "$encap"
		run_ip_tunnel gretap 4 "$traffic_family" "$encap"
	done
	run_ip_tunnel sit 4 6 "$encap"
	for traffic_family in 4 6; do
		run_ip_tunnel ip6tnl 6 "$traffic_family" "$encap"
		run_ip_tunnel ip6gre 6 "$traffic_family" "$encap"
		run_ip_tunnel ip6gretap 6 "$traffic_family" "$encap"
	done
done
