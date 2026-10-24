#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# SCTP I-FORWARD-TSN handling with user message interleaving (RFC 8260).
#
# TOPO: CLI_NS (veth, 10.0.0.2) <---> (veth, 10.0.0.1) SRV_NS
#
# A large reliable message on stream 0 is sent interleaved with a PR-SCTP
# message on stream 1 that an nft rule in SRV_NS drops, so the sender
# abandons it and sends an I-FORWARD-TSN. The netem delay keeps the sender
# window-limited, so the two messages' fragments interleave. Most of the
# checks are done by sctp_ifwdtsn, see there.

source lib.sh

ALL_TESTS="
	test_ordered
	test_unordered
	test_leading_edge
	test_uo_pd
	test_reset
"

# nft matches on the first chunk of a packet: chunk type at byte 12 of the
# SCTP header, flags at byte 13, I-DATA stream id at byte 20 and FSN at
# byte 28. SCTP_MAXSEG limits fragments to 1000 bytes and GSO is limited
# to the MTU, so no two full-size fragments share a packet.
NFT_SCTP="meta l4proto sctp"
NFT_CHUNK_IDATA="@th,96,8 64"
NFT_CHUNK_IFWDTSN="@th,96,8 194"
NFT_FLAG_B="@th,104,8 & 0x02 == 0x02"
NFT_SID1="@th,160,16 1"
NFT_FSN5="@th,224,32 5"

setup()
{
	setup_ns CLI_NS SRV_NS || return
	defer cleanup_all_ns

	ip -n "$SRV_NS" link add veth0 type veth peer name veth0 \
		netns "$CLI_NS" || return
	ip -n "$SRV_NS" addr add 10.0.0.1/24 dev veth0 || return
	ip -n "$CLI_NS" addr add 10.0.0.2/24 dev veth0 || return
	for ns in "$SRV_NS" "$CLI_NS"; do
		ip -n "$ns" link set veth0 gso_max_size 1500 up || return
		tc -n "$ns" qdisc add dev veth0 root netem delay 50ms || return
		ip netns exec "$ns" sysctl -wq net.sctp.intl_enable=1 \
			net.sctp.prsctp_enable=1 net.sctp.reconf_enable=1 ||
			return
	done
}

# $1: nft rules for the server's input hook (may be empty)
nft_rules()
{
	ip netns exec "$SRV_NS" nft -f - <<-EOF
		table ip sctp_test {
			set blk {
				type ipv4_addr
				flags dynamic
			}
			chain input {
				type filter hook input priority 0;
				$1
			}
		}
	EOF
}

# $1: test name for sctp_ifwdtsn, $2: description, $3: nft rules (optional)
run_helper()
{
	if ! setup || { [ -n "$3" ] && ! nft_rules "$3"; }; then
		log_test_skip "$2"
		return
	fi
	ip netns exec "$SRV_NS" ./sctp_ifwdtsn "$CLI_NS" "$1"
	RET=$?
	[ "$RET" -eq "$ksft_skip" ] || [ "$RET" -eq 0 ] || RET=$ksft_fail
	log_test "$2"
}

# Fragments of the abandoned message must not take fragments of a live
# message below the New Cumulative TSN with them, and the abandoned
# message's own received fragments must be freed.
test_ordered()
{
	run_helper ordered \
		"abandoned message does not purge ordered message" \
		"$NFT_SCTP $NFT_CHUNK_IDATA $NFT_SID1 $NFT_FLAG_B drop"
}

test_unordered()
{
	run_helper unordered \
		"abandoned message does not purge unordered message" \
		"$NFT_SCTP $NFT_CHUNK_IDATA $NFT_SID1 $NFT_FLAG_B drop"
}

# Drop the abandoned message and every packet after it until one starting
# with the I-FORWARD-TSN arrives, so that its New Cumulative TSN is the
# highest TSN received. This must not abort the partial delivery of the
# message on stream 0.
test_leading_edge()
{
	run_helper leading_edge \
		"I-FORWARD-TSN at the highest TSN is not a reset" "
		$NFT_SCTP $NFT_CHUNK_IFWDTSN delete @blk { ip saddr }
		$NFT_SCTP $NFT_CHUNK_IDATA $NFT_SID1 add @blk { ip saddr } drop
		$NFT_SCTP ip saddr @blk drop"
}

# Abandon an unordered message during its partial delivery: the partial
# delivery must be aborted, and the next unordered message on the stream
# must not be appended to it.
test_uo_pd()
{
	run_helper uo_pd "abandoned unordered partial delivery is aborted" \
		"$NFT_SCTP $NFT_CHUNK_IDATA $NFT_SID1 $NFT_FSN5 drop"
}

# An SSN/TSN association reset with interleaving completes and leaves a
# working association.
test_reset()
{
	run_helper reset "association reset with interleaving"
}

require_command nft
require_command tc
modprobe -q sctp
if [ ! -d /proc/net/sctp ]; then
	echo "SKIP: SCTP not available"
	exit "$ksft_skip"
fi

trap defer_scopes_cleanup EXIT

tests_run

exit "$EXIT_STATUS"
