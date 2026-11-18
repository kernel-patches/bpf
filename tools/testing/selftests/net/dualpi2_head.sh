#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Check DualPI2 head timestamps after changing queue limits.
# HFSC with only ls/ul curves holds packets without peeking into DualPI2.
# This avoids exercising the separate peeked-packet memory accounting path.

source "$(dirname "$(readlink -e "$0")")/lib.sh"

ALL_TESTS="
	c_dequeue
	l_dequeue
	c_empty_trim
	l_empty_trim
	c_memory_trim
	l_memory_trim
	c_packet_trim
	l_packet_trim
	mixed_empty_trim
	mixed_partial_trim
	no_trim_change
"

TC=$(printenv TC || echo tc)
SENDER="$net_dir/dualpi2_head"
ns=
FAIL_REASON=

skip()
{
	echo "SKIP: $*"
	exit "$ksft_skip"
}

cleanup()
{
	cleanup_all_ns
}

in_ns()
{
	ip netns exec "$ns" "$@"
}

tc_ns()
{
	in_ns "$TC" "$@"
}

fail()
{
	FAIL_REASON="$*"
	return 1
}

setup_queue()
{
	local mode=$1

	tc_ns qdisc del dev dummy0 root >/dev/null 2>&1 || true
	if [[ $mode == slow ]]; then
		tc_ns qdisc add dev dummy0 root handle 1: hfsc default 1 || return 1
		tc_ns class add dev dummy0 parent 1: classid 1:1 \
			hfsc ls m2 8bit ul m2 8bit || return 1
		tc_ns qdisc add dev dummy0 parent 1:1 handle 10: dualpi2 \
			limit 1000 memlimit 1048576 target 60s no_split_gso || return 1
	else
		tc_ns qdisc add dev dummy0 root handle 10: dualpi2 \
			limit 1000 memlimit 1048576 target 60s no_split_gso || return 1
	fi
}

send_frames()
{
	local bounds

	bounds=$(in_ns "$SENDER" dummy0 "$1" "$2" 1024) ||
		{ fail "packet sender failed"; return 1; }
	read -r SEND_START SEND_END <<< "$bounds"
	[[ $SEND_START =~ ^[0-9]+$ && $SEND_END =~ ^[0-9]+$ ]] ||
		{ fail "invalid sender timestamps"; return 1; }
}

snapshot()
{
	local stats value

	stats=$(in_ns "$SENDER" --stats dummy0) ||
		{ fail "cannot read DualPI2 statistics"; return 1; }
	read -r QLEN MEMORY DELAY_C DELAY_L PKTS_C PKTS_L PROB \
		READ_START READ_END <<< "$stats"
	for value in $stats; do
		[[ $value =~ ^[0-9]+$ ]] ||
			{ fail "invalid numeric statistics"; return 1; }
	done
	[[ -n $READ_END ]] || { fail "incomplete statistics"; return 1; }
	echo "# qlen=$QLEN memory=$MEMORY delays=$DELAY_C/$DELAY_L prob=$PROB"
}

check_counts()
{
	local ecn=$1 expected=$2

	if (( ecn == 0 )); then
		(( PKTS_C == expected && PKTS_L == 0 )) ||
			{ fail "expected C/L counts $expected/0, got $PKTS_C/$PKTS_L"; return 1; }
	else
		(( PKTS_C == 0 && PKTS_L == expected )) ||
			{ fail "expected C/L counts 0/$expected, got $PKTS_C/$PKTS_L"; return 1; }
	fi
}

check_empty()
{
	(( QLEN == 0 && MEMORY == 0 && DELAY_C == 0 && DELAY_L == 0 )) ||
		{ fail "empty queue: qlen=$QLEN memory=$MEMORY delays=$DELAY_C/$DELAY_L"
		  return 1; }
}

wait_empty()
{
	local deadline now

	deadline=$(( $("$SENDER" --now) + 1000000 ))
	while :; do
		snapshot || return 1
		if (( QLEN == 0 )); then
			check_empty
			return $?
		fi
		now=$("$SENDER" --now) || return 1
		(( now < deadline )) || { fail "queue did not drain within 1s"; return 1; }
		sleep 0.01
	done
}

prime_slow_queue()
{
	local ecn=$1

	setup_queue slow || { fail "HFSC fixture setup failed"; return 1; }
	# The first frame transmits; the ul curve holds the next for about 1000s.
	send_frames "$ecn" 1 || return 1
	wait_empty || return 1
	check_counts "$ecn" 1 || return 1
}

normal_dequeue()
{
	local ecn=$1

	setup_queue normal || { fail "DualPI2 setup failed"; return 1; }
	send_frames "$ecn" 4 || return 1
	wait_empty || return 1
	check_counts "$ecn" 4 || return 1
}

full_trim()
{
	local ecn=$1 delay immediate_ok=1 immediate_reason

	prime_slow_queue "$ecn" || return 1
	send_frames "$ecn" 8 || return 1
	sleep 0.2
	snapshot || return 1
	check_counts "$ecn" 9 || return 1
	delay=$DELAY_C
	(( ecn != 0 )) && delay=$DELAY_L
	(( QLEN == 8 && MEMORY > 0 && delay >= 150000 )) ||
		{ fail "fixture did not retain eight aged packets"; return 1; }
	tc_ns qdisc change dev dummy0 parent 1:1 handle 10: dualpi2 memlimit 1 ||
		{ fail "memory limit change failed"; return 1; }
	snapshot || return 1
	if ! check_empty; then
		immediate_ok=0
		immediate_reason=$FAIL_REASON
	fi
	sleep 0.2
	snapshot || return 1
	check_empty || return 1
	check_counts "$ecn" 9 || return 1
	(( immediate_ok )) || { fail "$immediate_reason"; return 1; }
}

check_head_delay()
{
	local ecn=$1 start=$2 end=$3 low high delay

	(( READ_END >= READ_START && READ_END - READ_START < 100000 )) ||
		{ fail "statistics observation exceeded 100ms"; return 1; }
	# Both kernel enqueue and xstats sampling use CLOCK_MONOTONIC.
	# Allow 2ms around the userspace bounds. Callers age retained packets
	# for at least 20ms, so resetting a nonempty queue timestamp cannot pass.
	low=$(( READ_START - end - 2000 ))
	high=$(( READ_END - start + 2000 ))
	(( low > 0 )) || { fail "retained packets were not aged enough"; return 1; }
	delay=$DELAY_C
	(( ecn != 0 )) && delay=$DELAY_L
	echo "# expected head delay $low..$high us; observed $delay us"
	(( delay >= low && delay <= high )) ||
		{ fail "head delay $delay outside enqueue bounds $low..$high"; return 1; }
}

partial_trim()
{
	local ecn=$1 trim_kind=$2 start end budget

	prime_slow_queue "$ecn" || return 1
	send_frames "$ecn" 6 || return 1
	sleep 0.2
	send_frames "$ecn" 4 || return 1
	start=$SEND_START
	end=$SEND_END
	snapshot || return 1
	check_counts "$ecn" 11 || return 1
	(( QLEN == 10 && MEMORY > 0 && MEMORY % 10 == 0 )) ||
		{ fail "fixture did not retain ten equal-sized packets"; return 1; }
	budget=$(( MEMORY / 10 * 4 ))
	if [[ $trim_kind == memory ]]; then
		tc_ns qdisc change dev dummy0 parent 1:1 handle 10: dualpi2 \
			memlimit "$budget" || { fail "memory trim failed"; return 1; }
	else
		# Explicit memlimit avoids the automatic cap derived from limit.
		tc_ns qdisc change dev dummy0 parent 1:1 handle 10: dualpi2 \
			limit 4 memlimit 1048576 || { fail "packet trim failed"; return 1; }
	fi
	sleep 0.02
	snapshot || return 1
	(( QLEN == 4 && MEMORY == budget )) ||
		{ fail "trim: qlen=$QLEN memory=$MEMORY expected memory=$budget"; return 1; }
	check_head_delay "$ecn" "$start" "$end" || return 1
	if (( ecn == 0 )); then
		(( DELAY_L == 0 )) || { fail "unused L queue has delay"; return 1; }
	else
		(( DELAY_C == 0 )) || { fail "unused C queue has delay"; return 1; }
	fi
	check_counts "$ecn" 11 || return 1
}

mixed_trim()
{
	prime_slow_queue 0 || return 1
	send_frames 0 4 || return 1
	send_frames 1 4 || return 1
	sleep 0.2
	snapshot || return 1
	(( QLEN == 8 && MEMORY > 0 && PKTS_C == 5 && PKTS_L == 4 &&
	   DELAY_C >= 150000 && DELAY_L >= 150000 )) ||
		{ fail "fixture did not retain mixed C/L packets"; return 1; }
	tc_ns qdisc change dev dummy0 parent 1:1 handle 10: dualpi2 memlimit 1 ||
		{ fail "mixed memory trim failed"; return 1; }
	snapshot || return 1
	check_empty || return 1
	(( PKTS_C == 5 && PKTS_L == 4 )) || { fail "mixed counts changed"; return 1; }
}

mixed_partial()
{
	local start end budget

	prime_slow_queue 0 || return 1
	send_frames 0 4 || return 1
	send_frames 1 4 || return 1
	start=$SEND_START
	end=$SEND_END
	sleep 0.2
	snapshot || return 1
	(( QLEN == 8 && MEMORY > 0 && PKTS_C == 5 && PKTS_L == 4 )) ||
		{ fail "fixture did not retain mixed C/L packets"; return 1; }
	budget=$(( MEMORY / 2 ))
	# The change path drains C first, retaining all four L packets.
	tc_ns qdisc change dev dummy0 parent 1:1 handle 10: dualpi2 \
		limit 4 memlimit 1048576 || { fail "mixed packet trim failed"; return 1; }
	sleep 0.02
	snapshot || return 1
	(( QLEN == 4 && MEMORY == budget && DELAY_C == 0 &&
	   PKTS_C == 5 && PKTS_L == 4 )) ||
		{ fail "mixed trim did not drain C and retain L"; return 1; }
	check_head_delay 1 "$start" "$end"
}

change_without_trim()
{
	local c_start c_end l_start l_end memory

	prime_slow_queue 0 || return 1
	send_frames 0 4 || return 1
	c_start=$SEND_START
	c_end=$SEND_END
	send_frames 1 4 || return 1
	l_start=$SEND_START
	l_end=$SEND_END
	snapshot || return 1
	(( QLEN == 8 && MEMORY > 0 && PKTS_C == 5 && PKTS_L == 4 )) ||
		{ fail "fixture did not retain mixed C/L packets"; return 1; }
	memory=$MEMORY
	tc_ns qdisc change dev dummy0 parent 1:1 handle 10: dualpi2 target 120s ||
		{ fail "target change failed"; return 1; }
	sleep 0.02
	snapshot || return 1
	(( QLEN == 8 && MEMORY == memory && PKTS_C == 5 && PKTS_L == 4 )) ||
		{ fail "non-trimming change altered queue contents"; return 1; }
	check_head_delay 0 "$c_start" "$c_end" || return 1
	check_head_delay 1 "$l_start" "$l_end" || return 1
}

run_case()
{
	local label=$1
	shift

	RET=0
	retmsg=
	FAIL_REASON=
	if ! "$@"; then
		check_err 1 "$FAIL_REASON"
	fi
	log_test "$label"
}

c_dequeue() { run_case "C normal dequeue" normal_dequeue 0; }
l_dequeue() { run_case "L normal dequeue" normal_dequeue 1; }
c_empty_trim() { run_case "C trim to empty" full_trim 0; }
l_empty_trim() { run_case "L trim to empty" full_trim 1; }
c_memory_trim() { run_case "C partial memory trim" partial_trim 0 memory; }
l_memory_trim() { run_case "L partial memory trim" partial_trim 1 memory; }
c_packet_trim() { run_case "C partial packet trim" partial_trim 0 packets; }
l_packet_trim() { run_case "L partial packet trim" partial_trim 1 packets; }
mixed_empty_trim() { run_case "Mixed C/L trim to empty" mixed_trim; }
mixed_partial_trim() { run_case "Mixed trim drains C and retains L" mixed_partial; }
no_trim_change() { run_case "Change without trimming" change_without_trim; }

[[ $(id -u) == 0 ]] || skip "requires root"
require_command ip
require_command "$TC"
require_command "$SENDER"

trap cleanup EXIT
setup_ns ns || exit "$ksft_skip"

# Prevent unsolicited IPv6 traffic when dummy0 is brought up. IPv6 is optional.
in_ns sh -c '
	p=/proc/sys/net/ipv6/conf/default/disable_ipv6
	[ ! -e "$p" ] || echo 1 > "$p"
' || exit "$ksft_fail"
ip -n "$ns" link add dummy0 type dummy || skip "requires dummy interface support"
ip -n "$ns" link set dummy0 up || exit "$ksft_fail"
setup_queue slow || skip "requires HFSC, DualPI2 and tc DualPI2 support"

tests_run
exit "$EXIT_STATUS"
