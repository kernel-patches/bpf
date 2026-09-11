#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

source lib.sh

cleanup()
{
	cleanup_ns "$NS"
}

trap cleanup EXIT

require_command ip
setup_ns NS || exit $?

ip -n "$NS" -6 address add 2001:db8:1::1/128 dev lo nodad
ip -n "$NS" -6 address add 2001:db8:3::1/128 dev lo nodad

if ! ip -n "$NS" -6 route add 2001:db8:10::/64 \
	encap rpl segs 2001:db8:4::1 dev lo 2>/dev/null; then
	echo "SKIP: RPL lightweight tunnel support not available"
	exit $ksft_skip
fi

RET=0
ip -n "$NS" -6 route add 2001:db8:11::/64 \
	encap rpl segs 2001:db8:1::1,2001:db8:3::1 dev lo
check_err $? "Adjacent local addresses were rejected"
log_test "RPL accepts adjacent local addresses"

RET=0
ip -n "$NS" -6 route add 2001:db8:12::/64 \
	encap rpl segs 2001:db8:1::1,2001:db8:2::1,2001:db8:3::1 dev lo \
	2>/dev/null
check_fail $? "Separated local addresses were accepted"
log_test "RPL rejects separated local addresses"

exit $EXIT_STATUS
