#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# This test is for the accept_untracked_na feature to
# enable RFC9131 behaviour. The following is the test-matrix.
# state   drop   accept  fwding                   behaviour
# ------  ----   ------  ------  ----------------------------------------------
# absent     1        X       X  Don't update NC
# absent     0        0       X  Don't update NC
# absent     0        1       0  Don't update NC
# absent     0        1       1  Add a STALE NC entry
# failed     1        X       X  Keep the NC entry in FAILED state
# failed     0        0       X  Keep the NC entry in FAILED state
# failed     0        1       0  Keep the NC entry in FAILED state
# failed     0        1       1  Update the NC entry to STALE
# failed     0        2       1  Update the NC entry to STALE if in-network
# failed     0        2       1  Keep the NC entry FAILED if out-of-network

source lib.sh
ret=0

PAUSE_ON_FAIL=no
PAUSE=no

HOST_INTF="veth-host"
ROUTER_INTF="veth-router"

ROUTER_ADDR="2000:20::1"
HOST_ADDR_IN_NETWORK="2000:20::2"
HOST_ADDR_OUT_OF_NETWORK="2000:21::2"
HOST_ADDR="${HOST_ADDR_IN_NETWORK}"
SUBNET_WIDTH=64
ROUTER_ADDR_WITH_MASK="${ROUTER_ADDR}/${SUBNET_WIDTH}"
HOST_ADDR_WITH_MASK="${HOST_ADDR}/${SUBNET_WIDTH}"

tcpdump_stdout=
tcpdump_stderr=

log_test()
{
	log_test_expected "$1" "$2" "$3"
}

setup()
{
	set -e

	local drop_unsolicited_na=$1
	local accept_untracked_na=$2
	local forwarding=$3

	# Setup two namespaces and a veth tunnel across them.
	# On end of the tunnel is a router and the other end is a host.
	setup_ns HOST_NS ROUTER_NS
	IP_HOST="ip -6 -netns ${HOST_NS}"
	IP_HOST_EXEC="ip netns exec ${HOST_NS}"
	IP_ROUTER="ip -6 -netns ${ROUTER_NS}"
	IP_ROUTER_EXEC="ip netns exec ${ROUTER_NS}"

	${IP_ROUTER} link add ${ROUTER_INTF} type veth \
                peer name ${HOST_INTF} netns ${HOST_NS}

	# Enable IPv6 on both router and host, and configure static addresses.
	# The router here is the DUT
	# Setup router configuration as specified by the arguments.
	# forwarding=0 case is to check that a non-router
	# doesn't add neighbour entries.
        ROUTER_CONF=net.ipv6.conf.${ROUTER_INTF}
	${IP_ROUTER_EXEC} sysctl -qw \
                ${ROUTER_CONF}.forwarding=${forwarding}
	${IP_ROUTER_EXEC} sysctl -qw \
                ${ROUTER_CONF}.drop_unsolicited_na=${drop_unsolicited_na}
	${IP_ROUTER_EXEC} sysctl -qw \
                ${ROUTER_CONF}.accept_untracked_na=${accept_untracked_na}
	${IP_ROUTER_EXEC} sysctl -qw \
                ${ROUTER_CONF}.ndisc_evict_nocarrier=0
	${IP_ROUTER_EXEC} sysctl -qw ${ROUTER_CONF}.disable_ipv6=0
	${IP_ROUTER} addr add ${ROUTER_ADDR_WITH_MASK} dev ${ROUTER_INTF}

	# Turn on ndisc_notify on host interface so that
	# the host sends unsolicited NAs.
	HOST_CONF=net.ipv6.conf.${HOST_INTF}
	${IP_HOST_EXEC} sysctl -qw ${HOST_CONF}.ndisc_notify=1
	${IP_HOST_EXEC} sysctl -qw ${HOST_CONF}.disable_ipv6=0
	${IP_HOST} addr add ${HOST_ADDR_WITH_MASK} dev ${HOST_INTF}

	set +e
}

start_tcpdump() {
	set -e
	tcpdump_stdout=`mktemp`
	tcpdump_stderr=`mktemp`
	${IP_ROUTER_EXEC} timeout 15s \
                tcpdump --immediate-mode -tpni ${ROUTER_INTF} -c 1 \
                "icmp6 && icmp6[0] == 136 && src ${HOST_ADDR}" \
                > ${tcpdump_stdout} 2> /dev/null
	set +e
}

cleanup_tcpdump()
{
	set -e
	[[ ! -z  ${tcpdump_stdout} ]] && rm -f ${tcpdump_stdout}
	[[ ! -z  ${tcpdump_stderr} ]] && rm -f ${tcpdump_stderr}
	tcpdump_stdout=
	tcpdump_stderr=
	set +e
}

cleanup()
{
	cleanup_tcpdump
	ip netns del ${HOST_NS}
	ip netns del ${ROUTER_NS}
}

link_up() {
	set -e
	${IP_ROUTER} link set dev ${ROUTER_INTF} up
	${IP_HOST} link set dev ${HOST_INTF} up
	set +e
}

verify_ndisc() {
	local drop_unsolicited_na=$1
	local accept_untracked_na=$2
	local forwarding=$3
	local initial_state=${4:-absent}
	local same_subnet=${5:-1}
	local neigh_show_output
	local expected_state

	if [ "${drop_unsolicited_na}" -eq 0 ] &&
			[ "${forwarding}" -eq 1 ]; then
		case "${accept_untracked_na}" in
		1)
			expected_state=STALE
			;;
		2)
			[ "${same_subnet}" -eq 1 ] && expected_state=STALE
			;;
		esac
	fi
	if [ -z "${expected_state}" ] &&
			[ "${initial_state}" = "failed" ]; then
		expected_state=FAILED
	fi

	if [ -n "${expected_state}" ]; then
		neigh_show_output=$(${IP_ROUTER} neigh show \
			to "${HOST_ADDR}" dev "${ROUTER_INTF}")
		if [[ " ${neigh_show_output} " != \
				*" ${expected_state} "* ]]; then
			return 1
		fi
		if [ "${initial_state}" = "failed" ]; then
			[[ "${neigh_show_output}" == *"extern_learn"* ]]
		fi
	else
		neigh_show_output=$(${IP_ROUTER} neigh show \
			to "${HOST_ADDR}" dev "${ROUTER_INTF}")
		[[ -z ${neigh_show_output} ]]
	fi
}

test_unsolicited_na_common()
{
	local same_subnet=${5:-1}
	local neigh_show_output

	if [ "${same_subnet}" -eq 1 ]; then
		HOST_ADDR="${HOST_ADDR_IN_NETWORK}"
	else
		HOST_ADDR="${HOST_ADDR_OUT_OF_NETWORK}"
	fi
	HOST_ADDR_WITH_MASK="${HOST_ADDR}/${SUBNET_WIDTH}"

	# Setup the test bed, but keep links down
	setup "$1" "$2" "$3"

	if [ "${4:-absent}" = "failed" ]; then
		if ! ${IP_ROUTER} neigh replace "${HOST_ADDR}" \
				dev "${ROUTER_INTF}" \
				nud failed extern_learn; then
			echo "Unable to create NUD_FAILED neighbor entry"
			return 1
		fi
		neigh_show_output=$(${IP_ROUTER} neigh show \
			to "${HOST_ADDR}" dev "${ROUTER_INTF}")
		if [[ " ${neigh_show_output} " != *" FAILED "* ]]; then
			echo "Unable to verify NUD_FAILED neighbor entry"
			return 1
		fi
		if [[ "${neigh_show_output}" != *"extern_learn"* ]]; then
			echo "Neighbor entry is not externally learned"
			return 1
		fi
	fi

	# Bring the link up, wait for the NA,
	# and add a delay to ensure neighbour processing is done.
	link_up
	start_tcpdump

	# Verify the neighbour table
	verify_ndisc "$1" "$2" "$3" "$4" "${same_subnet}"

}

test_unsolicited_na_combination() {
	local initial_state=${4:-absent}
	local same_subnet=${5:-1}
	local rc

	test_unsolicited_na_common "$1" "$2" "$3" "${initial_state}" \
		"${same_subnet}"
	rc=$?
	test_msg=("test_unsolicited_na: "
		"drop_unsolicited_na=$1 "
		"accept_untracked_na=$2 "
		"forwarding=$3")
	if [ "${initial_state}" = "failed" ]; then
		test_msg+=("initial_state=failed")
	fi
	if [ "$2" -eq 2 ]; then
		test_msg+=("same_subnet=${same_subnet}")
	fi
	log_test "${rc}" 0 "${test_msg[*]}"
	cleanup
}

test_unsolicited_na_combinations() {
	# Args: drop_unsolicited_na accept_untracked_na forwarding
	#       [initial_state] [same_subnet]

	# Expect entry
	test_unsolicited_na_combination 0 1 1

	# Expect no entry
	test_unsolicited_na_combination 0 0 0
	test_unsolicited_na_combination 0 0 1
	test_unsolicited_na_combination 0 1 0
	test_unsolicited_na_combination 1 0 0
	test_unsolicited_na_combination 1 0 1
	test_unsolicited_na_combination 1 1 0
	test_unsolicited_na_combination 1 1 1

	# Expect FAILED entry to become STALE
	test_unsolicited_na_combination 0 1 1 failed
	test_unsolicited_na_combination 0 2 1 failed 1

	# Expect FAILED entry to remain FAILED
	test_unsolicited_na_combination 0 0 1 failed
	test_unsolicited_na_combination 0 1 0 failed
	test_unsolicited_na_combination 1 1 1 failed
	test_unsolicited_na_combination 0 2 1 failed 0
}

###############################################################################
# usage

usage()
{
	cat <<EOF
usage: ${0##*/} OPTS
        -p          Pause on fail
        -P          Pause after each test before cleanup
EOF
}

###############################################################################
# main

while getopts :pPh o
do
	case $o in
		p) PAUSE_ON_FAIL=yes;;
		P) PAUSE=yes;;
		h) usage; exit 0;;
		*) usage; exit 1;;
	esac
done

# make sure we don't pause twice
[ "${PAUSE}" = "yes" ] && PAUSE_ON_FAIL=no

if [ "$(id -u)" -ne 0 ];then
	echo "SKIP: Need root privileges"
	exit $ksft_skip;
fi

if [ ! -x "$(command -v ip)" ]; then
	echo "SKIP: Could not run test without ip tool"
	exit $ksft_skip
fi

if [ ! -x "$(command -v tcpdump)" ]; then
	echo "SKIP: Could not run test without tcpdump tool"
	exit $ksft_skip
fi

# start clean
cleanup &> /dev/null

test_unsolicited_na_combinations

printf "\nTests passed: %3d\n" ${nsuccess}
printf "Tests failed: %3d\n"   ${nfail}

exit $ret
