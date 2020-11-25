#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2020 Intel Corporation, Weqaar Janjua <weqaar.a.janjua@intel.com>

# AF_XDP selftests based on veth
#
# End-to-end AF_XDP over Veth test
#
# Topology:
# ---------
#                 -----------
#               _ | Process | _
#              /  -----------  \
#             /        |        \
#            /         |         \
#      -----------     |     -----------
#      | Thread1 |     |     | Thread2 |
#      -----------     |     -----------
#           |          |          |
#      -----------     |     -----------
#      |  xskX   |     |     |  xskY   |
#      -----------     |     -----------
#           |          |          |
#      -----------     |     ----------
#      |  vethX  | --------- |  vethY |
#      -----------   peer    ----------
#           |          |          |
#      namespaceX      |     namespaceY
#
# AF_XDP is an address family optimized for high performance packet processing,
# it is XDP’s user-space interface.
#
# An AF_XDP socket is linked to a single UMEM which is a region of virtual
# contiguous memory, divided into equal-sized frames.
#
# Refer to AF_XDP Kernel Documentation for detailed information:
# https://www.kernel.org/doc/html/latest/networking/af_xdp.html
#
# Prerequisites setup by script:
#
#   Set up veth interfaces as per the topology shown ^^:
#   * setup two veth interfaces and one namespace
#   ** veth<xxxx> in root namespace
#   ** veth<yyyy> in af_xdp<xxxx> namespace
#   ** namespace af_xdp<xxxx>
#   * create a spec file veth.spec that includes this run-time configuration
#   *** xxxx and yyyy are randomly generated 4 digit numbers used to avoid
#       conflict with any existing interface
#   * tests the veth and xsk layers of the topology
#
# See the source xdpxceiver.c for information on each test
#
# Kernel configuration:
# ---------------------
# See "config" file for recommended kernel config options.
#
# Turn on XDP sockets and veth support when compiling i.e.
# 	Networking support -->
# 		Networking options -->
# 			[ * ] XDP sockets
#
# Executing Tests:
# ----------------
# Must run with CAP_NET_ADMIN capability.
#
# Run (summary only):
#  sudo make summary=1 run_tests
#
# Run (full color-coded output):
#   sudo make colorconsole=1 run_tests
#
# Run (full output without color-coding):
#   sudo make run_tests
#
# Clean:
#  sudo make clean

. xsk_prereqs.sh

TEST_NAME="PREREQUISITES"

URANDOM=/dev/urandom
[ ! -e "${URANDOM}" ] && { echo "${URANDOM} not found. Skipping tests."; test_exit 1 1; }

VETH0_POSTFIX=$(cat ${URANDOM} | tr -dc '0-9' | fold -w 256 | head -n 1 | head --bytes 4)
VETH0=ve${VETH0_POSTFIX}
VETH1_POSTFIX=$(cat ${URANDOM} | tr -dc '0-9' | fold -w 256 | head -n 1 | head --bytes 4)
VETH1=ve${VETH1_POSTFIX}
NS1=af_xdp${VETH1_POSTFIX}
IPADDR_VETH0=192.168.222.1/30
IPADDR_VETH1=192.168.222.2/30
MTU=1500

setup_vethPairs() {
	echo "setting up ${VETH0}: root: ${IPADDR_VETH0}"
	ip netns add ${NS1}
	ip link add ${VETH0} type veth peer name ${VETH1}
	ip addr add dev ${VETH0} ${IPADDR_VETH0}
	echo "setting up ${VETH1}: ${NS1}: ${IPADDR_VETH1}"
	ip link set ${VETH1} netns ${NS1}
	ip netns exec ${NS1} ip addr add dev ${VETH1} ${IPADDR_VETH1}
	ip netns exec ${NS1} ip link set ${VETH1} mtu ${MTU}
	ip netns exec ${NS1} ip link set ${VETH1} up
	ip link set ${VETH0} mtu ${MTU}
	ip link set ${VETH0} up
}

validate_root_exec
validate_veth_support ${VETH0}
validate_configs
setup_vethPairs

retval=$?
if [ $retval -ne 0 ]; then
	test_status $retval "${TEST_NAME}"
	cleanup_exit ${VETH0} ${VETH1} ${NS1}
	exit $retval
fi

echo "${VETH0}:${VETH1},${NS1}" > ${SPECFILE}

echo "Spec file created: ${SPECFILE}"

test_status $retval "${TEST_NAME}"

## START TESTS

. xsk_env.sh
statusList=()

### TEST 1
TEST_NAME="SKB NOPOLL"

vethXDPgeneric ${VETH0} ${VETH1} ${NS1}

params=("-S")
execxdpxceiver params

retval=$?
test_status $retval "${TEST_NAME}"
statusList+=($retval)

### TEST 2
TEST_NAME="SKB POLL"

vethXDPgeneric ${VETH0} ${VETH1} ${NS1}

params=("-S" "-p")
execxdpxceiver params

retval=$?
test_status $retval "${TEST_NAME}"
statusList+=($retval)

## END TESTS

cleanup_exit ${VETH0} ${VETH1} ${NS1}

for _status in "${statusList[@]}"
do
	if [ $_status -ne 0 ]; then
		test_exit $ksft_fail 0
	fi
done

test_exit $ksft_pass 0
