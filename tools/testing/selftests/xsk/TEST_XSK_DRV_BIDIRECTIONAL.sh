#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2020 Intel Corporation.

#Includes
. prereqs.sh
. xskenv.sh

TEST_NAME="DRV BIDIRECTIONAL SOCKETS"

vethXDPnative ${VETH0} ${VETH1} ${NS1}

params=("-N" "-B")
execxdpxceiver params

retval=$?
test_status $retval "${TEST_NAME}"

# Must be called in the last test to execute
cleanup_exit ${VETH0} ${VETH1} ${NS1}

test_exit $retval 0
