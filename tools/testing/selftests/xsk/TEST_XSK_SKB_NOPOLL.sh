#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2020 Intel Corporation.

. prereqs.sh
. xskenv.sh

TEST_NAME="SKB NOPOLL"

vethXDPgeneric ${VETH0} ${VETH1} ${NS1}

params=("-S")
execxdpxceiver params

retval=$?
test_status $retval "${TEST_NAME}"

test_exit $retval 0
