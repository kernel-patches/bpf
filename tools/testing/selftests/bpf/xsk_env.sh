#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2020 Intel Corporation.

. xsk_prereqs.sh

validate_veth_spec_file

VETH0=$(cat ${SPECFILE} | cut -d':' -f 1)
VETH1=$(cat ${SPECFILE} | cut -d':' -f 2 | cut -d',' -f 1)
NS1=$(cat ${SPECFILE} | cut -d':' -f 2 | cut -d',' -f 2)
