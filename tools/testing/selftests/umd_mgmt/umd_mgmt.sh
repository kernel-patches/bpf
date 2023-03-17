#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2023 Huawei Technologies Duesseldorf GmbH
#
# Author: Roberto Sassu <roberto.sassu@huawei.com>
#
# Script to test the UMD management library.

# Kselftest framework defines: ksft_pass=0, ksft_fail=1, ksft_skip=4
ksft_pass=0
ksft_fail=1
ksft_skip=4

if ! /sbin/modprobe -q sample_mgr; then
	echo "umd_mgmt: module sample_mgr is not found [SKIP]"
	exit $ksft_skip
fi

if [ ! -f /sys/kernel/security/sample_umd ]; then
	echo "umd_mgmt: kernel interface is not found [SKIP]"
	exit $ksft_skip
fi

i=0

while [ $i -lt 500 ]; do
	if ! echo $(( RANDOM % 128 * 1024 )) > /sys/kernel/security/sample_umd; then
		echo "umd_mgmt: test failed"
		exit $ksft_fail
	fi

	if [ $(( i % 50 )) -eq 0 ]; then
		rmmod sample_loader_kmod
	fi

	(( i++ ))
done

exit $ksft_pass
