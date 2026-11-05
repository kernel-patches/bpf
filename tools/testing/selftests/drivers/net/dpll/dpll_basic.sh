#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Basic DPLL subsystem test. Read-only validation of the device properties
# exposed over netlink. Runs against a hardware DPLL device when one is
# present (or when DPLL_DEV_ID is set), otherwise against a freshly
# created dpllsim device.
#
# Copyright (c) 2026 Red Hat, Inc.

SCRIPTDIR=$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")

source "$SCRIPTDIR/../../../net/lib.sh"
source "$SCRIPTDIR/../lib/sh/dpll_lib.sh"

ALL_TESTS="
	test_device_properties
"

test_device_properties()
{
	local json

	RET=0

	# A device that cannot be queried at all would be reported as one
	# that misses every attribute, so bail out on that first.
	if ! json=$(dpll_device_json "$DPLL_DEV_ID") || [ -z "$json" ]; then
		check_err 1 "device query failed"
		log_test "DPLL device properties"
		return
	fi

	local field
	for field in '.id' '.["module-name"]' '.["clock-id"]' '.type' \
		     '.mode' '.["lock-status"]'; do
		if ! jq -e "$field" <<< "$json" &> /dev/null; then
			check_err 1 "device is missing the $field attribute"
		fi
	done

	log_test "DPLL device properties"
}

##############################################################################

cleanup()
{
	# A second signal must not abort the teardown half way.
	trap '' INT TERM

	if [ -n "$CREATED_DEVICE" ]; then
		dpllsim_delete_device "$CREATED_DEVICE" ||
			log_info "cannot delete device $CREATED_DEVICE"
	fi
	# The device whose creation a signal interrupted is recorded by the
	# library alone, a double delete of a tracked one is harmless.
	if [ -n "$DPLLSIM_CREATED_NAME" ]; then
		dpllsim_delete_device "$DPLLSIM_CREATED_NAME" ||
			log_info "cannot delete device $DPLLSIM_CREATED_NAME"
	fi
	dpll_lib_cleanup
}

dpll_lib_check_prereqs
# Another run would find the devices of this one left behind, see the
# lock in the library.
dpll_lib_lock
dpll_lib_init

CREATED_DEVICE=""
# The module check may mount configfs, so the exit trap that unmounts it
# again has to be in place before. INT and TERM exit through it as well,
# so that a timeout imposed by the harness still removes the device.
trap cleanup EXIT
trap 'exit 1' INT TERM

if [ -z "$DPLL_DEV_ID" ]; then
	dpllsim_check_module
	if ! dpllsim_setup_standard_device; then
		echo "SKIP: cannot create dpllsim device"
		exit "$ksft_skip"
	fi
	CREATED_DEVICE=$DPLLSIM_CREATED_NAME
	DPLL_DEV_ID=$DPLLSIM_DEV_ID
	DPLL_MODULE_NAME="dpllsim"
fi

log_info "testing DPLL device $DPLL_DEV_ID (module $DPLL_MODULE_NAME)"

tests_run

exit $EXIT_STATUS
