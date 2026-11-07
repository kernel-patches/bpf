#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# DPLL reference tracking test. With CONFIG_DPLL_REFCNT_TRACKER=y the DPLL
# core tracks device and pin references through ref_tracker; the debugfs
# files dpll_device@<ptr> / dpll_pin@<ptr> list the stack traces of
# currently unreleased references. This test records the entries that
# exist before it starts, registers dpllsim devices and verifies that
# every entry that appeared since is released again after unregistration.
#
# Copyright (c) 2026 Red Hat, Inc.

SCRIPTDIR=$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")

source "$SCRIPTDIR/../../../net/lib.sh"
source "$SCRIPTDIR/../lib/sh/dpll_lib.sh"

ALL_TESTS="
	test_ref_tracker_probe
	test_basic_reftrack
	test_final_leak_check
"

CREATED_DEVICE=""

# The device stays recorded when its removal fails, so that the cleanup
# handler tries again.
destroy_device()
{
	[ -n "$CREATED_DEVICE" ] || return 0

	dpllsim_delete_device "$CREATED_DEVICE" || return 1
	CREATED_DEVICE=""
}

cleanup()
{
	# A second signal must not abort the teardown half way.
	trap '' INT TERM

	defer_scopes_cleanup
	destroy_device || log_info "cannot delete device $CREATED_DEVICE"
	# The device whose creation a signal interrupted is recorded by the
	# library alone, a double delete of a tracked one is harmless.
	if [ -n "$DPLLSIM_CREATED_NAME" ]; then
		dpllsim_delete_device "$DPLLSIM_CREATED_NAME" ||
			log_info "cannot delete device $DPLLSIM_CREATED_NAME"
	fi
	if [ -n "$DPLLSIM_PROBE_DEVICE" ]; then
		dpllsim_delete_device "$DPLLSIM_PROBE_DEVICE" ||
			log_info "cannot delete device $DPLLSIM_PROBE_DEVICE"
	fi
	[ -n "$REF_SNAPSHOT" ] && rm -f "$REF_SNAPSHOT"
	dpll_lib_cleanup
}

##############################################################################

# Probe for the reference tracker and record the entries that exist
# before the first test that creates devices, so that every entry that
# appears from here on is attributed to this script. A probe device
# that cannot be created says nothing about the tracker, the simulator
# is broken. A probe device whose references do not drain is the kind
# of leak the tests look for, found before the first test. One that
# cannot be deleted is a failure too, it stays recorded for the cleanup
# handler to try again. The tests skip when REF_TRACKER is 0 afterwards.
test_ref_tracker_probe()
{
	RET=0

	REF_TRACKER=0
	if ! dpll_debugfs_available || ! [ -d "$DPLL_REF_TRACKER_DIR" ]; then
		log_test_skip "DPLL ref_tracker probe" \
			      "ref_tracker debugfs not available"
		return
	fi

	# The snapshot file doubles as the scratch file of the probe, so
	# it is needed before anything is recorded.
	if ! REF_SNAPSHOT=$(dpll_ref_tracker_snapshot_file); then
		check_err 1 "cannot create a temporary file for the snapshot"
		log_test "DPLL ref_tracker probe"
		return
	fi

	dpll_ref_tracker_probe "$REF_SNAPSHOT"
	case $? in
	0)
		REF_TRACKER=1
		;;
	1)
		log_test_skip "DPLL ref_tracker probe" \
			      "CONFIG_DPLL_REFCNT_TRACKER not enabled"
		return
		;;
	3)
		REF_TRACKER=1
		check_err 1 "references of the probe device not released"
		;;
	4)
		check_err 1 "cannot delete the dpllsim probe device"
		;;
	*)
		check_err 1 "cannot create dpllsim probe device"
		;;
	esac
	dpll_ref_tracker_snapshot "$REF_SNAPSHOT"

	log_test "DPLL ref_tracker probe"
}

test_basic_reftrack()
{
	RET=0

	if [ "$REF_TRACKER" -eq 0 ]; then
		log_test_skip "DPLL basic reference tracking" \
			      "DPLL reference tracker not available"
		return
	fi

	if ! dpllsim_setup_standard_device; then
		check_err 1 "cannot create dpllsim device"
		log_test "DPLL basic reference tracking"
		return
	fi
	CREATED_DEVICE=$DPLLSIM_CREATED_NAME

	destroy_device
	check_err $? "cannot delete device $CREATED_DEVICE"

	if ! dpll_device_wait_gone_by_clock_id "$DPLLSIM_CLOCK_ID" dpllsim; then
		check_err 1 "device still on netlink after delete"
	fi

	dpll_ref_tracker_check_leaks "$REF_SNAPSHOT"
	check_err $? "leaked references after device removal"

	log_test "DPLL basic reference tracking"
}

test_final_leak_check()
{
	RET=0

	if [ "$REF_TRACKER" -eq 0 ]; then
		log_test_skip "DPLL final ref_tracker check" \
			      "DPLL reference tracker not available"
		return
	fi
	# A device an earlier test could not remove still holds its
	# references, the failure to report is that one.
	if [ -n "$CREATED_DEVICE" ]; then
		log_test_skip "DPLL final ref_tracker check" \
			      "device from an earlier test still present"
		return
	fi

	dpll_ref_tracker_check_leaks "$REF_SNAPSHOT"
	check_err $? "leaked DPLL references at end of test"

	log_test "DPLL final ref_tracker check"
}

##############################################################################

dpll_lib_check_prereqs
# Another run would find the devices of this one left behind and see
# them as leaks, see the lock in the library.
dpll_lib_lock

REF_SNAPSHOT=""
REF_TRACKER=0
# The module check and the probe test may mount configfs and debugfs, so
# the exit trap that unmounts them again has to be in place before. INT
# and TERM exit through it as well, so that a timeout imposed by the
# harness still removes the device.
trap cleanup EXIT
trap 'exit 1' INT TERM
dpllsim_check_module

tests_run

exit $EXIT_STATUS
