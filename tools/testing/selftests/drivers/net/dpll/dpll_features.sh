#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# DPLL device and pin feature tests. Exercises individual dpll_device_ops
# and dpll_pin_ops callbacks, verifying get/set roundtrips through the
# netlink interface. By default a dpllsim device with a known pin layout
# is created; set DPLL_DEV_ID to run against an existing device instead,
# the simulator-only tests then skip unless that device is a dpllsim one.
#
# Copyright (c) 2026 Red Hat, Inc.

SCRIPTDIR=$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")

source "$SCRIPTDIR/../../../net/lib.sh"
source "$SCRIPTDIR/../lib/sh/dpll_lib.sh"

ALL_TESTS="
	test_pin_state_transitions
	test_pin_priority_get_set
"

##############################################################################
# Pin-level feature tests

test_pin_priority_get_set()
{
	local before target after reason candidate

	RET=0

	if [ -z "$PIN_TUNE_ID" ]; then
		dpll_log_test_skip_or_fail "DPLL pin priority set/get" \
		    "no spare input pin"
		return
	fi
	if ! dpll_pin_set_supports prio; then
		log_test_skip "DPLL pin priority set/get" \
		    "dpll tool lacks pin set prio"
		return
	fi
	if ! dpll_pin_has_capability "$PIN_TUNE_ID" priority-can-change; then
		dpll_log_test_skip_or_fail "DPLL pin priority set/get" \
		    "priority cannot change"
		return
	fi

	before=$(dpll_pin_get_prio "$DPLL_DEV_ID" "$PIN_TUNE_ID")
	if [ -z "$before" ]; then
		dpll_log_test_skip_or_fail "DPLL pin priority set/get" \
		    "prio not reported"
		return
	fi
	defer dpll_pin_set_prio "$DPLL_DEV_ID" "$PIN_TUNE_ID" "$before"

	# The accepted range is not advertised, so try one below the current
	# value and then small values, a refusal of all of them is a skip on
	# a device the user provided, the simulator accepts every priority.
	target=""
	for candidate in $((before - 1)) 1 7; do
		[ "$candidate" -ge 0 ] && [ "$candidate" != "$before" ] ||
			continue
		if dpll_pin_set_prio "$DPLL_DEV_ID" "$PIN_TUNE_ID" \
				     "$candidate"; then
			target=$candidate
			break
		fi
		reason=${DPLL_LAST_ERR%%$'\n'*}
	done
	if [ -z "$target" ]; then
		dpll_log_test_skip_or_fail "DPLL pin priority set/get" \
		    "cannot set a new prio${reason:+, $reason}"
		return
	fi
	after=$(dpll_pin_get_prio "$DPLL_DEV_ID" "$PIN_TUNE_ID")
	if [ "$after" != "$target" ]; then
		check_err 1 "priority expected $target, got '$after'"
	fi

	dpll_pin_set_prio "$DPLL_DEV_ID" "$PIN_TUNE_ID" "$before"
	check_err $? "cannot restore pin priority"
	after=$(dpll_pin_get_prio "$DPLL_DEV_ID" "$PIN_TUNE_ID")
	if [ "$after" != "$before" ]; then
		check_err 1 "priority not restored, got '$after'"
	fi

	log_test "DPLL pin priority set/get"
}

test_pin_state_transitions()
{
	local before state after reason

	RET=0

	if [ -z "$PIN_TUNE_ID" ]; then
		dpll_log_test_skip_or_fail "DPLL pin state transitions" \
		    "no spare input pin"
		return
	fi
	if ! dpll_pin_set_supports state; then
		log_test_skip "DPLL pin state transitions" \
		    "dpll tool lacks pin set state"
		return
	fi
	if ! dpll_pin_has_capability "$PIN_TUNE_ID" state-can-change; then
		dpll_log_test_skip_or_fail "DPLL pin state transitions" \
		    "state cannot change"
		return
	fi

	before=$(dpll_pin_get_state "$DPLL_DEV_ID" "$PIN_TUNE_ID")
	if [ -z "$before" ]; then
		dpll_log_test_skip_or_fail "DPLL pin state transitions" \
		    "state not reported"
		return
	fi
	# Restore the original state even when the test aborts half way.
	defer dpll_pin_set_state "$DPLL_DEV_ID" "$PIN_TUNE_ID" "$before"

	# The pin is not connected, see how PIN_TUNE_ID is picked, and the
	# test never connects it, it moves the pin between the disconnected
	# and selectable states only and ends at the original one. A pin
	# that is connected may become the reference the device locks to.
	#
	# A driver may refuse a state the capability promises, for a
	# constraint the interface does not tell. On a device provided by
	# the user that is a skip with the reason the tool reported, on
	# the created device a failure, the simulator accepts both states.
	# The test ends there, whichever set was refused, a state that was
	# not set has nothing to read back and the deferred restore puts
	# the pin back. A refused restore is treated the same way when
	# nothing failed before it, afterwards it is one more failure, a
	# skip would hide the earlier one.
	for state in disconnected selectable; do
		if ! dpll_pin_set_state "$DPLL_DEV_ID" "$PIN_TUNE_ID" \
					"$state"; then
			reason=${DPLL_LAST_ERR%%$'\n'*}
			dpll_log_test_skip_or_fail \
			    "DPLL pin state transitions" \
			    "cannot set pin state to $state${reason:+, $reason}"
			return
		fi
		after=$(dpll_pin_get_state "$DPLL_DEV_ID" "$PIN_TUNE_ID")
		if [ "$after" != "$state" ]; then
			check_err 1 "pin not $state, state '$after'"
		fi
	done

	if ! dpll_pin_set_state "$DPLL_DEV_ID" "$PIN_TUNE_ID" "$before"; then
		reason=${DPLL_LAST_ERR%%$'\n'*}
		reason=${reason:+, $reason}
		if [ "$RET" -eq 0 ]; then
			dpll_log_test_skip_or_fail \
			    "DPLL pin state transitions" \
			    "cannot set pin state to $before$reason"
			return
		fi
		check_err 1 "cannot restore pin state$reason"
	fi
	after=$(dpll_pin_get_state "$DPLL_DEV_ID" "$PIN_TUNE_ID")
	if [ "$after" != "$before" ]; then
		check_err 1 "pin state not restored, got '$after'"
	fi

	log_test "DPLL pin state transitions"
}

##############################################################################

cleanup()
{
	# A second signal must not abort the teardown half way.
	trap '' INT TERM

	# Run the pending restores of an interrupted test first, the device
	# they apply to may be one the user provided.
	defer_scopes_cleanup
	if [ -n "$DPLL_CREATED_DEVICE" ]; then
		dpllsim_delete_device "$DPLL_CREATED_DEVICE" ||
			log_info "cannot delete device $DPLL_CREATED_DEVICE"
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

# The module check may mount configfs, so the exit trap that unmounts it
# again has to be in place before. INT and TERM exit through it as well,
# so that a timeout imposed by the harness still restores the device.
trap cleanup EXIT
trap 'exit 1' INT TERM

if [ -n "${DPLL_DEV_ID:-}" ]; then
	dpll_lib_init
else
	dpllsim_check_module
	if ! dpllsim_setup_standard_device; then
		echo "SKIP: cannot create dpllsim device"
		exit "$ksft_skip"
	fi
	DPLL_DEV_ID=$DPLLSIM_DEV_ID
	DPLL_CREATED_DEVICE=$DPLLSIM_CREATED_NAME
	DPLL_MODULE_NAME="dpllsim"
fi

log_info "testing DPLL device $DPLL_DEV_ID (module $DPLL_MODULE_NAME)"

# PIN_TUNE_ID is the input pin the tests reconfigure. It must not be the
# reference the device is locked to, so it is the first input pin that
# is not connected on the device. When the first dumped input pin and
# another one both qualify the other one is taken, so that the first
# pin, the one a simulated device locks to once it is connected, is left
# alone. Tests that need the pin skip when there is none rather than
# reconfiguring the reference.
pick_tune_pin()
{
	local pin_id state

	PIN_TUNE_ID=""
	for pin_id in "${input_pins[@]}"; do
		state=$(dpll_pin_get_state "$DPLL_DEV_ID" "$pin_id")
		case "$state" in
		disconnected|selectable)
			;;
		*)
			continue
			;;
		esac
		PIN_TUNE_ID=$pin_id
		[ "$pin_id" != "${input_pins[0]}" ] && return
	done
}

mapfile -t input_pins < <(dpll_pin_find_by_direction "$DPLL_DEV_ID" input)
pick_tune_pin

tests_run

exit $EXIT_STATUS
