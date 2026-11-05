#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Basic DPLL subsystem test. Read-only validation of device and pin
# enumeration and of the properties exposed over netlink. Runs against a
# hardware DPLL device when one is present (or when DPLL_DEV_ID is set),
# otherwise against a freshly created dpllsim device.
#
# Copyright (c) 2026 Red Hat, Inc.

SCRIPTDIR=$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")

source "$SCRIPTDIR/../../../net/lib.sh"
source "$SCRIPTDIR/../lib/sh/dpll_lib.sh"

ALL_TESTS="
	test_device_properties
	test_pin_enumeration
	test_pin_properties
	test_pin_state
"

# Fail on every entry of a pin id list that is not a number. The ids are
# taken from the dump as they are, so a pin without one shows up as the
# "null" jq prints for a missing field, not as an empty line. Return 1
# when any entry is invalid.
check_pin_ids()
{
	local id ret=0

	for id in "$@"; do
		if ! [[ "$id" =~ ^[0-9]+$ ]]; then
			check_err 1 "invalid pin id '$id'"
			ret=1
		fi
	done

	return "$ret"
}

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

test_pin_enumeration()
{
	local pin_ids

	RET=0

	mapfile -t pin_ids < <(dpll_pin_get_ids "$DPLL_DEV_ID")
	if [ "${#pin_ids[@]}" -eq 0 ]; then
		dpll_log_test_skip_or_fail "DPLL pin enumeration" \
		    "no pins found"
		return
	fi
	check_pin_ids "${pin_ids[@]}"

	log_test "DPLL pin enumeration (${#pin_ids[@]} pins)"
}

check_pin_properties()
{
	local pin_id=$1
	local json field

	# A pin that cannot be queried at all would be reported as one
	# that misses every attribute, so bail out on that first.
	if ! json=$(dpll_pin_json "$pin_id") || [ -z "$json" ]; then
		check_err 1 "pin $pin_id query failed"
		return
	fi

	# Frequency is optional, a pin without a frequency callback such
	# as a recovered clock pin does not report it.
	for field in '.id' '.type'; do
		if ! jq -e "$field" <<< "$json" &> /dev/null; then
			check_err 1 \
			    "pin $pin_id is missing the $field attribute"
		fi
	done

	# The parent-device nest is not present for all pin types, but when
	# the device under test is in it, that entry must carry the
	# direction. A pin can be registered on more than one device, so
	# match on parent-id instead of taking the first entry.
	if jq -e --argjson dev "$DPLL_DEV_ID" \
		'[.["parent-device"][]? | select(.["parent-id"] == $dev)] |
		 length > 0' <<< "$json" &> /dev/null; then
		if ! jq -e --argjson dev "$DPLL_DEV_ID" \
			'.["parent-device"][]? |
			 select(.["parent-id"] == $dev) | .direction' \
			<<< "$json" &> /dev/null; then
			check_err 1 \
			    "pin $pin_id parent-device is missing direction"
		fi
	fi
}

test_pin_properties()
{
	local pin_ids pin_id

	RET=0

	mapfile -t pin_ids < <(dpll_pin_get_ids "$DPLL_DEV_ID")
	if [ "${#pin_ids[@]}" -eq 0 ]; then
		dpll_log_test_skip_or_fail "DPLL pin properties" "no pins found"
		return
	fi
	if ! check_pin_ids "${pin_ids[@]}"; then
		log_test "DPLL pin properties"
		return
	fi

	for pin_id in "${pin_ids[@]}"; do
		check_pin_properties "$pin_id"
	done

	log_test "DPLL pin properties (${#pin_ids[@]} pins)"
}

test_pin_state()
{
	local pin_id state

	RET=0

	pin_id=$(dpll_pin_find_by_direction "$DPLL_DEV_ID" input | head -1)
	if [ -z "$pin_id" ]; then
		dpll_log_test_skip_or_fail "DPLL pin state" "no input pin"
		return
	fi

	# The pin was found through its parent-device nest for this device
	# and the state is mandatory there, so an empty value is a failed
	# query rather than a state.
	state=$(dpll_pin_get_state "$DPLL_DEV_ID" "$pin_id")
	case "$state" in
	"")
		check_err 1 "cannot read the state of pin $pin_id"
		;;
	connected|disconnected|selectable)
		;;
	*)
		check_err 1 "pin $pin_id reports invalid state '$state'"
		;;
	esac

	log_test "DPLL pin state"
}

##############################################################################

cleanup()
{
	# A second signal must not abort the teardown half way.
	trap '' INT TERM

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
dpll_lib_init

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
	DPLL_DEV_ID=$DPLLSIM_DEV_ID
	DPLL_CREATED_DEVICE=$DPLLSIM_CREATED_NAME
	DPLL_MODULE_NAME="dpllsim"
fi

log_info "testing DPLL device $DPLL_DEV_ID (module $DPLL_MODULE_NAME)"

tests_run

exit $EXIT_STATUS
