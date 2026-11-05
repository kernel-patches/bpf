#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# DPLL subsystem stress test. Uses dpllsim to exercise rapid device
# registration/unregistration, concurrent operations from multiple
# processes, pin state change flooding and notification load, then
# verifies via ref_tracker that no references leaked.
#
# Copyright (c) 2026 Red Hat, Inc.

SCRIPTDIR=$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")

source "$SCRIPTDIR/../../../net/lib.sh"
source "$SCRIPTDIR/../lib/sh/dpll_lib.sh"

ALL_TESTS="
	test_rapid_create_delete
	test_pin_state_flooding
	test_deploy_cycle
"

STRESS_ITERATIONS=${STRESS_ITERATIONS:-20}

CREATED_DEVICES=()

track_device()
{
	CREATED_DEVICES+=("$1")
}

untrack_device()
{
	local name=$1 dev
	local remaining=()

	for dev in "${CREATED_DEVICES[@]}"; do
		[ "$dev" = "$name" ] || remaining+=("$dev")
	done
	CREATED_DEVICES=("${remaining[@]}")
}

cleanup()
{
	local dev

	# A second signal must not abort the teardown half way.
	trap '' INT TERM

	defer_scopes_cleanup
	for dev in "${CREATED_DEVICES[@]}"; do
		dpllsim_delete_device "$dev" ||
			log_info "cannot delete device $dev"
	done
	# The device whose creation a signal interrupted is recorded by the
	# library alone, a double delete of a tracked one is harmless.
	if [ -n "$DPLLSIM_CREATED_NAME" ]; then
		dpllsim_delete_device "$DPLLSIM_CREATED_NAME" ||
			log_info "cannot delete device $DPLLSIM_CREATED_NAME"
	fi
	dpll_lib_cleanup
}

# Pin type and a frequency the simulator supports for it.
STRESS_PIN_KINDS=(
	"gnss 1"
	"ext 10000000"
	"ext 25000000"
	"synce-eth-port 10000000"
	"int-oscillator 25000000"
	"mux 2048000"
)

# Create a device named after the given clock-id with the given pin count
# and deploy it. Sets DPLLSIM_CREATED_NAME.
create_stress_device()
{
	local clock_id=$1
	local num_pins=$2
	local name="st$clock_id"
	local i type freq dir
	local dirs=(input output)

	dpllsim_create_device "$name" "$clock_id" || return 1

	# Always have at least one plain input pin, then random ones
	if ! dpllsim_add_pin "$name" ext0 ext 10000000 input; then
		dpllsim_delete_device "$name"
		return 1
	fi
	for i in $(seq 1 $((num_pins - 1))); do
		read -r type freq <<< \
			"${STRESS_PIN_KINDS[RANDOM % ${#STRESS_PIN_KINDS[@]}]}"
		# A MUX pin is an input selector, the simulator rejects an
		# output one
		dir=${dirs[RANDOM % 2]}
		[ "$type" = mux ] && dir=input
		if ! dpllsim_add_pin "$name" "pin$i" "$type" "$freq" \
				     "$dir"; then
			dpllsim_delete_device "$name"
			return 1
		fi
	done

	if ! dpllsim_deploy "$name"; then
		dpllsim_delete_device "$name"
		return 1
	fi
}

##############################################################################

test_rapid_create_delete()
{
	local i clock_id name

	RET=0

	for i in $(seq 1 "$STRESS_ITERATIONS"); do
		dpllsim_alloc_clock_id; clock_id=$DPLLSIM_CLOCK_ID

		if ! create_stress_device "$clock_id" 5; then
			check_err 1 "failed to create device (iteration $i)"
			break
		fi
		name=$DPLLSIM_CREATED_NAME
		track_device "$name"

		if ! dpllsim_delete_device "$name"; then
			check_err 1 "failed to delete device (iteration $i)"
			break
		fi
		untrack_device "$name"
	done

	log_test "DPLL rapid create/delete ($STRESS_ITERATIONS iterations)"
}

test_pin_state_flooding()
{
	local clock_id name dev_id pin_id i last state fails=0
	local states=(connected disconnected selectable)

	RET=0

	if ! dpll_pin_set_supports state; then
		log_test_skip "DPLL pin state flooding" \
			      "dpll tool lacks pin set state"
		return
	fi

	dpllsim_alloc_clock_id; clock_id=$DPLLSIM_CLOCK_ID
	if ! create_stress_device "$clock_id" 10; then
		check_err 1 "cannot create device"
		log_test "DPLL pin state flooding"
		return
	fi
	name=$DPLLSIM_CREATED_NAME
	track_device "$name"

	if ! dev_id=$(dpll_device_wait_by_clock_id "$clock_id" dpllsim); then
		check_err 1 "device not visible on netlink"
	else
		pin_id=$(dpll_pin_find_by_direction "$dev_id" input | head -1)
		if [ -z "$pin_id" ]; then
			check_err 1 "no input pin on stress device"
		else
			for i in $(seq 1 50); do
				last=${states[i % 3]}
				dpll_pin_set_state "$dev_id" "$pin_id" \
						   "$last" ||
					fails=$((fails + 1))
			done
			if [ "$fails" -gt 0 ]; then
				check_err 1 "$fails of 50 state changes failed"
			fi
			state=$(dpll_pin_get_state "$dev_id" "$pin_id")
			if [ "$state" != "$last" ]; then
				check_err 1 \
				    "state expected '$last', got '$state'"
			fi
		fi
	fi

	if dpllsim_delete_device "$name"; then
		untrack_device "$name"
	else
		check_err 1 "cannot delete device $name"
	fi

	log_test "DPLL pin state flooding"
}

test_deploy_cycle()
{
	local clock_id name i

	RET=0

	dpllsim_alloc_clock_id; clock_id=$DPLLSIM_CLOCK_ID
	name="cycle$clock_id"
	if ! dpllsim_create_device "$name" "$clock_id"; then
		check_err 1 "cannot create device"
		log_test "DPLL deploy/undeploy cycling"
		return
	fi
	track_device "$name"

	if ! dpllsim_add_pin "$name" gnss0 gnss 1 input ||
	   ! dpllsim_add_pin "$name" ext0 ext 10000000 input ||
	   ! dpllsim_add_pin "$name" out0 ext 10000000 output; then
		check_err 1 "cannot add pins"
		log_test "DPLL deploy/undeploy cycling"
		return
	fi

	for i in $(seq 1 "$STRESS_ITERATIONS"); do
		if ! dpllsim_deploy "$name"; then
			check_err 1 "deploy failed (iteration $i)"
			break
		fi
		if ! dpll_device_wait_by_clock_id "$clock_id" dpllsim \
		     > /dev/null; then
			check_err 1 "device not on netlink (iteration $i)"
			break
		fi
		if ! dpllsim_undeploy "$name"; then
			check_err 1 "undeploy failed (iteration $i)"
			break
		fi
		if ! dpll_device_wait_gone_by_clock_id "$clock_id" dpllsim; then
			check_err 1 "device still on netlink (iteration $i)"
			break
		fi
	done

	if dpllsim_delete_device "$name"; then
		untrack_device "$name"
	else
		check_err 1 "cannot delete device $name"
	fi

	log_test "DPLL deploy/undeploy cycling"
}

##############################################################################

dpll_lib_check_prereqs
# Another run would find the devices of this one left behind, see the
# lock in the library.
dpll_lib_lock

# The module check may mount configfs, so the exit trap that unmounts it
# again has to be in place before. INT and TERM exit through it as well,
# so that a timeout imposed by the harness still removes the devices.
trap cleanup EXIT
trap 'exit 1' INT TERM
dpllsim_check_module

tests_run

exit $EXIT_STATUS
