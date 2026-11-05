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
	test_ref_tracker_probe
	test_rapid_create_delete
	test_concurrent_workers
	test_pin_state_flooding
	test_max_devices
	test_deploy_cycle
	test_ref_leaks
"

STRESS_ITERATIONS=${STRESS_ITERATIONS:-20}
STRESS_DEVICES=${STRESS_DEVICES:-5}
# The simulator accepts up to 128 pins per device (DPLLSIM_MAX_PINS)
STRESS_PINS_PER_DEVICE=${STRESS_PINS_PER_DEVICE:-10}
STRESS_CONCURRENT_PROCS=${STRESS_CONCURRENT_PROCS:-4}
STRESS_WORKER_ITERATIONS=${STRESS_WORKER_ITERATIONS:-10}

CREATED_DEVICES=()
BACKGROUND_PIDS=()
# Base clock-ids of the workers in flight, their devices are named
# st<base + iteration>
WORKER_BASES=()

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

# Remove whatever a worker started from the given base clock-id left
# behind, which is the device in flight when the worker had to be killed.
# A device that does not exist counts as deleted.
delete_worker_devices()
{
	local base=$1
	local i name

	for i in $(seq 1 "$STRESS_WORKER_ITERATIONS"); do
		name="st$((base + i))"
		dpllsim_delete_device "$name" ||
			log_info "cannot delete device $name"
	done
}

# Return 0 while the process still runs. A process that has exited but
# has not been reaped yet is a zombie, state Z in /proc/<pid>/stat, and
# counts as gone, or a wait on it would spin until the forced kill.
pid_running()
{
	local stat

	kill -0 "$1" 2>/dev/null || return 1
	# The state follows the parenthesized command name, which may
	# contain spaces and parentheses. The ".*" is greedy, so the
	# expression strips everything up to the last ") " of the line, and
	# a ")" inside the name is harmless.
	stat=$(sed 's/^.*) //' "/proc/$1/stat" 2>/dev/null) || return 1
	[ "${stat%% *}" != "Z" ]
}

# Return 0 once none of the given processes runs any more, 1 when some
# still does after about five seconds.
pids_gone()
{
	local i pid alive

	for i in $(seq 1 50); do
		alive=0
		for pid in "$@"; do
			pid_running "$pid" && alive=1
		done
		[ "$alive" -eq 0 ] && return 0
		sleep 0.1
	done
	return 1
}

cleanup()
{
	local pid dev base
	local pids=() shell_jobs=()

	# A second signal must not abort the teardown half way.
	trap '' INT TERM

	# A worker forked right before the signal arrived may not be
	# recorded yet, so the jobs of the shell are taken as well. The
	# jobs builtin reports them from a subshell only when it is the
	# whole command of that subshell.
	mapfile -t shell_jobs < <(jobs -p)
	mapfile -t pids < <(printf '%s\n' "${BACKGROUND_PIDS[@]}" \
				   "${shell_jobs[@]}" | grep . | sort -u)
	for pid in "${pids[@]}"; do
		kill "$pid" 2>/dev/null
	done
	# Give the workers a few seconds to run their exit traps, then
	# force the survivors and give those a few seconds to die. The
	# kernel cannot recycle the pid of a child until it is reaped,
	# which the wait below does, so the forced kill cannot hit a
	# process that reused one. A worker stuck in the kernel does not
	# die of the forced kill before whatever it waits for returns, so
	# only the workers that are gone are waited for, which reaps them,
	# and the teardown goes on without the rest. The removal of what
	# such a worker left behind can then fail or race with it, which
	# is logged like any other failed removal.
	pids_gone "${pids[@]}"
	for pid in "${pids[@]}"; do
		kill -KILL "$pid" 2>/dev/null
	done
	pids_gone "${pids[@]}"
	for pid in "${pids[@]}"; do
		if pid_running "$pid"; then
			log_info "worker $pid did not exit, giving up"
		else
			wait "$pid" 2>/dev/null
		fi
	done

	defer_scopes_cleanup
	for dev in "${CREATED_DEVICES[@]}"; do
		dpllsim_delete_device "$dev" ||
			log_info "cannot delete device $dev"
	done
	for base in "${WORKER_BASES[@]}"; do
		delete_worker_devices "$base"
	done
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
	local i type freq dir prio
	local dirs=(input output)

	dpllsim_create_device "$name" "$clock_id" || return 1

	# Always have at least one plain input pin, then random ones
	if ! dpllsim_add_pin "$name" ext0 ext 10000000 input 1; then
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
		# Only input pins accept a priority
		prio=""
		[ "$dir" = input ] && prio=$((RANDOM % 128))
		if ! dpllsim_add_pin "$name" "pin$i" "$type" "$freq" "$dir" \
				     "$prio"; then
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

# Probe for the reference tracker and record the entries that exist
# before the first test that creates devices, so that the final check
# attributes every entry that appears from here on to this script. A
# probe device that cannot be created says nothing about the tracker,
# the simulator is broken. A probe device whose references do not drain
# is the kind of leak the final check looks for, found before the first
# test. One that cannot be deleted is a failure too, it stays recorded
# for the cleanup handler to try again. REF_TRACKER tells the leak
# check whether the tracker was seen at work.
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

# The exit trap of a worker. The worker runs in a subshell, so
# track_device() cannot reach CREATED_DEVICES of the parent. Remove the
# device in flight from the exit trap instead, or killing the worker
# leaks it. The trap saves the exit status first, so that the removal
# cannot mask a failed iteration, and drops the traps, since bash runs
# the EXIT trap again when a signal handler exits.
worker_exit()
{
	local status=$?

	trap - EXIT TERM INT
	if [ -n "$DPLLSIM_CREATED_NAME" ]; then
		dpllsim_delete_device "$DPLLSIM_CREATED_NAME"
		DPLLSIM_CREATED_NAME=""
	fi
	exit "$status"
}

# Create and delete STRESS_WORKER_ITERATIONS devices with clock-ids
# following the given base, in a subshell. Each worker derives its own
# unique clock-ids from a range reserved for it, so its devices can never
# be confused with those of another worker or of the parent. The parent
# records the base of every worker, so that the device a killed worker
# left behind can be removed by name.
concurrent_worker()
{
	# The workers inherit the state of the generator from the parent
	# and would draw the same pin layouts, so reseed it with the pid of
	# the subshell first.
	RANDOM=$BASHPID
	local base=$1
	local i name failed=0

	trap worker_exit EXIT TERM INT

	for i in $(seq 1 "$STRESS_WORKER_ITERATIONS"); do
		if ! create_stress_device $((base + i)) 3; then
			failed=$((failed + 1))
			continue
		fi
		name=$DPLLSIM_CREATED_NAME
		dpllsim_delete_device "$name" ||
			failed=$((failed + 1))
	done

	[ "$failed" -eq 0 ]
}

test_concurrent_workers()
{
	local pid base failed=0

	RET=0

	for _ in $(seq 1 "$STRESS_CONCURRENT_PROCS"); do
		dpllsim_alloc_clock_id_range $((STRESS_WORKER_ITERATIONS + 1))
		base=$DPLLSIM_CLOCK_ID
		WORKER_BASES+=("$base")
		concurrent_worker "$base" &
		BACKGROUND_PIDS+=($!)
	done

	for pid in "${BACKGROUND_PIDS[@]}"; do
		wait "$pid" || failed=1
	done
	BACKGROUND_PIDS=()

	check_err "$failed" "some concurrent workers failed"

	for base in "${WORKER_BASES[@]}"; do
		delete_worker_devices "$base"
	done
	WORKER_BASES=()

	log_test "DPLL concurrent workers ($STRESS_CONCURRENT_PROCS processes)"
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

test_max_devices()
{
	local i clock_id created=0 visible
	local test_devs=() clock_ids=()

	RET=0

	for i in $(seq 1 "$STRESS_DEVICES"); do
		dpllsim_alloc_clock_id; clock_id=$DPLLSIM_CLOCK_ID
		create_stress_device "$clock_id" \
				     "$STRESS_PINS_PER_DEVICE" || break
		track_device "$DPLLSIM_CREATED_NAME"
		test_devs+=("$DPLLSIM_CREATED_NAME")
		clock_ids+=("$clock_id")
		created=$((created + 1))
	done

	if [ "$created" -lt "$STRESS_DEVICES" ]; then
		check_err 1 "created only $created of $STRESS_DEVICES devices"
	fi

	# Every created device must be visible on netlink.
	visible=0
	for clock_id in "${clock_ids[@]}"; do
		if dpll_device_wait_by_clock_id "$clock_id" dpllsim \
		   > /dev/null; then
			visible=$((visible + 1))
		fi
	done
	if [ "$visible" -ne "$created" ]; then
		check_err 1 "only $visible of $created devices visible"
	fi

	for i in "${test_devs[@]}"; do
		if dpllsim_delete_device "$i"; then
			untrack_device "$i"
		else
			check_err 1 "cannot delete device $i"
		fi
	done

	log_test "DPLL maximum devices ($STRESS_DEVICES devices)"
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

	if ! dpllsim_add_pin "$name" gnss0 gnss 1 input 0 ||
	   ! dpllsim_add_pin "$name" ext0 ext 10000000 input 1 ||
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

test_ref_leaks()
{
	RET=0

	# The probe test found the tracker inactive or could not run.
	if [ "$REF_TRACKER" -eq 0 ]; then
		log_test_skip "DPLL stress ref_tracker check" \
			      "DPLL reference tracker not available"
		return
	fi

	dpll_ref_tracker_check_leaks "$REF_SNAPSHOT"
	check_err $? "leaked DPLL references after stress"

	log_test "DPLL stress ref_tracker check"
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
# harness still removes the devices.
trap cleanup EXIT
trap 'exit 1' INT TERM
dpllsim_check_module

tests_run

exit $EXIT_STATUS
