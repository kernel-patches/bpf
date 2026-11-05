#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Helpers for DPLL selftests. Provides wrappers around the iproute2 dpll
# tool and around the dpllsim configfs interface for creating virtual DPLL
# devices. Sourcing this file has no side effects; call
# dpll_lib_check_prereqs and dpll_lib_init explicitly. net/lib.sh must be
# sourced first, it provides ksft_skip, busywait and log_info to the
# library and defer to the scripts.
#
# Copyright (c) 2026 Red Hat, Inc.
#
# shellcheck disable=SC2034,SC2154 # the globals set here are read by the
# scripts and ksft_skip is defined by net/lib.sh

CONFIGFS_DIR="/sys/kernel/config"
DPLLSIM_CFG="$CONFIGFS_DIR/dpllsim"

# Next clock-id handed out by dpllsim_alloc_clock_id. The lookups of the
# dpllsim helpers match on the module name as well, which is what keeps
# the tests away from the devices of other drivers whatever clock-id
# those use. The random start only avoids collisions between runs, as
# the devices are named after their clock-id in configfs.
DPLLSIM_NEXT_CLOCK_ID=$((96000 + RANDOM))

##############################################################################
# Prerequisites and device selection

dpll_lib_check_prereqs()
{
	if [ "$EUID" -ne 0 ]; then
		echo "SKIP: must be run as root"
		exit "$ksft_skip"
	fi

	local cmd
	for cmd in jq dpll; do
		if ! command -v "$cmd" &> /dev/null; then
			echo "SKIP: $cmd not found"
			exit "$ksft_skip"
		fi
	done

	if ! dpll device help 2>&1 | grep -q "show"; then
		echo "SKIP: dpll tool too old, missing 'device show'"
		exit "$ksft_skip"
	fi
	if ! dpll pin help 2>&1 | grep -q "show"; then
		echo "SKIP: dpll tool too old, missing 'pin show'"
		exit "$ksft_skip"
	fi
}

# The scripts that create dpllsim devices share the one dpllsim directory
# and cannot run alongside each other, so each takes a lock on
# DPLL_LOCK_FILE before it mounts or creates anything and skips when
# another run holds it. The file lives under /run rather than in the
# world-writable /tmp, where a planted symlink could redirect the open.
DPLL_RUN_DIR="/run/dpll-selftest"
DPLL_LOCK_FILE="$DPLL_RUN_DIR/lock"
DPLL_LOCK_FD=""

# Create DPLL_RUN_DIR when it is missing, skip when that fails.
dpll_lib_run_dir()
{
	mkdir -p "$DPLL_RUN_DIR" 2>/dev/null
	if ! [ -d "$DPLL_RUN_DIR" ]; then
		echo "SKIP: cannot create $DPLL_RUN_DIR"
		exit "$ksft_skip"
	fi
}

dpll_lib_lock()
{
	if ! command -v flock &> /dev/null; then
		echo "SKIP: flock not found"
		exit "$ksft_skip"
	fi
	dpll_lib_run_dir
	if ! { exec {DPLL_LOCK_FD}> "$DPLL_LOCK_FILE"; } 2>/dev/null; then
		echo "SKIP: cannot open $DPLL_LOCK_FILE"
		exit "$ksft_skip"
	fi
	if ! flock -n "$DPLL_LOCK_FD"; then
		echo "SKIP: another dpll selftest run is in progress"
		exit "$ksft_skip"
	fi
}

# Print the usage block of the given command of the given object from
# the help of the dpll tool, "dpll pin set" for instance. The help lists
# one usage per command, each starting with "Usage: dpll <obj> <cmd>" or
# with "dpll <obj> <cmd>" indented under the first, possibly wrapped
# over further lines. The block starts at the line that names the
# command, with a space after the name so that a command whose name
# merely begins the same way does not match, and ends before the next
# line that names another command of the object, or at the end of the
# help when none follows. Return 1 when the help has no usage for the
# command, in which case nothing is printed.
__dpll_usage_block()
{
	local obj=$1
	local cmd=$2

	dpll "$obj" help 2>&1 | \
		awk -v start="[[:space:]]dpll $obj $cmd([[:space:]]|$)" \
		    -v other="[[:space:]]dpll $obj [a-z-]+([[:space:]]|$)" \
		    '$0 ~ start { s = 1; print; next }
		     s && $0 ~ other { exit }
		     s { print }
		     END { exit !s }'
}

# Return 0 when the dpll tool knows the given "pin set" keyword, such as
# state or frequency. A test that sets something checks its keyword
# first and skips on a tool that is too old for it. Only the "pin set"
# usage is searched, a keyword that only "pin show" knows must not
# count, and the keyword must stand on its own between blanks or
# brackets, a hyphenated compound that contains it does not count.
dpll_pin_set_supports()
{
	local usage

	usage=$(__dpll_usage_block pin set) || return 1
	grep -qE "(^|[[:space:][])$1([[:space:]]|$)" <<< "$usage"
}

# Detect the DPLL device to test. DPLL_DEV_ID may be set by the user to
# force a specific device; an empty value means auto-detect, which takes
# the first device that is not a dpllsim one, so that an instance of the
# simulator left behind by an earlier run is not mistaken for hardware.
# Sets DPLL_DEV_ID (may end up empty) and DPLL_MODULE_NAME.
dpll_lib_init()
{
	DPLL_MODULE_NAME=""

	if [ -n "${DPLL_DEV_ID:-}" ]; then
		if ! dpll device show id "$DPLL_DEV_ID" &> /dev/null; then
			echo "SKIP: DPLL device \"$DPLL_DEV_ID\" not found"
			exit "$ksft_skip"
		fi
	else
		DPLL_DEV_ID=$(dpll device show -j 2>/dev/null | \
			      jq -r '[.device[]? |
				      select(.["module-name"] != "dpllsim")
				     ][0].id // empty')
	fi

	if [ -n "$DPLL_DEV_ID" ]; then
		DPLL_MODULE_NAME=$(dpll_device_get_module "$DPLL_DEV_ID")
	fi
}

# Name of the dpllsim device a script created as the device under test,
# set by the script next to DPLL_DEV_ID. Empty when the user provided
# the device.
DPLL_CREATED_DEVICE=""

# The layout and the capabilities of the device a script created are
# known, so a missing pin, attribute or capability on it can only mean a
# failed query or broken tooling. Report such a condition as a failure
# on the created device and as a skip on a device the user provided,
# where it is a property of the hardware.
# $1: test name, $2: reason
dpll_log_test_skip_or_fail()
{
	local name=$1
	local reason=$2

	if [ -n "$DPLL_CREATED_DEVICE" ]; then
		check_err 1 "$reason on the device created by the test"
		log_test "$name"
	else
		log_test_skip "$name" "$reason"
	fi
}

##############################################################################
# Device queries
#
# "dpll device show id X -j" may print either a flat object or a dump-style
# {"device":[...]} wrapper depending on the iproute2 version, so normalize
# with (.device[0]? // .) before extracting fields, same for pins. The
# device helpers run the tool first and jq only on what it printed, so
# that a failed query returns its status instead of the empty output a
# missing field produces too.

dpll_device_json()
{
	local dev_id=$1
	local out

	out=$(dpll device show id "$dev_id" -j 2>/dev/null) || return 1
	jq '(.device[0]? // .)' <<< "$out"
}

__dpll_device_field()
{
	local dev_id=$1; shift
	local out

	out=$(dpll device show id "$dev_id" -j 2>/dev/null) || return 1
	jq -r "(.device[0]? // .) | $1 // empty" <<< "$out"
}

dpll_device_get_module()
{
	__dpll_device_field "$1" '.["module-name"]'
}

# Look up the netlink device id by the clock-id chosen at create time,
# restricted to the devices of the given module when one is named. The
# clock-id is the only reliable handle on a device the test created, as
# netlink ids depend on what else exists, and the module name keeps a
# lookup for a dpllsim device from returning a device of another driver
# that happens to use the same clock-id. The clock-id is compared as a
# string, so that it does not matter whether the tool prints it as a
# JSON number or as a string. Return 1 when the dump itself failed, a
# caller must not take that for a device that is gone.
# $1: clock-id, $2: module name (optional)
dpll_device_get_id_by_clock_id()
{
	local clock_id=$1
	local module=${2:-}
	local out

	out=$(dpll device show -j 2>/dev/null) || return 1
	jq -r --arg cid "$clock_id" --arg mod "$module" \
	   '[.device[]? |
	     select((.["clock-id"] | tostring) == $cid and
		    ($mod == "" or .["module-name"] == $mod))
	    ][0].id // empty' <<< "$out"
}

# The two checks below fail when the lookup itself failed, so that a
# failed dump neither counts as a device that is present nor as one
# that is gone, the wait helpers keep polling instead.
__dpll_device_present_by_clock_id()
{
	local dev_id

	dev_id=$(dpll_device_get_id_by_clock_id "$@") || return 1
	[ -n "$dev_id" ] && echo "$dev_id"
}

__dpll_device_absent_by_clock_id()
{
	local dev_id

	dev_id=$(dpll_device_get_id_by_clock_id "$@") || return 1
	[ -z "$dev_id" ]
}

# Wait until a device with the given clock-id (and module, when given) is
# visible on netlink and print its netlink id. Callers must check the
# exit status rather than the output, busywait prints the output of the
# last failed check when it times out.
dpll_device_wait_by_clock_id()
{
	busywait "$BUSYWAIT_TIMEOUT" __dpll_device_present_by_clock_id "$@"
}

dpll_device_wait_gone_by_clock_id()
{
	busywait "$BUSYWAIT_TIMEOUT" __dpll_device_absent_by_clock_id "$@"
}

##############################################################################
# Pin queries
#
# Attributes of the pin itself are read by pin id alone. Attributes that
# live in the parent-device nest (state, prio, ...) take the device id in
# addition, to select the nest of the device under test. The helpers
# that work on the full pin dump normalize its shape like the id-based
# ones do, with (.pin? // [.]), so that a flat object would work too.
# Like the device queries, every helper runs the tool first and jq only
# on what it printed, and returns 1 when the tool failed.

dpll_pin_json()
{
	local pin_id=$1
	local out

	out=$(dpll pin show id "$pin_id" -j 2>/dev/null) || return 1
	jq '(.pin[0]? // .)' <<< "$out"
}

__dpll_pin_field()
{
	local pin_id=$1; shift
	local out

	out=$(dpll pin show id "$pin_id" -j 2>/dev/null) || return 1
	jq -r "(.pin[0]? // .) | $1 // empty" <<< "$out"
}

# Fields living in the parent-device nest matching the given device
__dpll_pin_dev_field()
{
	local dev_id=$1
	local pin_id=$2; shift 2
	local out

	out=$(dpll pin show id "$pin_id" -j 2>/dev/null) || return 1
	jq -r --argjson dev "$dev_id" \
	   "(.pin[0]? // .) | .[\"parent-device\"][]? |
	    select(.[\"parent-id\"] == \$dev) | $1 // empty" <<< "$out"
}

# Print ids of all pins belonging to the device, one per line: pins
# registered on the device directly plus pins registered on those pins
# (MUX children), followed recursively so that children of children are
# included too. Older iproute2 lacks the "pin show device <id>" filter,
# so filter the full dump with jq.
dpll_pin_get_ids()
{
	local dev_id=$1
	local out

	out=$(dpll pin show -j 2>/dev/null) || return 1
	jq -r --argjson dev "$dev_id" '
		(.pin? // [.]) as $pins |
		def children($ids):
			[$pins[] | select(any(.["parent-pin"][]?;
					     .["parent-id"] as $p |
					     $ids | index($p))) | .id];
		def closure($ids):
			(($ids + children($ids)) | unique) as $n |
			if ($n | length) == ($ids | length) then $ids
			else closure($n) end;
		closure([$pins[] |
			 select(any(.["parent-device"][]?;
				    .["parent-id"] == $dev)) | .id])
		as $all |
		$pins[] | select(.id as $i | $all | index($i)) | .id' \
		<<< "$out"
}

# Print ids of all non-MUX pins of the device with the given direction
# (input/output), one per line. Direction lives in the parent-device nest.
dpll_pin_find_by_direction()
{
	local dev_id=$1
	local dir=$2
	local out

	out=$(dpll pin show -j 2>/dev/null) || return 1
	jq -r --argjson dev "$dev_id" --arg dir "$dir" \
	   '(.pin? // [.])[] | select(.type != "mux") |
	    select(.["parent-device"][]? |
		   (.["parent-id"] == $dev and .direction == $dir)) |
	    .id' <<< "$out"
}

dpll_pin_get_frequency()
{
	__dpll_pin_field "$1" '.frequency'
}

dpll_pin_get_state()
{
	__dpll_pin_dev_field "$1" "$2" '.state'
}

# Return 0 when the pin advertises the given capability, named as
# iproute2 prints it (state-can-change, priority-can-change, ...).
dpll_pin_has_capability()
{
	local pin_id=$1
	local name=$2
	local out

	out=$(dpll pin show id "$pin_id" -j 2>/dev/null) || return 1
	jq -e --arg name "$name" \
	   '(.pin[0]? // .) | .capabilities | index($name) != null' \
	   <<< "$out" &> /dev/null
}

##############################################################################
# Pin setters
#
# Every setter returns the status of the tool and keeps what the tool
# printed on stderr in DPLL_LAST_ERR, the "Error: ..." line that carries
# the extack message of the kernel, so that a caller can tell a refusal
# it may skip on from a failure.

DPLL_LAST_ERR=""

# $3: connected / disconnected / selectable
dpll_pin_set_state()
{
	local dev_id=$1
	local pin_id=$2
	local state=$3

	DPLL_LAST_ERR=$(dpll pin set id "$pin_id" parent-device "$dev_id" \
			     state "$state" 2>&1 >/dev/null)
}

##############################################################################
# dpllsim configfs interface
#
# Each directory under $DPLLSIM_CFG is one simulated device; its pins are
# directories under <dev>/pins/. Writing 1 to <dev>/live registers the
# device and its pins with the DPLL core, writing 0 unregisters them. The
# structure (pins, clock_id, pin attributes) can only be changed while the
# device is not live.
#
# dpllsim_available mounts configfs when nothing else did, which is the
# one side effect the library has outside the dpllsim directory. Scripts
# call dpll_lib_cleanup last from their exit trap to undo it.

DPLLSIM_MOUNTED_CONFIGFS=0

dpllsim_available()
{
	[ -d "$DPLLSIM_CFG" ] && return 0

	modprobe dpllsim &> /dev/null
	if ! mountpoint -q "$CONFIGFS_DIR"; then
		mount -t configfs none "$CONFIGFS_DIR" &> /dev/null &&
			DPLLSIM_MOUNTED_CONFIGFS=1
	fi
	[ -d "$DPLLSIM_CFG" ]
}

# Unmount configfs again when dpllsim_available mounted it. Call after
# the devices of the script are gone. A dpllsim device the script could
# not remove keeps the mount, so that what is left can be looked at.
dpll_lib_cleanup()
{
	local dev_path name

	[ "$DPLLSIM_MOUNTED_CONFIGFS" -eq 1 ] || return 0
	DPLLSIM_MOUNTED_CONFIGFS=0

	for dev_path in "$DPLLSIM_CFG"/*/; do
		[ -d "$dev_path" ] || continue
		name=$(basename "$dev_path")
		log_info "device $name left behind, $CONFIGFS_DIR kept mounted"
		return
	done
	umount "$CONFIGFS_DIR" 2>/dev/null ||
		log_info "cannot unmount $CONFIGFS_DIR"
}

dpllsim_check_module()
{
	if ! dpllsim_available; then
		echo "SKIP: dpllsim module not available"
		exit "$ksft_skip"
	fi
}

# $1: device name, $2: clock-id. Sets DPLLSIM_CREATED_NAME as soon as the
# directory exists, so that the cleanup handler of a script can remove a
# device whose creation a signal interrupted before the script recorded
# it. The name stays set once the device is complete.
dpllsim_create_device()
{
	local name=$1
	local clock_id=$2
	local dev_path="$DPLLSIM_CFG/$name"

	# Record the name before the directory exists, so that a cleanup
	# run by a signal between the two still finds it.
	DPLLSIM_CREATED_NAME=$name
	if ! mkdir "$dev_path" 2>/dev/null; then
		DPLLSIM_CREATED_NAME=""
		return 1
	fi
	if ! echo "$clock_id" 2>/dev/null > "$dev_path/clock_id"; then
		rmdir "$dev_path" 2>/dev/null
		DPLLSIM_CREATED_NAME=""
		return 1
	fi
}

# $1: device name, $2: pin name (becomes the board-label), $3: type (gnss,
# int-oscillator, ext, synce-eth-port, mux), $4: frequency in Hz,
# $5: direction (input/output)
dpllsim_add_pin()
{
	local dev=$1
	local pin=$2
	local type=$3
	local frequency=$4
	local direction=$5
	local pin_path="$DPLLSIM_CFG/$dev/pins/$pin"

	mkdir "$pin_path" 2>/dev/null || return 1

	if ! echo "$type" 2>/dev/null > "$pin_path/type" ||
	   ! echo "$frequency" 2>/dev/null > "$pin_path/frequency" ||
	   ! echo "$direction" 2>/dev/null > "$pin_path/direction"; then
		rmdir "$pin_path" 2>/dev/null
		return 1
	fi
}

dpllsim_deploy()
{
	echo 1 2>/dev/null > "$DPLLSIM_CFG/$1/live"
}

dpllsim_undeploy()
{
	echo 0 2>/dev/null > "$DPLLSIM_CFG/$1/live"
}

# Take the device offline and remove it together with all its pins.
# Every step is attempted even when an earlier one failed, the return
# value is non-zero when any did. A device that does not exist counts as
# deleted.
dpllsim_delete_device()
{
	local dev_path="$DPLLSIM_CFG/$1"
	local pin_path ret=0

	[ -d "$dev_path" ] || return 0

	dpllsim_undeploy "$1" || ret=1
	for pin_path in "$dev_path"/pins/*/; do
		[ -d "$pin_path" ] || continue
		rmdir "$pin_path" || ret=1
	done
	rmdir "$dev_path" || ret=1

	return "$ret"
}

# Set DPLLSIM_CLOCK_ID to a clock-id unique within this test run. Must
# not be called from a subshell (the counter increment would be lost);
# derive per-worker id ranges in the parent instead.
dpllsim_alloc_clock_id()
{
	DPLLSIM_CLOCK_ID=$((DPLLSIM_NEXT_CLOCK_ID++))
}

# Create a device with the standard 3-pin layout, deploy it and resolve
# the netlink device id. Sets DPLLSIM_CREATED_NAME, DPLLSIM_CLOCK_ID and
# DPLLSIM_DEV_ID.
#   gnss0: GNSS, 1 Hz, input
#   ext0: EXT, 10 MHz, input
#   out0: EXT, 10 MHz, output
# shellcheck disable=SC2120 # the argument is optional
dpllsim_setup_standard_device()
{
	local clock_id name

	dpllsim_alloc_clock_id
	clock_id=$DPLLSIM_CLOCK_ID
	name="std$clock_id"
	dpllsim_create_device "$name" "$clock_id" || return 1

	if ! dpllsim_add_pin "$name" gnss0 gnss 1 input ||
	   ! dpllsim_add_pin "$name" ext0 ext 10000000 input ||
	   ! dpllsim_add_pin "$name" out0 ext 10000000 output; then
		dpllsim_delete_device "$name"
		return 1
	fi

	if ! dpllsim_deploy "$name"; then
		dpllsim_delete_device "$name"
		return 1
	fi

	if ! DPLLSIM_DEV_ID=$(dpll_device_wait_by_clock_id "$clock_id" \
							  dpllsim); then
		dpllsim_delete_device "$name"
		return 1
	fi
}
