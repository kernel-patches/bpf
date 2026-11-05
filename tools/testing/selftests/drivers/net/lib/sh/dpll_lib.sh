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
DEBUGFS_DIR="/sys/kernel/debug"
DPLL_REF_TRACKER_DIR="$DEBUGFS_DIR/ref_tracker"

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
# and the leak check attributes every new ref_tracker entry to the run,
# so each takes a lock on DPLL_LOCK_FILE before it mounts or creates
# anything and skips when another run holds it. The workers a script
# forks inherit the open file and keep the lock until they exit. The
# files live under /run rather than in the world-writable /tmp, where a
# planted symlink could redirect the open.
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

dpll_pin_get_prio()
{
	__dpll_pin_dev_field "$1" "$2" '.prio'
}

dpll_pin_get_phase_adjust()
{
	__dpll_pin_field "$1" '.["phase-adjust"]'
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

dpll_pin_set_prio()
{
	local dev_id=$1
	local pin_id=$2
	local prio=$3

	DPLL_LAST_ERR=$(dpll pin set id "$pin_id" parent-device "$dev_id" \
			     prio "$prio" 2>&1 >/dev/null)
}

dpll_pin_set_frequency()
{
	DPLL_LAST_ERR=$(dpll pin set id "$1" frequency "$2" 2>&1 >/dev/null)
}

dpll_pin_set_phase_adjust()
{
	DPLL_LAST_ERR=$(dpll pin set id "$1" phase-adjust "$2" 2>&1 >/dev/null)
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
# dpllsim_available mounts configfs when nothing else did, like
# dpll_debugfs_available below does for debugfs, which are the only side
# effects the library has outside the dpllsim directory. Scripts call
# dpll_lib_cleanup last from their exit trap to undo them.

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

__dpll_lib_umount()
{
	umount "$1" 2>/dev/null || log_info "cannot unmount $1"
}

# Unmount configfs and debugfs again when the library mounted them. Call
# after the devices of the script are gone. A dpllsim device the script
# could not remove keeps both mounted, so that what is left can be
# looked at, the device in configfs and the references it still holds
# in the ref_tracker entries of debugfs.
dpll_lib_cleanup()
{
	local dev_path name dir kept
	local mounted=()

	[ "$DPLLSIM_MOUNTED_CONFIGFS" -eq 1 ] && mounted+=("$CONFIGFS_DIR")
	[ "$DPLL_MOUNTED_DEBUGFS" -eq 1 ] && mounted+=("$DEBUGFS_DIR")
	DPLLSIM_MOUNTED_CONFIGFS=0
	DPLL_MOUNTED_DEBUGFS=0
	[ "${#mounted[@]}" -gt 0 ] || return 0

	for dev_path in "$DPLLSIM_CFG"/*/; do
		[ -d "$dev_path" ] || continue
		name=$(basename "$dev_path")
		kept=${mounted[*]}
		kept="${kept/ / and } kept mounted"
		log_info "device $name left behind, $kept"
		return
	done
	for dir in "${mounted[@]}"; do
		__dpll_lib_umount "$dir"
	done
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
# $5: direction (input/output), $6: prio (optional, input pins only).
# The priority is written only when one is given, so a pin without one
# keeps the default of the simulator.
dpllsim_add_pin()
{
	local dev=$1
	local pin=$2
	local type=$3
	local frequency=$4
	local direction=$5
	local prio=${6:-}
	local pin_path="$DPLLSIM_CFG/$dev/pins/$pin"

	mkdir "$pin_path" 2>/dev/null || return 1

	if ! echo "$type" 2>/dev/null > "$pin_path/type" ||
	   ! echo "$frequency" 2>/dev/null > "$pin_path/frequency" ||
	   ! echo "$direction" 2>/dev/null > "$pin_path/direction" ||
	   { [ -n "$prio" ] &&
	     ! echo "$prio" 2>/dev/null > "$pin_path/prio"; }; then
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
# value is non-zero when any did. A device that does not exist counts
# as deleted, and so does a part of it that is gone by the time its
# step runs, the live file of the undeploy and the pin or device
# directory of an rmdir, so that a removal running concurrently, or an
# earlier one whose later steps failed, does not turn into a spurious
# failure here.
dpllsim_delete_device()
{
	local dev_path="$DPLLSIM_CFG/$1"
	local pin_path ret=0

	[ -d "$dev_path" ] || return 0

	dpllsim_undeploy "$1" || [ ! -e "$dev_path/live" ] || ret=1
	for pin_path in "$dev_path"/pins/*/; do
		[ -d "$pin_path" ] || continue
		rmdir "$pin_path" || [ ! -d "$pin_path" ] || ret=1
	done
	rmdir "$dev_path" || [ ! -d "$dev_path" ] || ret=1

	return "$ret"
}

# Set DPLLSIM_CLOCK_ID to a clock-id unique within this test run. Must
# not be called from a subshell (the counter increment would be lost);
# derive per-worker id ranges in the parent instead.
dpllsim_alloc_clock_id()
{
	DPLLSIM_CLOCK_ID=$((DPLLSIM_NEXT_CLOCK_ID++))
}

# Set DPLLSIM_CLOCK_ID to the first of $1 consecutive clock-ids unique
# within this test run and move the allocator past them, for a worker
# that derives the clock-ids of its devices from it. A device the parent
# creates afterwards cannot collide with one of the worker.
dpllsim_alloc_clock_id_range()
{
	DPLLSIM_CLOCK_ID=$DPLLSIM_NEXT_CLOCK_ID
	DPLLSIM_NEXT_CLOCK_ID=$((DPLLSIM_NEXT_CLOCK_ID + $1))
}

# Create a device with the standard 3-pin layout, deploy it and resolve
# the netlink device id. Sets DPLLSIM_CREATED_NAME, DPLLSIM_CLOCK_ID and
# DPLLSIM_DEV_ID.
#   gnss0: GNSS, 1 Hz, input, prio 0 (active reference)
#   ext0: EXT, 10 MHz, input, prio 1
#   out0: EXT, 10 MHz, output
# shellcheck disable=SC2120 # the argument is optional
dpllsim_setup_standard_device()
{
	local clock_id name

	dpllsim_alloc_clock_id
	clock_id=$DPLLSIM_CLOCK_ID
	name="std$clock_id"
	dpllsim_create_device "$name" "$clock_id" || return 1

	if ! dpllsim_add_pin "$name" gnss0 gnss 1 input 0 ||
	   ! dpllsim_add_pin "$name" ext0 ext 10000000 input 1 ||
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

##############################################################################
# ref_tracker leak checking
#
# With CONFIG_DPLL_REFCNT_TRACKER=y the DPLL core creates regular files
# named dpll_device@<ptr> / dpll_pin@<ptr> under the ref_tracker debugfs
# dir. Reading one prints the stack traces of currently unreleased
# references; an empty (or removed) file means no leaks.
#
# The entries do not name their owner, so leaks are attributed by
# snapshot, a non-empty entry whose name is not in the snapshot taken
# before the test created its devices is a leak, an entry that is in it
# belongs to another driver and is ignored even when its content changed.

DPLL_MOUNTED_DEBUGFS=0
# The snapshot files are kept in DPLL_RUN_DIR, see the lock above for
# why that is not /tmp, as refsnap.<pid>.<random>.
DPLL_REF_SNAPSHOT_PREFIX="$DPLL_RUN_DIR/refsnap"
# Name of the probe device while it exists, so that the cleanup handler
# of a script can remove it when the probe could not.
DPLLSIM_PROBE_DEVICE=""

# Create the file a snapshot is recorded in and print its name. The
# scripts take the lock first, which creates DPLL_RUN_DIR. A run that
# is killed with SIGKILL cannot remove its file, so the files of earlier
# runs whose process is gone are removed first, the pid of the run is
# the component after the first dot of the name. A pid that was reused
# by a process that lives long would keep such a file forever, so files
# older than a day are removed whatever their pid is. Return 1 when the
# file cannot be created.
dpll_ref_tracker_snapshot_file()
{
	local file pid

	find "$DPLL_RUN_DIR" -maxdepth 1 \
	     -name "${DPLL_REF_SNAPSHOT_PREFIX##*/}.*" -mmin +1440 -delete \
	     2>/dev/null
	for file in "$DPLL_REF_SNAPSHOT_PREFIX".*; do
		[ -f "$file" ] || continue
		pid=${file#"$DPLL_REF_SNAPSHOT_PREFIX".}
		pid=${pid%%.*}
		[[ "$pid" =~ ^[0-9]+$ ]] || continue
		[ -d "/proc/$pid" ] || rm -f "$file"
	done
	mktemp "$DPLL_REF_SNAPSHOT_PREFIX.$$.XXXXXX"
}

# Mount debugfs when nothing else did, so that the ref_tracker entries
# can be read, and remember that for dpll_lib_cleanup. Return 0 when
# debugfs is mounted afterwards, whether the tracker dir exists is for
# the caller to check.
dpll_debugfs_available()
{
	if ! mountpoint -q "$DEBUGFS_DIR"; then
		mount -t debugfs none "$DEBUGFS_DIR" &> /dev/null &&
			DPLL_MOUNTED_DEBUGFS=1
	fi
	mountpoint -q "$DEBUGFS_DIR"
}

__dpll_ref_tracker_hash()
{
	printf '%s' "$1" | md5sum | cut -d' ' -f1
}

# Write "<name> <content hash>" for every existing dpll_device@* /
# dpll_pin@* entry to the given file, one entry per line. The file ends
# up empty when the tracker dir is missing.
dpll_ref_tracker_snapshot()
{
	local file=$1
	local entry content

	for entry in "$DPLL_REF_TRACKER_DIR"/dpll_device@* \
		     "$DPLL_REF_TRACKER_DIR"/dpll_pin@*; do
		[ -f "$entry" ] || continue
		content=$(cat "$entry" 2>/dev/null)
		echo "$(basename "$entry")" \
		     "$(__dpll_ref_tracker_hash "$content")"
	done > "$file"
}

# Print the leak candidates, the non-empty entries whose name is not in
# the snapshot, each followed by its content. Prints nothing when there
# is no candidate.
__dpll_ref_tracker_new_entries()
{
	local file=$1
	local entry name content

	for entry in "$DPLL_REF_TRACKER_DIR"/dpll_device@* \
		     "$DPLL_REF_TRACKER_DIR"/dpll_pin@*; do
		[ -f "$entry" ] || continue
		name=$(basename "$entry")
		grep -q "^$name " "$file" && continue
		content=$(cat "$entry" 2>/dev/null)
		[ -n "$content" ] || continue
		echo "Unreleased references in $name:"
		echo "$content"
	done
}

# Return 0 when there is no leak candidate. Otherwise print the
# candidates and return 1, busywait hands the output of its last failed
# check to the caller when it times out.
__dpll_ref_tracker_settled()
{
	local leaks

	leaks=$(__dpll_ref_tracker_new_entries "$1")
	[ -z "$leaks" ] && return 0

	echo "$leaks"
	return 1
}

# Log the entries of the snapshot whose content changed since and record
# the new content, so that the same change is logged once.
__dpll_ref_tracker_note_changed()
{
	local file=$1
	local entry name content hash changed=""

	for entry in "$DPLL_REF_TRACKER_DIR"/dpll_device@* \
		     "$DPLL_REF_TRACKER_DIR"/dpll_pin@*; do
		[ -f "$entry" ] || continue
		name=$(basename "$entry")
		grep -q "^$name " "$file" || continue
		content=$(cat "$entry" 2>/dev/null)
		hash=$(__dpll_ref_tracker_hash "$content")
		grep -qx "$name $hash" "$file" && continue
		sed -i "s/^$name .*/$name $hash/" "$file"
		changed="$changed $name"
	done

	[ -n "$changed" ] && log_info \
		"references of another driver changed (ignored):$changed"
	return 0
}

# $1: snapshot file written by dpll_ref_tracker_snapshot before the
# objects under test were created. Return 0 when no reference to an
# object created since the snapshot is held any more. A concurrent dump
# holds references for a moment, so wait for the candidates to drain. A
# timeout means the references never drained, the candidates seen by the
# last check are then printed and count as leaked.
dpll_ref_tracker_check_leaks()
{
	local file=$1
	local leaks ret=0

	[ -d "$DPLL_REF_TRACKER_DIR" ] || return 0

	if ! leaks=$(busywait "$BUSYWAIT_TIMEOUT" __dpll_ref_tracker_settled \
			      "$file"); then
		echo "References not released within $BUSYWAIT_TIMEOUT ms:"
		echo "$leaks"
		ret=1
	fi
	__dpll_ref_tracker_note_changed "$file"

	return "$ret"
}

# Probe whether the kernel tracks DPLL references with a throwaway
# dpllsim device, the entries that exist before it are recorded in the
# scratch file $1. Return 0 when the tracker works, 1 when no entry
# appeared (no CONFIG_DPLL_REFCNT_TRACKER), 2 when the probe device
# could not be created or deployed, 3 when its entries did not drain
# after its deletion and 4 when it could not be deleted, its name then
# stays in DPLLSIM_PROBE_DEVICE for the cleanup handler to retry. Must
# not be called from a subshell, it allocates clock-ids.
dpll_ref_tracker_probe()
{
	local file=$1
	local name attempt ret=2

	dpll_ref_tracker_snapshot "$file"

	# A directory of that name left behind by an earlier run takes a
	# fresh clock-id, anything else is a broken simulator.
	for attempt in 1 2 3; do
		dpllsim_alloc_clock_id
		name="probe$DPLLSIM_CLOCK_ID"
		dpllsim_create_device "$name" "$DPLLSIM_CLOCK_ID" && break
		[ -d "$DPLLSIM_CFG/$name" ] || return 2
		[ "$attempt" -lt 3 ] || return 2
	done
	DPLLSIM_PROBE_DEVICE=$name

	if dpllsim_add_pin "$name" ext0 ext 10000000 input &&
	   dpllsim_deploy "$name"; then
		ret=1
		[ -n "$(__dpll_ref_tracker_new_entries "$file")" ] && ret=0
	fi

	if dpllsim_delete_device "$name"; then
		DPLLSIM_PROBE_DEVICE=""
	else
		log_info "cannot delete device $name"
		return 4
	fi
	if [ "$ret" -eq 0 ] &&
	   ! busywait "$BUSYWAIT_TIMEOUT" __dpll_ref_tracker_settled "$file" \
		      > /dev/null; then
		ret=3
	fi
	return "$ret"
}
