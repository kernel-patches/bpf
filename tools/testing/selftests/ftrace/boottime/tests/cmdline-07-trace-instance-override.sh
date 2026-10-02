#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026, Google LLC.
# Check trace_instance= override with bootconfig and kernel command-line
TRACEDIR="/sys/kernel/tracing"

if [ -f /proc/bootconfig ] && \
   grep -q "dump_bconf" /proc/cmdline 2>/dev/null; then
	echo "=== /proc/bootconfig ==="
	cat /proc/bootconfig
	echo "========================"
fi

check_instance() {
	instance="$1"
	old_event="$2"
	new_event="$3"

	if [ ! -d "$TRACEDIR/instances/$instance" ]; then
		echo "FAIL: trace instance $instance does not exist"
		exit 1
	fi

	if [ -n "$old_event" ] && \
	   [ -f "$TRACEDIR/instances/$instance/events/$old_event/enable" ]; then
		ENABLE=$(cat "$TRACEDIR/instances/$instance/events/$old_event/enable")
		if [ "$ENABLE" = "1" ]; then
			echo "FAIL: overridden event $old_event" \
				"is still enabled in instance $instance"
			exit 1
		fi
	fi

	if [ -n "$new_event" ]; then
		if [ ! -d "$TRACEDIR/instances/$instance/events/$new_event" ]; then
			echo "FAIL: event $new_event does not exist in instance $instance"
			exit 1
		fi

		ENABLE=$(cat "$TRACEDIR/instances/$instance/events/$new_event/enable")
		if [ "$ENABLE" != "1" ]; then
			echo "FAIL: event $new_event is not enabled in instance $instance ($ENABLE)"
			exit 1
		fi
	fi

	TRACING_ON=$(cat "$TRACEDIR/instances/$instance/tracing_on")
	if [ "$TRACING_ON" != "0" ]; then
		echo "FAIL: tracing_on is not 0 in instance $instance ($TRACING_ON)"
		exit 1
	fi
}

check_backup_instance() {
	instance="$1"

	if [ ! -d "$TRACEDIR/instances/$instance" ]; then
		echo "FAIL: trace instance $instance does not exist"
		exit 1
	fi

	# Backup instances have a trace buffer file
	if [ ! -f "$TRACEDIR/instances/$instance/trace" ]; then
		echo "FAIL: backup instance $instance has no trace file"
		exit 1
	fi

	# Backup instances are read-only and do not have tracing_on
	if [ -f "$TRACEDIR/instances/$instance/tracing_on" ]; then
		echo "FAIL: backup instance $instance unexpectedly has tracing_on"
		exit 1
	fi

	# Backup instances do not support enabling events
	if [ -f \
	   "$TRACEDIR/instances/$instance/events/sched/sched_switch/enable" ]; then
		echo "FAIL: backup instance $instance unexpectedly has enabled events"
		exit 1
	fi
}

check_mapped_instance() {
	instance="$1"
	old_event="$2"
	new_event="$3"

	check_instance "$instance" "$old_event" "$new_event"

	# Check dmesg to confirm physical mapping occurred
	if ! dmesg | grep -q "mapped boot instance $instance"; then
		echo "FAIL: memory-mapped instance $instance was not mapped at boot"
		exit 1
	fi
}

# Test 1: bootconfig trace_instance overridden by cmdline parameter
check_instance "foo" "sched/sched_switch" "sched/sched_waking"

# Test 2: cmdline trace_instance overridden by subsequent cmdline parameter
check_instance "bar" "sched/sched_switch" "irq/irq_handler_entry"

# Test 3: memory-mapped (@trace) instance in bootconfig overridden by cmdline
check_mapped_instance "boot_map" "sched/sched_switch" "sched/sched_waking"

# Test 4a: backup instance in bootconfig overridden by normal
# instance in cmdline
check_instance "bak_to_norm" "" "irq/irq_handler_entry"

# Test 4b: normal instance in bootconfig overridden by backup
# instance in cmdline
check_backup_instance "bak_from_norm"

# Test 5: instances separated by multiple tabs, where first is overridden
check_instance "tab1" "sched/sched_switch" "sched/sched_waking"
# tab2 was not overridden, so its original event should remain enabled
if [ ! -d "$TRACEDIR/instances/tab2/events/sched/sched_switch" ]; then
	echo "FAIL: instance tab2 event sched/sched_switch does not exist"
	exit 1
fi
ENABLE=$(cat "$TRACEDIR/instances/tab2/events/sched/sched_switch/enable")
if [ "$ENABLE" != "1" ]; then
	echo "FAIL: instance tab2 event sched/sched_switch is not enabled ($ENABLE)"
	exit 1
fi

# Test 6: Verify empty strings and malformed entries did not create
# bogus directories
for dir in "$TRACEDIR/instances"/*; do
	[ -d "$dir" ] || continue
	bname=$(basename "$dir")
	case "$bname" in
		foo|bar|boot_map|bak_to_norm|bak_from_norm|tab1|tab2)
			;;
		*)
			echo "FAIL: unexpected trace instance directory found: $bname"
			exit 1
			;;
	esac
done

# Test 7: Verify no kernel warnings or assertion failures were triggered
if dmesg | grep -q "WARNING: CPU:"; then
	echo "FAIL: kernel warning triggered during boot"
	exit 1
fi

echo "PASS: cmdline-07-trace-instance-override"
exit 0
