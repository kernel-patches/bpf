#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

# Loading the module runs its in-kernel hierarchy API checks. Then validate
# all 16 exported zones, their power readings and constraint attributes, and
# removal of the controller while a sysfs attribute descriptor remains open.

ksft_pass=0
ksft_fail=1
ksft_skip=4

MODULE=powercap_hierarchy
CONTROL=powercap-test
SYSFS=/sys/devices/virtual/powercap/$CONTROL

fail()
{
	echo "FAIL: $*"
	exit $ksft_fail
}

skip()
{
	echo "SKIP: $*"
	exit $ksft_skip
}

cleanup()
{
	if lsmod | grep -q "^${MODULE}\b"; then
		if ! rmmod "$MODULE"; then
			echo "WARNING: failed to unload $MODULE"
		fi
	fi
}

[ "$(id -u)" -eq 0 ] || skip "must be run as root"
[ -d /sys/class/powercap ] || skip "powercap is not available in the running kernel"
[ -f ./powercap_hierarchy.ko ] || skip "powercap_hierarchy.ko is not available"

trap cleanup EXIT INT TERM

insmod ./powercap_hierarchy.ko || fail "failed to load module"

[ -d "$SYSFS" ] || fail "missing $SYSFS"

check_zone()
{
	zone=$1

	# Check required attributes and the deterministic values from the module.
	[ -f "$zone/name" ] || fail "$zone/name missing"

	[ -f "$zone/power_uw" ] || \
		fail "$zone/power_uw missing"

	[ -f "$zone/max_power_range_uw" ] || \
		fail "$zone/max_power_range_uw missing"

	power=$(cat "$zone/power_uw")
	[ "$power" = "12648430" ] || \
		fail "$zone: unexpected power_uw ($power)"

	max=$(cat "$zone/max_power_range_uw")
	[ "$max" = "50159747054" ] || \
		fail "$zone: unexpected max_power_range_uw ($max)"

	constraint="$zone/constraint_0"

	name=$(cat "$constraint""_name")
	[ "$name" = "my constraint name" ] || \
		fail "$constraint: bad constraint name"

	pl=$(cat "$constraint""_power_limit_uw")
	[ "$pl" = "3735929054" ] || \
		fail "$constraint: bad power limit"

	mp=$(cat "$constraint""_max_power_uw")
	[ "$mp" = "3735929054" ] || \
		fail "$constraint: bad max power"
}

zones=0

namefiles=$(find "$SYSFS" -type f -name name) || fail "failed to list zones"

while IFS= read -r namefile
do
	zone=$(dirname "$namefile")

	case "$zone" in
		*/constraint_*)
			continue
			;;
	esac

	check_zone "$zone"

	zones=$((zones + 1))
done <<EOF
$namefiles
EOF

#
# Count the number of powercap zones.
#
[ "$zones" -eq 16 ] || \
	fail "expected 16 zones, got $zones"

#
# Keep an attribute open across module removal, then close it afterwards.
#
exec 3<"$zone/power_uw" || fail "failed to open power_uw before removal"
cleanup
exec 3<&-

#
# Verify that the hierarchy disappeared.
#
if [ -d "$SYSFS" ]; then
	fail "$SYSFS still exists after module removal"
fi

trap - EXIT INT TERM

echo "PASS"

exit $ksft_pass
