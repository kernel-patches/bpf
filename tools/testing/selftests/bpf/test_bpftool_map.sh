#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

# Kselftest framework requirement - SKIP code is 4.
ksft_skip=4

PROTECTED_MAP_NAME="prot_map"
NOT_PROTECTED_MAP_NAME="not_prot_map"
BPF_FILE="security_bpf_map.bpf.o"
TESTNAME="security_bpf_map"
BPF_FS=$(awk '$3 == "bpf" {print $2; exit}' /proc/mounts)
BPF_DIR="$BPF_FS/test_$TESTNAME"
SCRIPT_DIR=$(dirname $(realpath "$0"))
BPF_FILE_PATH="$SCRIPT_DIR/$BPF_FILE"
# Assume the script is located under tools/testing/selftests/bpf/
KDIR_ROOT_DIR=$(realpath "$SCRIPT_DIR"/../../../../)

_cleanup()
{
	set +eu
	[ -d "$TMPDIR" ] && rm -rf "$TMPDIR" 2> /dev/null
	[ -d "$BPF_DIR" ] && rm -rf "$BPF_DIR" 2> /dev/null
}

cleanup_skip()
{
	echo "selftests: $TESTNAME [SKIP]"
	_cleanup

	exit $ksft_skip
}

cleanup()
{
	if [ "$?" = 0 ]; then
		echo "selftests: $TESTNAME [PASS]"
	else
		echo "selftests: $TESTNAME [FAILED]"
	fi
	_cleanup
}

# Parameters:
#   $1: The top of kernel repository
#   $2: Output directory
build_bpftool()
{
	local kdir_root_dir="$1"
	local output_dir="$2"
	local pwd="$(pwd)"
	local ncpus=1

	echo Building bpftool ...

	#We want to start build from the top of kernel repository.
	cd "$kdir_root_dir"
	if [ ! -e tools/bpf/bpftool/Makefile ]; then
		echo bpftool files not found
		exit $ksft_skip
	fi

	# Determine the number of CPUs for parallel compilation
	if command -v nproc >/dev/null 2>&1; then
		ncpus=$(nproc)
	fi

	make -C tools/bpf/bpftool -s -j"$ncpus" OUTPUT="$output_dir"/ >/dev/null
	echo ... finished building bpftool
	cd "$pwd"
}

# Function to test map access with configurable write expectations
# Parameters:
#   $1: Map name
#   $2: Whether write should succeed (true/false)
#   $3: bpftool path
#   $4: BPF_DIR
test_map_access() {
	local map_name="$1"
	local write_should_succeed="$2"
	local bpftool_path="$3"
	local pin_path="$4/${map_name}_pinned"
	local key="0 0 0 0"
	local value="1 1 1 1"

	echo "Testing access to map: $map_name"

	# Test read access to the map
	if "$bpftool_path" map lookup name "$map_name" key $key; then
		echo "  Read access to $map_name succeeded"
	else
		echo "  Read access to $map_name failed"
		exit 1
	fi

	# Test write access to the map
	if "$bpftool_path" map update name "$map_name" key $key value $value; then
		if [ "$write_should_succeed" = "true" ]; then
			echo "  Write access to $map_name succeeded as expected"
		else
			echo "  Write access to $map_name succeeded but should have failed"
			exit 1
		fi
	else
		if [ "$write_should_succeed" = "true" ]; then
			echo "  Write access to $map_name failed but should have succeeded"
			exit 1
		else
			echo "  Write access to $map_name failed as expected"
		fi
	fi

	# Pin the map to the BPF filesystem
	"$bpftool_path" map pin name "$map_name" "$pin_path"
	if [ -e "$pin_path" ]; then
		echo "  Successfully pinned $map_name to $pin_path"
	else
		echo "  Failed to pin $map_name"
		exit 1
	fi

	# Test read access to the pinned map
	if "$bpftool_path" map lookup pinned "$pin_path" key $key; then
		echo "  Read access to pinned $map_name succeeded"
	else
		echo "  Read access to pinned $map_name failed"
		exit 1
	fi

	# Test write access to the pinned map
	if "$bpftool_path" map update pinned "$pin_path" key $key value $value; then
		if [ "$write_should_succeed" = "true" ]; then
			echo "  Write access to pinned $map_name succeeded as expected"
		else
			echo "  Write access to pinned $map_name succeeded but should have failed"
			exit 1
		fi
	else
		if [ "$write_should_succeed" = "true" ]; then
			echo "  Write access to pinned $map_name failed but should have succeeded"
			exit 1
		else
			echo "  Write access to pinned $map_name failed as expected"
		fi
	fi

	echo "  Finished testing $map_name"
	echo
}

check_root_privileges() {
	if [ $(id -u) -ne 0 ]; then
		echo "Need root privileges"
		exit $ksft_skip
	fi
}

check_bpffs() {
	if [ -z "$BPF_FS" ]; then
		echo "Could not run test without bpffs mounted"
		exit $ksft_skip
	fi
}

create_tmp_dir() {
	TMPDIR=$(mktemp -d)
	if [ $? -ne 0 ] || [ ! -d "$TMPDIR" ]; then
		echo "Failed to create temporary directory"
		exit $ksft_skip
	fi
}

locate_or_build_bpftool() {
	if ! bpftool version > /dev/null 2>&1; then
		build_bpftool "$KDIR_ROOT_DIR" "$TMPDIR"
		BPFTOOL_PATH="$TMPDIR"/bpftool
	else
		echo "Using bpftool from PATH"
		BPFTOOL_PATH="bpftool"
	fi
}

set -eu

trap cleanup_skip EXIT

check_root_privileges

check_bpffs

create_tmp_dir

locate_or_build_bpftool

mkdir "$BPF_DIR"

trap cleanup EXIT

# Load and attach the BPF programs to control maps access
"$BPFTOOL_PATH" prog loadall "$BPF_FILE_PATH" "$BPF_DIR"/prog autoattach

# Test protected map (write should fail)
test_map_access "$PROTECTED_MAP_NAME" "false" "$BPFTOOL_PATH" "$BPF_DIR"

# Test not protected map (write should succeed)
test_map_access "$NOT_PROTECTED_MAP_NAME" "true" "$BPFTOOL_PATH" "$BPF_DIR"

exit 0
