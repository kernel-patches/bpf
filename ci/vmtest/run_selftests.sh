#!/bin/bash

# run_selftest.sh will run the tests within /${PROJECT_NAME}/selftests/bpf
# If no specific test names are given, all test will be ran, otherwise, it will
# run the test passed as parameters.
# There is 2 ways to pass test names.
# 1) command-line arguments to this script
# 2) a comma-separated list of test names passed as `run_tests` boot parameters.
# test names passed as any of those methods will be ran.

set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/helpers.sh"

ARCH=$(uname -m)

STATUS_FILE=/exitstatus

declare -a TEST_NAMES=()

read_lists() {
	(for path in "$@"; do
		if [[ -s "$path" ]]; then
			cat "$path"
		fi;
	done) | cut -d'#' -f1 | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | tr -s '\n' ','
}

read_test_names() {
    foldable start read_test_names "Reading test names from boot parameters and command line arguments"
    # Check if test names were passed as boot parameter.
    # We expect `run_tests` to be a comma-separated list of test names.
    IFS=',' read -r -a test_names_from_boot <<< \
        "$(sed -n 's/.*run_tests=\([^ ]*\).*/\1/p' /proc/cmdline)"

    echo "${#test_names_from_boot[@]} tests extracted from boot parameters: ${test_names_from_boot[*]}"
    # Sort and only keep unique test names from both boot params and arguments
    # TEST_NAMES will contain a sorted list of uniq tests to be ran.
    # Only do this if any of $test_names_from_boot[@] or $@ has elements as
    # "printf '%s\0'" will otherwise generate an empty element.
    if [[ ${#test_names_from_boot[@]} -gt 0 || $# -gt 0 ]]
    then
        readarray -t TEST_NAMES < \
            <(printf '%s\0' "${test_names_from_boot[@]}" "$@" | \
                sort --zero-terminated --unique | \
                xargs --null --max-args=1)
    fi
    foldable end read_test_names
}

test_progs_helper() {
  local selftest="test_progs${1}"
  local args="$2"

  foldable start ${selftest} "Testing ${selftest}"
  # "&& true" does not change the return code (it is not executed
  # if the Python script fails), but it prevents exiting on a
  # failure due to the "set -e".
  ./${selftest} ${args} ${DENYLIST:+-d"$DENYLIST"} ${ALLOWLIST:+-a"$ALLOWLIST"} && true
  echo "${selftest}:$?" >>"${STATUS_FILE}"
  foldable end ${selftest}
}

test_progs() {
  test_progs_helper "" ""
}

test_progs_parallel() {
  test_progs_helper "" "-j"
}

test_progs_no_alu32() {
  test_progs_helper "-no_alu32" ""
}

test_progs_no_alu32_parallel() {
  test_progs_helper "-no_alu32" "-j"
}

test_maps() {
  foldable start test_maps "Testing test_maps"
  taskset 0xF ./test_maps && true
  echo "test_maps:$?" >>"${STATUS_FILE}"
  foldable end test_maps
}

test_verifier() {
  foldable start test_verifier "Testing test_verifier"
  ./test_verifier && true
  echo "test_verifier:$?" >>"${STATUS_FILE}"
  foldable end test_verifier
}

foldable end vm_init

foldable start kernel_config "Kconfig"

zcat /proc/config.gz

foldable end kernel_config

configs_path=${PROJECT_NAME}/selftests/bpf
local_configs_path=${PROJECT_NAME}/vmtest/configs
DENYLIST=$(read_lists \
	"$configs_path/DENYLIST" \
	"$configs_path/DENYLIST.${ARCH}" \
	"$local_configs_path/DENYLIST" \
	"$local_configs_path/DENYLIST.${ARCH}" \
)
ALLOWLIST=$(read_lists \
	"$configs_path/ALLOWLIST" \
	"$configs_path/ALLOWLIST.${ARCH}" \
	"$local_configs_path/ALLOWLIST" \
	"$local_configs_path/ALLOWLIST.${ARCH}" \
)

echo "DENYLIST: ${DENYLIST}"
echo "ALLOWLIST: ${ALLOWLIST}"

cd ${PROJECT_NAME}/selftests/bpf

# populate TEST_NAMES
read_test_names "$@"
# if we don't have any test name provided to the script, we run all tests.
if [ ${#TEST_NAMES[@]} -eq 0 ]; then
	test_progs
	test_progs_no_alu32
	test_maps
	test_verifier
else
	# else we run the tests passed as command-line arguments and through boot
	# parameter.
	for test_name in "${TEST_NAMES[@]}"; do
		"${test_name}"
	done
fi
