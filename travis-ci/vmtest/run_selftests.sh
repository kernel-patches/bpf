#!/bin/bash

set -euo pipefail

source $(cd $(dirname $0) && pwd)/helpers.sh

ARCH=$(uname -m)

STATUS_FILE=/exitstatus

read_lists() {
	(for path in "$@"; do
		if [[ -s "$path" ]]; then
			cat "$path"
		fi;
	done) | cut -d'#' -f1 | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | tr -s '\n' ','
}

TEST_PROGS_ARGS=""
# Disabled due to issue
# if [[ "$(nproc)" -gt 2 ]]; then
#   TEST_PROGS_ARGS="-j"
# fi

test_progs() {
  foldable start test_progs "Testing test_progs"
  # "&& true" does not change the return code (it is not executed
  # if the Python script fails), but it prevents exiting on a
  # failure due to the "set -e".
  ./test_progs ${DENYLIST:+-b"$DENYLIST"} ${ALLOWLIST:+-t"$ALLOWLIST"} ${TEST_PROGS_ARGS} && true
  echo "test_progs:$?" >>"${STATUS_FILE}"
  foldable end test_progs

  foldable start test_progs-no_alu32 "Testing test_progs-no_alu32"
  ./test_progs-no_alu32 ${DENYLIST:+-b"$DENYLIST"} ${ALLOWLIST:+-t"$ALLOWLIST"} ${TEST_PROGS_ARGS} && true
  echo "test_progs-no_alu32:$?" >>"${STATUS_FILE}"
  foldable end test_progs-no_alu32
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
DENYLIST=$(read_lists "$configs_path/DENYLIST" "$configs_path/DENYLIST.${ARCH}")
ALLOWLIST=$(read_lists "$configs_path/ALLOWLIST" "$configs_path/ALLOWLIST.${ARCH}")

cd ${PROJECT_NAME}/selftests/bpf

test_progs
test_maps
test_verifier
