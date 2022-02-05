#!/bin/bash

set -euo pipefail

source $(cd $(dirname $0) && pwd)/helpers.sh

STATUS_FILE=/exitstatus

TEST_PROGS_ARGS=""
# Disabled due to issue
# if [[ "$(nproc)" -gt 2 ]]; then
#   TEST_PROGS_ARGS="-j"
# fi

test_progs() {
  travis_fold start test_progs "Testing test_progs"
  # "&& true" does not change the return code (it is not executed
  # if the Python script fails), but it prevents exiting on a
  # failure due to the "set -e".
  ./test_progs ${BLACKLIST:+-b$BLACKLIST} ${WHITELIST:+-t$WHITELIST} ${TEST_PROGS_ARGS} && true
  echo "test_progs:$?" >>"${STATUS_FILE}"
  travis_fold end test_progs

  travis_fold start test_progs-no_alu32 "Testing test_progs-no_alu32"
  ./test_progs-no_alu32 ${BLACKLIST:+-b$BLACKLIST} ${WHITELIST:+-t$WHITELIST} ${TEST_PROGS_ARGS} && true
  echo "test_progs-no_alu32:$?" >>"${STATUS_FILE}"
  travis_fold end test_progs-no_alu32
}

test_maps() {
  travis_fold start test_maps "Testing test_maps"
  ./test_maps && true
  echo "test_maps:$?" >>"${STATUS_FILE}"
  travis_fold end test_maps
}

test_verifier() {
  travis_fold start test_verifier "Testing test_verifier"
  ./test_verifier && true
  echo "test_verifier:$?" >>"${STATUS_FILE}"
  travis_fold end test_verifier
}

travis_fold end vm_init

configs_path='libbpf/travis-ci/vmtest/configs'
blacklist_path="$configs_path/blacklist/BLACKLIST-${KERNEL}"
if [[ -s "${blacklist_path}" ]]; then
  BLACKLIST=$(cat "${blacklist_path}" | cut -d'#' -f1 | tr -s '[:space:]' ',')
fi

whitelist_path="$configs_path/whitelist/WHITELIST-${KERNEL}"
if [[ -s "${whitelist_path}" ]]; then
  WHITELIST=$(cat "${whitelist_path}" | cut -d'#' -f1 | tr -s '[:space:]' ',')
fi

cd libbpf/selftests/bpf

test_progs
test_maps
test_verifier
