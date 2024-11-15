#!/bin/bash

set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/helpers.sh"

foldable start selftests/sched_ext "Executing selftests/sched_ext/runner"

SELFTESTS_DIR="${KERNEL_ROOT}/selftests/sched_ext"
STATUS_FILE=/mnt/vmtest/exitstatus

cd "${SELFTESTS_DIR}"
./runner "$@" | tee runner.log

failed=$(tail -n 16 runner.log | grep "FAILED" | awk '{print $2}')

echo "selftests/sched_ext:$failed" >>"${STATUS_FILE}"

foldable end selftests/sched_ext
