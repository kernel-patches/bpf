#!/bin/bash

# Guest entrypoint for libbpf/ci run-vmtest, selected through VMTEST_SCRIPT.
# run.sh stops before collecting statuses if the guest command fails, so
# report the measurement result through the status file instead.

set -euo pipefail

status=0
python3 "$(dirname "$0")/run_veristat.py" \
    --veristat "${VERISTAT_BINARY}" \
    --manifest "${VERISTAT_MANIFEST}" \
    --output "${VERISTAT_RESULTS}" || status=$?

echo "veristat:${status}" >> "${STATUS_FILE:-/mnt/vmtest/exitstatus}"
