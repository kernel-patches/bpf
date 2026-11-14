#!/bin/bash

veristat=$(realpath selftests/bpf/veristat)

if [[ ! -f "${BASELINE_PATH}" ]]; then
    echo "# No ${BASELINE_PATH} available" >> "${GITHUB_STEP_SUMMARY}"

    echo "No ${BASELINE_PATH} available"
    echo "Printing veristat results"
    cat "${VERISTAT_OUTPUT}"

    echo "$(basename "$0"): no baseline provided for veristat output"
    echo "VERISTAT JOB PASSED"
    exit 0
fi

cmp_out=$(mktemp veristate_compare_out_XXXXXX.csv)

$veristat \
    --output-format csv \
    --emit file,prog,verdict,states \
    --compare "${BASELINE_PATH}" "${VERISTAT_OUTPUT}" > $cmp_out

python3 ./ci/veristat/veristat_compare.py $cmp_out
exit_code=$?

if [[ $exit_code -eq 0 ]]; then
    echo "$(basename "$0"): veristat output matches the baseline"
    echo "VERISTAT JOB PASSED"
else
    echo "$(basename "$0"): veristat output does not match the baseline"
    echo "VERISTAT JOB FAILED"
fi

exit $exit_code
