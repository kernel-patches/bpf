#!/bin/bash

if [[ ! -f "${BASELINE_PATH}" ]]; then
    echo "# No ${BASELINE_PATH} available" >> "${GITHUB_STEP_SUMMARY}"

    echo "No ${BASELINE_PATH} available"
    echo "Printing veristat results"
    cat "${VERISTAT_OUTPUT}"

    exit 0
fi

veristat=$(realpath selftests/bpf/veristat)
cmp_out=$(mktemp veristate_compare_out_XXXXXX.csv)

$veristat \
    --output-format csv \
    --emit file,prog,verdict,states \
    --compare "${BASELINE_PATH}" "${VERISTAT_OUTPUT}" > $cmp_out

python3 ./.github/scripts/veristat_compare.py $cmp_out
exit_code=$?

echo
# if comparison failed, print verifier log for failure mismatches
if [[ -n "$VERISTAT_DUMP_LOG_ON_FAILURE" && $exit_code -ne 0 ]]; then
    cat $cmp_out | tail -n +1 | \
    while read -r line; do
        verdict=$(echo $line | cut -d',' -f4)
        verdict_diff=$(echo $line | cut -d',' -f5)
        if [[ "$verdict" == "failure" && "$verdict_diff" == "MISMATCH" ]]; then
            file=$(echo $line | cut -d',' -f1)
            prog=$(echo $line | cut -d',' -f2)
            echo "VERIFIER LOG FOR $file/$prog:"
            echo "=================================================================="
            $veristat -v $VERISTAT_OBJECTS_DIR/$file -f $prog 2>&1
            echo "=================================================================="
        fi
    done
fi

exit $exit_code
