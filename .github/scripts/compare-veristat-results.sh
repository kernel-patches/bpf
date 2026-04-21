#!/bin/bash

veristat=$(realpath selftests/bpf/veristat)

# Dump verifier logs for a list of programs
# Usage: dump_failed_logs <progs_file>
# - progs_file: file with lines of format "file_name,prog_name"
dump_failed_logs() {
    local progs_file="$1"
    local objects_dir="${VERISTAT_OBJECTS_DIR:-$(pwd)}"

    while read -r line; do
        local file prog
        file=$(echo "$line" | cut -d',' -f1)
        prog=$(echo "$line" | cut -d',' -f2)
        echo "VERIFIER LOG FOR $file/$prog:"
        echo "=================================================================="
        $veristat -v "$objects_dir/$file" -f "$prog"
        echo "=================================================================="
    done < "$progs_file"
}

if [[ ! -f "${BASELINE_PATH}" ]]; then
    echo "# No ${BASELINE_PATH} available" >> "${GITHUB_STEP_SUMMARY}"

    echo "No ${BASELINE_PATH} available"
    echo "Printing veristat results"
    cat "${VERISTAT_OUTPUT}"

    if [[ -n "$VERISTAT_DUMP_LOG_ON_FAILURE" ]]; then
        failed_progs=$(mktemp failed_progs_XXXXXX.txt)
        awk -F',' '$3 == "failure" { print $1","$2 }' "${VERISTAT_OUTPUT}" > "$failed_progs"
        if [[ -s "$failed_progs" ]]; then
            echo && dump_failed_logs "$failed_progs"
        fi
        rm -f "$failed_progs"
    fi

    echo "$(basename "$0"): no baseline provided for veristat output"
    echo "VERISTAT JOB PASSED"
    exit 0
fi

cmp_out=$(mktemp veristate_compare_out_XXXXXX.csv)

$veristat \
    --output-format csv \
    --emit file,prog,verdict,states \
    --compare "${BASELINE_PATH}" "${VERISTAT_OUTPUT}" > $cmp_out

python3 ./.github/scripts/veristat_compare.py $cmp_out
exit_code=$?

# print verifier log for progs that failed to load
if [[ -n "$VERISTAT_DUMP_LOG_ON_FAILURE" ]]; then
    failed_progs=$(mktemp failed_progs_XXXXXX.txt)
    awk -F',' '$4 == "failure" { print $1","$2 }' "$cmp_out" > "$failed_progs"
    if [[ -s "$failed_progs" ]]; then
        echo && dump_failed_logs "$failed_progs"
    fi
    rm -f "$failed_progs"
fi

if [[ $exit_code -eq 0 ]]; then
    echo "$(basename "$0"): veristat output matches the baseline"
    echo "VERISTAT JOB PASSED"
else
    echo "$(basename "$0"): veristat output does not match the baseline"
    echo "VERISTAT JOB FAILED"
fi

exit $exit_code
