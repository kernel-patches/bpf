#!/bin/bash

if [[ ! -f "${CACHE_RESULT_KEY}" ]]; then
    echo "# No ${CACHE_RESULT_KEY} available" >> "${GITHUB_STEP_SUMMARY}"

    echo "No ${CACHE_RESULT_KEY} available"
    echo "Printing veristat results"
    cat "${VERISTAT_OUTPUT}"

    exit
fi

selftests/bpf/veristat \
    --output-format csv \
    --emit file,prog,verdict,states \
    --compare "${CACHE_RESULT_KEY}" "${VERISTAT_OUTPUT}" > compare.csv

python3 ./.github/scripts/veristat-compare.py compare.csv
