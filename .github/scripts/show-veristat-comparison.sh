#!/bin/bash

cd "${GITHUB_WORKSPACE}" || exit 1

if [[ ! -f veristat-baseline.csv ]]; then
  echo "No veristat-baseline.csv available"
  echo "# No veristat-baseline.csv available" >> "${GITHUB_STEP_SUMMARY}"
  exit
fi

selftests/bpf/veristat \
  --output-format csv \
  --emit file,prog,verdict,states \
  --compare veristat-baseline.csv veristat.csv > compare.csv

python3 ./.github/scripts/veristat-compare.py compare.csv
