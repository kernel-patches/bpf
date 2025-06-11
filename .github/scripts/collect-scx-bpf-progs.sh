#!/bin/bash

set -euo pipefail

PROGS_DIR=$1

mkdir -p "${PROGS_DIR}"

find "${SCX_BUILD_OUTPUT}" -type f -name "bpf.bpf.o" -print0 | \
while IFS= read -r -d '' prog; do
    obj_name=$(echo "$prog" | grep -o "scx.*.bpf.o" | tr / _)
    cp -v "$prog" "${PROGS_DIR}/${obj_name}"
done
