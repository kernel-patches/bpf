#!/bin/bash

set -euo pipefail

PROGS_DIR=$1

mkdir -p "${PROGS_DIR}"

find "${SCX_BUILD_OUTPUT}" -type f -name "*.bpf.o" -printf '%P\0' | \
while IFS= read -r -d '' prog; do
    obj_name=$(echo "${prog}" | tr / _)
    cp -v "${SCX_BUILD_OUTPUT}/$prog" "${PROGS_DIR}/${obj_name}"
done
