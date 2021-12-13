#!/bin/bash

set -eu

DIFF_DIR="$(cd $(dirname $0) && pwd)/diffs"

if ls ${DIFF_DIR}/*.diff 1>/dev/null 2>&1; then
  for file in ${DIFF_DIR}/*.diff; do
    if patch --dry-run -p1 < "${file}"; then
      patch -p1 < "${file}"
      echo "Successfully applied ${file}!"
    else
      echo "Failed to apply ${file}, skipping!"
    fi
  done
fi
