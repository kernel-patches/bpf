#!/bin/bash

set -x -euo pipefail

TMPFS_SIZE=20 # GB
MEM_TOTAL=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)

# sanity check: total mem is at least double TMPFS_SIZE
if [ $MEM_TOTAL -lt $(($TMPFS_SIZE*1024*2)) ]; then
    echo "tmpfsify-workspace.sh: will not allocate tmpfs, total memory is too low (${MEM_TOTAL}MB)"
    exit 0
fi

dir="$(basename "$GITHUB_WORKSPACE")"
cd "$(dirname "$GITHUB_WORKSPACE")"
mv "${dir}" "${dir}.backup"
mkdir "${dir}"
sudo mount -t tmpfs -o size=${TMPFS_SIZE}G tmpfs "${dir}"
rsync -a "${dir}.backup/" "${dir}"
cd -

