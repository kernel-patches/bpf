#!/bin/bash

set -eu

source $(cd $(dirname $0) && pwd)/helpers.sh

travis_fold start apply_local_patch "Apply local patches"
if ls ${VMTEST_ROOT}/diffs/*.diff 1>/dev/null 2>&1; then
  for file in ${VMTEST_ROOT}/diffs/*.diff; do
    if patch --dry-run -p1 < ${file}; then
      patch -p1 < ${file}
      echo "Successfully applied ${file}!"
    else
      echo "Failed to apply ${file}, skipping!"
    fi
  done
fi
travis_fold end apply_local_patch

travis_fold start build_kernel "Kernel build"
cp ${VMTEST_ROOT}/configs/latest.config .config
make -j $((4*$(nproc))) olddefconfig all
travis_fold end build_kernel
