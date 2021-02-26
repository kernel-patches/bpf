#!/bin/bash

set -eu

source $(cd $(dirname $0) && pwd)/helpers.sh

travis_fold start build_kernel "Kernel build"
cp ${VMTEST_ROOT}/configs/latest.config .config
make -j $((4*$(nproc))) olddefconfig all
travis_fold end build_kernel
