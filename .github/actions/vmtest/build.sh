#!/bin/bash

set -euo pipefail

ARCH="$1"
TOOLCHAIN="$2"
TOOLCHAIN_NAME="$(echo $TOOLCHAIN | cut -d '-' -f 1)"
TOOLCHAIN_VERSION="$(echo $TOOLCHAIN | cut -d '-' -f 2)"

if [ "$TOOLCHAIN_NAME" == "llvm" ]; then
export LLVM="-$TOOLCHAIN_VERSION"
fi

THISDIR="$(cd $(dirname $0) && pwd)"

source "${THISDIR}"/helpers.sh

travis_fold start build_kernel "Building kernel with $TOOLCHAIN"

cp ${GITHUB_WORKSPACE}/travis-ci/vmtest/configs/config-latest.${ARCH} .config

make -j $((4*$(nproc))) olddefconfig all > /dev/null

travis_fold end build_kernel
