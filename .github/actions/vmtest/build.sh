#!/bin/bash

set -euo pipefail

THISDIR="$(cd $(dirname $0) && pwd)"

source "${THISDIR}"/helpers.sh

travis_fold start build_kernel "Building kernel"

cp "${GITHUB_ACTION_PATH}"/latest.config .config
make -j $((4*$(nproc))) olddefconfig all > /dev/null

travis_fold end build_kernel
