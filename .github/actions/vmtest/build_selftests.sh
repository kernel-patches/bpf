#!/bin/bash

set -euo pipefail

THISDIR="$(cd $(dirname $0) && pwd)"

source "${THISDIR}"/helpers.sh

TOOLCHAIN="$1"
TOOLCHAIN_NAME="$(echo $TOOLCHAIN | cut -d '-' -f 1)"
TOOLCHAIN_VERSION="$(echo $TOOLCHAIN | cut -d '-' -f 2)"

if [ "$TOOLCHAIN_NAME" == "llvm" ]; then
export LLVM="-$TOOLCHAIN_VERSION"
LLVM_VER=$TOOLCHAIN_VERSION
else
LLVM_VER=15
fi

travis_fold start prepare_selftests "Building selftests with $TOOLCHAIN"

LIBBPF_PATH="${REPO_ROOT}"

PREPARE_SELFTESTS_SCRIPT=${THISDIR}/prepare_selftests-${KERNEL}.sh
if [ -f "${PREPARE_SELFTESTS_SCRIPT}" ]; then
	(cd "${REPO_ROOT}/${REPO_PATH}/tools/testing/selftests/bpf" && ${PREPARE_SELFTESTS_SCRIPT})
fi

if [[ "${KERNEL}" = 'LATEST' ]]; then
	VMLINUX_H=
else
	VMLINUX_H=${THISDIR}/vmlinux.h
fi

cd ${REPO_ROOT}/${REPO_PATH}
make \
	CLANG=clang-${LLVM_VER} \
	LLC=llc-${LLVM_VER} \
	LLVM_STRIP=llvm-strip-${LLVM_VER} \
	VMLINUX_BTF="${VMLINUX_BTF}" \
	VMLINUX_H="${VMLINUX_H}" \
	-C "${REPO_ROOT}/${REPO_PATH}/tools/testing/selftests/bpf" \
	-j $((4*$(nproc))) > /dev/null
cd -
mkdir "${LIBBPF_PATH}"/selftests
cp -R "${REPO_ROOT}/${REPO_PATH}/tools/testing/selftests/bpf" \
	"${LIBBPF_PATH}"/selftests
cd "${LIBBPF_PATH}"
rm selftests/bpf/.gitignore
git add selftests

travis_fold end prepare_selftests
