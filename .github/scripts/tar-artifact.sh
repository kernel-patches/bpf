#!/bin/bash

set -eux

# Assumptions:
#   - $(pwd) is the root of kernel repo we're tarring
#   - zstd is installed by default in the runner images

if [ ! -d "${KBUILD_OUTPUT:-}" ]; then
  echo "KBUILD_OUTPUT must be a directory"
  exit 1
fi

arch="${1}"
toolchain="${2}"
archive_make_helpers="${3:-0}"

# Convert a platform (as returned by uname -m) to the kernel
# arch (as expected by ARCH= env).
platform_to_kernel_arch() {
  case $1 in
    s390x)
      echo "s390"
      ;;
    aarch64)
      echo "arm64"
      ;;
    riscv64)
      echo "riscv"
      ;;
    x86_64)
      echo "x86"
      ;;
    *)
      echo "$1"
      ;;
  esac
}

# Remove intermediate object files that we have no use for. Ideally
# we'd just exclude them from tar below, but it does not provide
# options to express the precise constraints.
find selftests/ -name "*.o" -a ! -name "*.bpf.o" -print0 | \
  xargs --null --max-args=10000 rm

# Strip debug information, which is excessively large (consuming
# bandwidth) while not actually being used (the kernel does not use
# DWARF to symbolize stacktraces).
"${arch}"-linux-gnu-strip --strip-debug "${KBUILD_OUTPUT}"/vmlinux

image_name=$(make ARCH="$(platform_to_kernel_arch "${arch}")" -s image_name)
kbuild_output_file_list=(
  ".config"
  "${image_name}"
  "include/config/auto.conf"
  "include/generated/autoconf.h"
  "vmlinux"
)

# While we are preparing the tarball, move $KBUILD_OUTPUT to a tmp
# location just in case it's inside the repo root
tmp=$(mktemp -d)
mv "${KBUILD_OUTPUT}" "${tmp}"
stashed_kbuild_output=${tmp}/$(basename "${KBUILD_OUTPUT}")

# Note: ${local_kbuild_output} must point to ./kbuild-output because
# of the tar command at the bottom.
local_kbuild_output=$(realpath kbuild-output)
mkdir -p "${local_kbuild_output}"

for file in "${kbuild_output_file_list[@]}"; do
  mkdir -p "$(dirname "${local_kbuild_output}/${file}")"
  cp -a "${stashed_kbuild_output}/${file}" "${local_kbuild_output}/${file}"
done

additional_file_list=()
if [ $archive_make_helpers -ne 0 ]; then
  # Package up a bunch of additional infrastructure to support running
  # 'make kernelrelease' and bpf tool checks later on.
  mapfile -t additional_file_list < <(find . -iname Makefile)
  additional_file_list+=(
    "scripts/"
    "tools/testing/selftests/bpf/"
    "tools/include/"
    "tools/bpf/bpftool/"
  )
fi


tar -cf - \
    kbuild-output \
    "${additional_file_list[@]}" \
    --exclude '*.cmd'                  \
    --exclude '*.d'                    \
    --exclude '*.h'                    \
    --exclude '*.output'               \
    selftests/bpf/                     \
  | zstd -T0 -19 -o "vmlinux-${arch}-${toolchain}.tar.zst"

# Cleanup and restore the original KBUILD_OUTPUT
# We have to put KBUILD_OUTPUT back to its original location for actions/cache
rm -rf "${local_kbuild_output}"
mv "${stashed_kbuild_output}" "${KBUILD_OUTPUT}"
