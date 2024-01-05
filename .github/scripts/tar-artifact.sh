#!/bin/bash

set -eux

arch="${1}"
toolchain="${2}"

# Remove intermediate object files that we have no use for. Ideally
# we'd just exclude them from tar below, but it does not provide
# options to express the precise constraints.
find selftests/ -name "*.o" -a ! -name "*.bpf.o" -print0 | \
  xargs --null --max-args=10000 rm

# Strip debug information, which is excessively large (consuming
# bandwidth) while not actually being used (the kernel does not use
# DWARF to symbolize stacktraces).
strip --strip-debug "${KBUILD_OUTPUT}"/vmlinux

additional_file_list=()
if [ "${GITHUB_REPOSITORY}" == "kernel-patches/vmtest" ]; then
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

image_name=$(make -s image_name)

# zstd is installed by default in the runner images.
tar -cf - \
  "${KBUILD_OUTPUT}/.config" \
  "${KBUILD_OUTPUT}/${image_name}" \
  "${KBUILD_OUTPUT}/include/config/auto.conf" \
  "${KBUILD_OUTPUT}/include/generated/autoconf.h" \
  "${KBUILD_OUTPUT}/vmlinux" \
  "${additional_file_list[@]}" \
  --exclude '*.cmd' \
  --exclude '*.d' \
  --exclude '*.h' \
  --exclude '*.output' \
  selftests/bpf/ | zstd -T0 -19 -o "vmlinux-${arch}-${toolchain}.tar.zst"
