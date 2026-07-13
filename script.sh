#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0

set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUT="${OUT:-$ROOT/.selftests-bpf}"
if [[ -z "${JOBS:-}" ]]; then
	if command -v nproc >/dev/null 2>&1; then
		JOBS="$(nproc)"
	elif command -v sysctl >/dev/null 2>&1; then
		JOBS="$(sysctl -n hw.ncpu)"
	else
		JOBS=1
	fi
fi
LIGHTSWITCH_BPF_SRC="${LIGHTSWITCH_BPF_SRC:-/Users/javierhonduco/src/lightswitch/bpf}"
if [[ ! -d "$LIGHTSWITCH_BPF_SRC" && -d /Users/javierhonduco/src/lightswitch/src/bpf ]]; then
	LIGHTSWITCH_BPF_SRC=/Users/javierhonduco/src/lightswitch/src/bpf
fi
LIGHTSWITCH_BPF_DIR="${LIGHTSWITCH_BPF_DIR:-$ROOT/tools/testing/selftests/bpf/progs/lightswitch}"

usage() {
	cat <<EOF
Usage: $0 [smoke|full|vm|make-target...]

Modes:
  smoke   Build veristat, libbpf, and the lightswitch BPF objects, then run
          the lightswitch regression kselftest on the host. This is the default.
  full    Run the host's tools/testing/selftests/bpf make run_tests target.
          This requires the host kernel BTF to match this checkout closely.
  vm      Build a matching BPF selftest kernel and run BPF selftests in QEMU
          through tools/testing/selftests/bpf/vmtest.sh. This requires KVM
          when PLATFORM matches the host architecture.

Environment:
  OUT                 selftest build output directory, default: $ROOT/.selftests-bpf
  JOBS                make parallelism, default: nproc
  LIGHTSWITCH_BPF_DIR default: tools/testing/selftests/bpf/progs/lightswitch
  LIGHTSWITCH_BPF_SRC source mirrored by the vendored test case,
                      default: /Users/javierhonduco/src/lightswitch/bpf
EOF
}

target_args=("$@")
if [[ ${#target_args[@]} -eq 0 ]]; then
	target_args=(smoke)
fi

case "${target_args[0]}" in
	-h|--help|help)
		usage
		exit 0
		;;
esac

if [[ "${target_args[0]}" == vm && ${#target_args[@]} -eq 2 &&
      ( "${target_args[1]}" == -h || "${target_args[1]}" == --help ) ]]; then
	exec bash "$ROOT/tools/testing/selftests/bpf/vmtest.sh" "${target_args[1]}"
fi

if [[ "${target_args[0]}" == vm ]]; then
	host_platform="$(uname -m)"
	vm_platform="${PLATFORM:-$host_platform}"
	if [[ "$vm_platform" == "$host_platform" && ! -e /dev/kvm ]]; then
		cat >&2 <<EOF
vm mode requires /dev/kvm for same-architecture QEMU runs.
Use smoke mode for the local lightswitch regression, or set PLATFORM and
CROSS_COMPILE for a non-KVM cross-architecture vmtest run.
EOF
		exit 1
	fi
fi

if [[ "${BPF_SELFTESTS_IN_NIX:-0}" != 1 ]]; then
	nix_packages=(
		nixpkgs#bash
		nixpkgs#bc
		nixpkgs#bison
		nixpkgs#elfutils
		nixpkgs#elfutils.dev
		nixpkgs#flex
		nixpkgs#gcc
		nixpkgs#gnumake
		nixpkgs#lld
		nixpkgs#llvmPackages.clang-unwrapped
		nixpkgs#llvm
		nixpkgs#openssl
		nixpkgs#openssl.dev
		nixpkgs#pahole
		nixpkgs#perl
		nixpkgs#pkg-config
		nixpkgs#python3
		nixpkgs#rsync
		nixpkgs#zlib
		nixpkgs#zlib.dev
	)
	if [[ "${target_args[0]}" == vm ]]; then
		nix_packages+=(
			nixpkgs#curl
			nixpkgs#e2fsprogs
			nixpkgs#qemu
			nixpkgs#util-linux
			nixpkgs#zstd
		)
	fi
	exec nix shell \
		"${nix_packages[@]}" \
		--command env BPF_SELFTESTS_IN_NIX=1 \
			OUT="$OUT" \
			JOBS="$JOBS" \
			LIGHTSWITCH_BPF_DIR="$LIGHTSWITCH_BPF_DIR" \
			LIGHTSWITCH_BPF_SRC="$LIGHTSWITCH_BPF_SRC" \
			bash "$0" "$@"
fi

if [[ ! -d "$LIGHTSWITCH_BPF_DIR" ]]; then
	echo "lightswitch BPF directory not found: $LIGHTSWITCH_BPF_DIR" >&2
	exit 1
fi

if [[ ! -d "$LIGHTSWITCH_BPF_SRC" ]]; then
	echo "lightswitch BPF source directory not found: $LIGHTSWITCH_BPF_SRC" >&2
	exit 1
fi

cd "$ROOT"
mkdir -p "$OUT"

elfutils_dev="$(nix build --no-link --print-out-paths nixpkgs#elfutils.dev)"
elfutils_out="$(nix build --no-link --print-out-paths nixpkgs#elfutils.out)"
openssl_dev="$(nix build --no-link --print-out-paths nixpkgs#openssl.dev)"
openssl_out="$(nix build --no-link --print-out-paths nixpkgs#openssl.out)"
zlib_dev="$(nix build --no-link --print-out-paths nixpkgs#zlib.dev)"
zlib_out="$(nix build --no-link --print-out-paths nixpkgs#zlib.out)"

extra_cflags="${EXTRA_CFLAGS:-} -I$elfutils_dev/include -I$openssl_dev/include -I$zlib_dev/include"
extra_ldflags="${EXTRA_LDFLAGS:-} -L$elfutils_out/lib -L$openssl_out/lib -L$zlib_out/lib"
export PKG_CONFIG_PATH="$openssl_dev/lib/pkgconfig:$elfutils_dev/lib/pkgconfig:$zlib_dev/share/pkgconfig:${PKG_CONFIG_PATH:-}"
export CPATH="$elfutils_dev/include:$openssl_dev/include:$zlib_dev/include:${CPATH:-}"
export C_INCLUDE_PATH="$elfutils_dev/include:$openssl_dev/include:$zlib_dev/include:${C_INCLUDE_PATH:-}"
export LIBRARY_PATH="$elfutils_out/lib:$openssl_out/lib:$zlib_out/lib:${LIBRARY_PATH:-}"
export LD_LIBRARY_PATH="$elfutils_out/lib:$openssl_out/lib:$zlib_out/lib:${LD_LIBRARY_PATH:-}"

make_bpf_selftests() {
	make -C tools/testing/selftests/bpf \
		OUTPUT="$OUT" \
		LLVM=1 \
		LIGHTSWITCH_BPF_DIR="$LIGHTSWITCH_BPF_DIR" \
		EXTRA_CFLAGS="$extra_cflags" \
		HOST_EXTRACFLAGS="$extra_cflags" \
		EXTRA_LDFLAGS="$extra_ldflags" \
		-j"$JOBS" \
		"$@"
}

case "${target_args[0]}" in
	-h|--help|help)
		usage
		;;
	smoke)
		make_bpf_selftests \
			"$OUT/veristat" \
			"$OUT/lightswitch_bpf/profiler.bpf.o" \
			"$OUT/lightswitch_bpf/tracers.bpf.o"
		(
			cd "$OUT"
			"$ROOT/tools/testing/selftests/bpf/test_lightswitch_bpf_build.sh"
		)
		;;
	full)
		make_bpf_selftests run_tests
		;;
	vm)
		vm_args=("${target_args[@]:1}")
		if [[ ${#vm_args[@]} -eq 0 ]]; then
			vm_args=(-- env BPF_STRICT_BUILD=0 SKIP_DOCS=1 make run_tests)
		fi
		exec env \
			OUTPUT_DIR="$OUT/vm" \
			LIGHTSWITCH_BPF_DIR="$LIGHTSWITCH_BPF_DIR" \
			BPF_STRICT_BUILD="${BPF_STRICT_BUILD:-0}" \
			SKIP_DOCS="${SKIP_DOCS:-1}" \
			EXTRA_CFLAGS="$extra_cflags" \
			HOSTCFLAGS="$extra_cflags" \
			HOST_EXTRACFLAGS="$extra_cflags" \
			EXTRA_LDFLAGS="$extra_ldflags" \
			"$ROOT/tools/testing/selftests/bpf/vmtest.sh" \
			-d "$OUT/vm" \
			-j "$JOBS" \
			"${vm_args[@]}"
		;;
	*)
		make_bpf_selftests "${target_args[@]}"
		;;
esac
