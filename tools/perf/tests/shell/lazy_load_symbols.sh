#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Lazy symbol loading tests (exclusive)
#
# Verifies that perf script and perf report print the same output with
# --lazy-load-symbols as with the default eager loader.

set -e

shelldir=$(dirname "$0")
# shellcheck source=lib/perf_has_symbol.sh
. "${shelldir}"/lib/perf_has_symbol.sh
# shellcheck source=lib/lazy_names.sh
. "${shelldir}"/lib/lazy_names.sh

testsym="test_loop"
# Printed with -vv for each symbol table loaded with lazy names.
lazy_names=': [1-9][0-9]* \.(symtab|dynsym) symbols with lazy names$'

skip_test_missing_symbol ${testsym}

if ! perf check feature -q libelf
then
	echo "Lazy symbol loading [Skipped no libelf support]"
	exit 2
fi

perf_path=$(readlink -f "$(command -v perf)")
err=0
passed=0
temp_dir=$(mktemp -d /tmp/__perf_test.lazy_load.XXXXX)
perfdata="${temp_dir}/perf.data"
eager_out="${temp_dir}/eager.out"
lazy_out="${temp_dir}/lazy.out"
lazy_err="${temp_dir}/lazy.err"
ns_pid=

cleanup() {
	if [ -n "${ns_pid}" ]; then
		kill "${ns_pid}" 2> /dev/null || true
		wait "${ns_pid}" 2> /dev/null || true
	fi
	rm -rf "${temp_dir}"
	trap - EXIT TERM INT
}

trap_cleanup() {
	echo "Unexpected signal in ${FUNCNAME[1]}"
	cleanup
	exit 1
}
trap trap_cleanup EXIT TERM INT

# check_lazy_names CASE
# Return whether perf was loaded with lazy names. If not, report CASE as
# skipped when perf's symbol table cannot have them, and as failed otherwise.
check_lazy_names() {
	if grep -F "${perf_path}: " "${lazy_err}" | grep -Eq "${lazy_names}"
	then
		return 0
	fi
	if ! command -v readelf > /dev/null
	then
		echo "$1 [Skipped no readelf to check perf's symbol table]"
	elif lazy_names_disabled "${perf_path}"
	then
		echo "$1 [Skipped perf loads its symbol names eagerly]"
	else
		echo "$1 [Failed perf has no lazy names]"
		err=1
	fi
	return 1
}

test_lazy_load_identical() {
	echo "Lazy-load output matches eager loader"

	if ! perf record -o "${perfdata}" -g -- perf test -w thloop 2> /dev/null
	then
		echo "Lazy-load identical [Skipped record not supported]"
		return 0
	fi

	if ! perf script -vv -i "${perfdata}" 2> /dev/null > "${eager_out}" || \
	   ! perf script -vv --lazy-load-symbols -i "${perfdata}" \
		2> "${lazy_err}" > "${lazy_out}"
	then
		echo "Lazy-load identical [Failed perf script error]"
		err=1
		return
	fi
	# The comparison is only meaningful if something actually resolved;
	# two all-[unknown] outputs would also match. Without samples in perf,
	# perf is not loaded and has no lazy names either.
	if ! grep -q "${testsym}" "${eager_out}"
	then
		echo "Lazy-load identical [Skipped no ${testsym} resolved]"
		return 0
	fi
	if ! cmp -s "${eager_out}" "${lazy_out}"
	then
		echo "Lazy-load identical [Failed output differs from eager]"
		err=1
		return
	fi
	if ! check_lazy_names "Lazy-load identical"
	then
		return
	fi
	echo "Lazy-load identical [Success]"
	passed=$((passed + 1))
}

test_lazy_load_report() {
	local eager_report="${temp_dir}/eager.report"
	local lazy_report="${temp_dir}/lazy.report"
	local mode

	echo "Lazy-load perf report output matches eager loader"

	if ! grep -qs "${testsym}" "${eager_out}"
	then
		echo "Lazy-load report [Skipped no ${testsym} resolved]"
		return 0
	fi
	for mode in "--no-children -g none" "--children"
	do
		# shellcheck disable=SC2086
		if ! perf report -vv --stdio ${mode} -i "${perfdata}" \
			2> /dev/null > "${eager_report}" ||
		   ! perf report -vv --stdio ${mode} --lazy-load-symbols \
			-i "${perfdata}" 2> "${lazy_err}" > "${lazy_report}"
		then
			echo "Lazy-load report [Failed perf report ${mode} error]"
			err=1
			return
		fi
		# -q would turn off the debug output, so drop the header,
		# which has a random tip.
		if ! cmp -s <(grep -v '^#' "${eager_report}") \
			    <(grep -v '^#' "${lazy_report}")
		then
			echo "Lazy-load report [Failed ${mode} output differs from eager]"
			err=1
			return
		fi
		if ! check_lazy_names "Lazy-load report"
		then
			return
		fi
	done
	echo "Lazy-load report [Success]"
	passed=$((passed + 1))
}

# perf script output for a process in another mount namespace, with the
# binary in the build-id cache, must not change with lazy names.
test_lazy_load_mount_ns() {
	echo "Lazy-load parity for a process in another mount namespace"

	if [ "$(id -u)" != 0 ] || ! command -v unshare > /dev/null
	then
		echo "Lazy-load mount namespace [Skipped needs root and unshare]"
		return 0
	fi

	local buildid_dir="${temp_dir}/buildid"
	local nsdata="${temp_dir}/ns.data"

	# The workload sees an empty build-id cache; perf sees the real one.
	mkdir -p "${buildid_dir}"
	unshare -m --propagation private sh -c \
		"mount -t tmpfs none '${buildid_dir}' && exec perf test -w thloop 30" &
	ns_pid=$!
	for _ in $(seq 50)
	do
		if [ "$(readlink "/proc/${ns_pid}/exe" 2> /dev/null)" = "${perf_path}" ]
		then
			break
		fi
		sleep 0.1
	done
	if [ "$(readlink "/proc/${ns_pid}/exe" 2> /dev/null)" != "${perf_path}" ]
	then
		echo "Lazy-load mount namespace [Skipped cannot start workload]"
		return 0
	fi

	if ! perf record -N -o "${nsdata}" -p "${ns_pid}" -- sleep 1 2> /dev/null ||
	   ! perf --buildid-dir "${buildid_dir}" buildid-cache -a "${perf_path}" \
		2> /dev/null ||
	   [ -z "$(ls -A "${buildid_dir}/.build-id" 2> /dev/null)" ]
	then
		echo "Lazy-load mount namespace [Skipped record or build-id cache failed]"
		return 0
	fi
	if ! perf --buildid-dir "${buildid_dir}" script -vv -i "${nsdata}" \
		2> /dev/null > "${eager_out}" ||
	   ! perf --buildid-dir "${buildid_dir}" script -vv --lazy-load-symbols \
		-i "${nsdata}" 2> "${lazy_err}" > "${lazy_out}"
	then
		echo "Lazy-load mount namespace [Failed perf script error]"
		err=1
		return
	fi

	if ! grep -q "${testsym}" "${eager_out}"
	then
		echo "Lazy-load mount namespace [Skipped no ${testsym} resolved]"
		return 0
	fi
	if ! cmp -s "${eager_out}" "${lazy_out}"
	then
		echo "Lazy-load mount namespace [Failed output differs from eager]"
		err=1
		return
	fi
	# For a process in another mount namespace, only a symbol table from
	# the build-id cache (origin B or D in perf report -v) has lazy names.
	if ! perf --buildid-dir "${buildid_dir}" report -v --stdio --sort sym \
		-i "${nsdata}" 2> /dev/null | grep -Eq " [BD] \[\.\] ${testsym}( |$)"
	then
		echo "Lazy-load mount namespace [Skipped perf symbols not from the build-id cache]"
		return 0
	fi
	if ! check_lazy_names "Lazy-load mount namespace"
	then
		return
	fi
	echo "Lazy-load mount namespace [Success]"
	passed=$((passed + 1))
}

test_lazy_load_identical
test_lazy_load_report
test_lazy_load_mount_ns

cleanup
if [ "${err}" -eq 0 ] && [ "${passed}" -eq 0 ]
then
	err=2
fi
exit $err
