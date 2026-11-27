#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

. "$(cd "$(dirname "$0")" && pwd)"/test_common.sh
ERR_CODE=0
pids=()

ublk_io_and_remove()
{
	run_io_and_remove "$@"
	ERR_CODE=$?
	if [ ${ERR_CODE} -ne 0 ]; then
		echo "$TID failure: $*"
	fi
	return "$ERR_CODE"
}

if ! _have_program fio; then
	exit "$UBLK_SKIP_CODE"
fi

_prep_test "stress" "run IO and remove device (user copy)"

_create_backfile 0 256M
_create_backfile 1 128M
_create_backfile 2 128M

ublk_io_and_remove 8G -t null -q 4 -u &
pids+=("$!")
ublk_io_and_remove 256M -t loop -q 4 -u "${UBLK_BACKFILES[0]}" &
pids+=("$!")
ublk_io_and_remove 256M -t stripe -q 4 -u "${UBLK_BACKFILES[1]}" "${UBLK_BACKFILES[2]}" &
pids+=("$!")
_wait_test_pids "${pids[@]}"
pids=()

ublk_io_and_remove 8G -t null -q 4 -u --nthreads 8 --per_io_tasks &
pids+=("$!")
ublk_io_and_remove 256M -t loop -q 4 -u --nthreads 8 --per_io_tasks "${UBLK_BACKFILES[0]}" &
pids+=("$!")
ublk_io_and_remove 256M -t stripe -q 4 -u --nthreads 8 --per_io_tasks "${UBLK_BACKFILES[1]}" "${UBLK_BACKFILES[2]}" &
pids+=("$!")
_wait_test_pids "${pids[@]}"
pids=()

_cleanup_test
_show_result $TID $ERR_CODE
