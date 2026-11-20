#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

. "$(cd "$(dirname "$0")" && pwd)"/test_common.sh
ERR_CODE=0
pids=()

if ! _have_program fio; then
	exit "$UBLK_SKIP_CODE"
fi

ublk_io_and_kill_daemon()
{
	run_io_and_kill_daemon "$@"
	ERR_CODE=$?
	if [ ${ERR_CODE} -ne 0 ]; then
		echo "$TID failure: $*"
	fi
	return "$ERR_CODE"
}

_prep_test "stress" "run IO and kill ublk server"

_create_backfile 0 256M
_create_backfile 1 128M
_create_backfile 2 128M

for nr_queue in 1 4; do
	ublk_io_and_kill_daemon 8G -t null -q "$nr_queue" &
	pids+=("$!")
	ublk_io_and_kill_daemon 256M -t loop -q "$nr_queue" "${UBLK_BACKFILES[0]}" &
	pids+=("$!")
	ublk_io_and_kill_daemon 256M -t stripe -q "$nr_queue" "${UBLK_BACKFILES[1]}" "${UBLK_BACKFILES[2]}" &
	pids+=("$!")
	_wait_test_pids "${pids[@]}"
	pids=()
done

_cleanup_test
_show_result $TID $ERR_CODE
