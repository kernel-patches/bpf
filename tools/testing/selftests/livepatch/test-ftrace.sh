#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2019 Joe Lawrence <joe.lawrence@redhat.com>

. $(dirname $0)/functions.sh

MOD_LIVEPATCH=test_klp_livepatch

setup_config


# - verify that kernel.ftrace_enabled=0 is refused (deprecated knob)

start_test "ftrace_enabled sysctl write is refused (deprecated)"

set_ftrace_enabled --fail 0

check_result "livepatch: sysctl: setting key \"kernel.ftrace_enabled\": Operation not supported"


# - verify livepatch can load
# - check if traces have a patched function
# - reset trace and unload livepatch

start_test "trace livepatched function and check that the live patch remains in effect"

FUNCTION_NAME="livepatch_cmdline_proc_show"

load_lp $MOD_LIVEPATCH
trace_function "$FUNCTION_NAME"

if [[ "$(cat /proc/cmdline)" == "$MOD_LIVEPATCH: this has been live patched" ]] ; then
	log "livepatch: ok"
fi

check_traced_functions "$FUNCTION_NAME"

disable_lp $MOD_LIVEPATCH
unload_lp $MOD_LIVEPATCH

check_result "% insmod test_modules/$MOD_LIVEPATCH.ko
livepatch: enabling patch '$MOD_LIVEPATCH'
livepatch: '$MOD_LIVEPATCH': initializing patching transition
livepatch: '$MOD_LIVEPATCH': starting patching transition
livepatch: '$MOD_LIVEPATCH': completing patching transition
livepatch: '$MOD_LIVEPATCH': patching complete
livepatch: ok
% echo 0 > $SYSFS_KLP_DIR/$MOD_LIVEPATCH/enabled
livepatch: '$MOD_LIVEPATCH': initializing unpatching transition
livepatch: '$MOD_LIVEPATCH': starting unpatching transition
livepatch: '$MOD_LIVEPATCH': completing unpatching transition
livepatch: '$MOD_LIVEPATCH': unpatching complete
% rmmod $MOD_LIVEPATCH"


# - trace a function
# - verify livepatch can load targgeting on the same traced function
# - check if the livepatch is in effect
# - reset trace and unload livepatch

start_test "livepatch a traced function and check that the live patch remains in effect"

FUNCTION_NAME="cmdline_proc_show"

trace_function "$FUNCTION_NAME"
load_lp $MOD_LIVEPATCH

if [[ "$(cat /proc/cmdline)" == "$MOD_LIVEPATCH: this has been live patched" ]] ; then
	log "livepatch: ok"
fi

check_traced_functions "$FUNCTION_NAME"

disable_lp $MOD_LIVEPATCH
unload_lp $MOD_LIVEPATCH

check_result "% insmod test_modules/$MOD_LIVEPATCH.ko
livepatch: enabling patch '$MOD_LIVEPATCH'
livepatch: '$MOD_LIVEPATCH': initializing patching transition
livepatch: '$MOD_LIVEPATCH': starting patching transition
livepatch: '$MOD_LIVEPATCH': completing patching transition
livepatch: '$MOD_LIVEPATCH': patching complete
livepatch: ok
% echo 0 > $SYSFS_KLP_DIR/$MOD_LIVEPATCH/enabled
livepatch: '$MOD_LIVEPATCH': initializing unpatching transition
livepatch: '$MOD_LIVEPATCH': starting unpatching transition
livepatch: '$MOD_LIVEPATCH': completing unpatching transition
livepatch: '$MOD_LIVEPATCH': unpatching complete
% rmmod $MOD_LIVEPATCH"

exit 0
