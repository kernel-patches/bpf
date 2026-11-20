#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 Yafang Shao <laoar.shao@gmail.com>

. $(dirname $0)/functions.sh

MOD_MEMINFO=test_klp_meminfo_lp
MOD_MEMINFO2=test_klp_meminfo_lp2
MOD_CMDLINE=test_klp_cmdline_lp
MOD_STATE=test_klp_state
MOD_STATE2=test_klp_state2

setup_config
detect_provides_attr

# The provides/obsoletes based tests only run on kernels that no longer
# support the legacy "replace" attribute.
if [[ "$HAS_PROVIDES_ATTR" != "1" ]]; then
	skip_exit "kernel still supports the legacy replace attribute"
fi


# - load a livepatch with provides=0 (cmdline), then another with
#   provides=0 (meminfo). The second replaces the first (same provides).
# - unload the remaining livepatch

start_test "provides 0 replaces provides 0"

load_lp $MOD_CMDLINE provides=0
load_lp $MOD_MEMINFO provides=0

check_sysfs_value "$MOD_MEMINFO" "enabled" "1"

disable_lp $MOD_MEMINFO
unload_lp $MOD_MEMINFO
unload_lp $MOD_CMDLINE

check_result "% insmod test_modules/$MOD_CMDLINE.ko provides=0
livepatch: enabling patch '$MOD_CMDLINE'
livepatch: '$MOD_CMDLINE': initializing patching transition
livepatch: '$MOD_CMDLINE': starting patching transition
livepatch: '$MOD_CMDLINE': completing patching transition
livepatch: '$MOD_CMDLINE': patching complete
% insmod test_modules/$MOD_MEMINFO.ko provides=0
livepatch: enabling patch '$MOD_MEMINFO'
livepatch: '$MOD_MEMINFO': initializing patching transition
livepatch: '$MOD_MEMINFO': starting patching transition
livepatch: '$MOD_MEMINFO': completing patching transition
livepatch: '$MOD_MEMINFO': patching complete
% echo 0 > $SYSFS_KLP_DIR/$MOD_MEMINFO/enabled
livepatch: '$MOD_MEMINFO': initializing unpatching transition
livepatch: '$MOD_MEMINFO': starting unpatching transition
livepatch: '$MOD_MEMINFO': completing unpatching transition
livepatch: '$MOD_MEMINFO': unpatching complete
% rmmod $MOD_MEMINFO
% rmmod $MOD_CMDLINE"


# - load a livepatch with provides=1 (cmdline), then another with
#   provides=1 (meminfo). The second replaces the first (same provides).
# - unload the remaining livepatch

start_test "same provides replaces"

load_lp $MOD_CMDLINE provides=1
load_lp $MOD_MEMINFO provides=1

check_sysfs_value "$MOD_MEMINFO" "enabled" "1"

disable_lp $MOD_MEMINFO
unload_lp $MOD_MEMINFO
unload_lp $MOD_CMDLINE

check_result "% insmod test_modules/$MOD_CMDLINE.ko provides=1
livepatch: enabling patch '$MOD_CMDLINE'
livepatch: '$MOD_CMDLINE': initializing patching transition
livepatch: '$MOD_CMDLINE': starting patching transition
livepatch: '$MOD_CMDLINE': completing patching transition
livepatch: '$MOD_CMDLINE': patching complete
% insmod test_modules/$MOD_MEMINFO.ko provides=1
livepatch: enabling patch '$MOD_MEMINFO'
livepatch: '$MOD_MEMINFO': initializing patching transition
livepatch: '$MOD_MEMINFO': starting patching transition
livepatch: '$MOD_MEMINFO': completing patching transition
livepatch: '$MOD_MEMINFO': patching complete
% echo 0 > $SYSFS_KLP_DIR/$MOD_MEMINFO/enabled
livepatch: '$MOD_MEMINFO': initializing unpatching transition
livepatch: '$MOD_MEMINFO': starting unpatching transition
livepatch: '$MOD_MEMINFO': completing unpatching transition
livepatch: '$MOD_MEMINFO': unpatching complete
% rmmod $MOD_MEMINFO
% rmmod $MOD_CMDLINE"


# - load a livepatch with provides=1 (cmdline), then another with
#   provides=2 and obsoletes=[1] (meminfo). The second replaces the
#   first (obsoletes contains the first patch's provides id).
# - verify the provides/obsoletes sysfs values
# - unload the remaining livepatch

start_test "obsoletes replaces"

load_lp $MOD_CMDLINE provides=1
load_lp $MOD_MEMINFO provides=2 obsoletes=1

check_sysfs_value "$MOD_MEMINFO" "provides" "2"
check_sysfs_value "$MOD_MEMINFO" "obsoletes" "1"

disable_lp $MOD_MEMINFO
unload_lp $MOD_MEMINFO
unload_lp $MOD_CMDLINE

check_result "% insmod test_modules/$MOD_CMDLINE.ko provides=1
livepatch: enabling patch '$MOD_CMDLINE'
livepatch: '$MOD_CMDLINE': initializing patching transition
livepatch: '$MOD_CMDLINE': starting patching transition
livepatch: '$MOD_CMDLINE': completing patching transition
livepatch: '$MOD_CMDLINE': patching complete
% insmod test_modules/$MOD_MEMINFO.ko provides=2 obsoletes=1
livepatch: enabling patch '$MOD_MEMINFO'
livepatch: '$MOD_MEMINFO': initializing patching transition
livepatch: '$MOD_MEMINFO': starting patching transition
livepatch: '$MOD_MEMINFO': completing patching transition
livepatch: '$MOD_MEMINFO': patching complete
% echo 0 > $SYSFS_KLP_DIR/$MOD_MEMINFO/enabled
livepatch: '$MOD_MEMINFO': initializing unpatching transition
livepatch: '$MOD_MEMINFO': starting unpatching transition
livepatch: '$MOD_MEMINFO': completing unpatching transition
livepatch: '$MOD_MEMINFO': unpatching complete
% rmmod $MOD_MEMINFO
% rmmod $MOD_CMDLINE"


# - load two livepatches with different provides ids that modify
#   different functions and verify that they coexist
# - in particular, verify that provides=0 does NOT replace a patch
#   with a different provides id
# - unload both livepatches

start_test "provides 0 coexists with provides 1"

load_lp $MOD_CMDLINE provides=0
load_lp $MOD_MEMINFO provides=1

grep 'live patched' /proc/cmdline > /dev/kmsg
grep 'live patched' /proc/meminfo > /dev/kmsg

disable_lp $MOD_CMDLINE
unload_lp $MOD_CMDLINE
disable_lp $MOD_MEMINFO
unload_lp $MOD_MEMINFO

check_result "% insmod test_modules/$MOD_CMDLINE.ko provides=0
livepatch: enabling patch '$MOD_CMDLINE'
livepatch: '$MOD_CMDLINE': initializing patching transition
livepatch: '$MOD_CMDLINE': starting patching transition
livepatch: '$MOD_CMDLINE': completing patching transition
livepatch: '$MOD_CMDLINE': patching complete
% insmod test_modules/$MOD_MEMINFO.ko provides=1
livepatch: enabling patch '$MOD_MEMINFO'
livepatch: '$MOD_MEMINFO': initializing patching transition
livepatch: '$MOD_MEMINFO': starting patching transition
livepatch: '$MOD_MEMINFO': completing patching transition
livepatch: '$MOD_MEMINFO': patching complete
$MOD_CMDLINE: this has been live patched
$MOD_MEMINFO: this has been live patched
% echo 0 > $SYSFS_KLP_DIR/$MOD_CMDLINE/enabled
livepatch: '$MOD_CMDLINE': initializing unpatching transition
livepatch: '$MOD_CMDLINE': starting unpatching transition
livepatch: '$MOD_CMDLINE': completing unpatching transition
livepatch: '$MOD_CMDLINE': unpatching complete
% rmmod $MOD_CMDLINE
% echo 0 > $SYSFS_KLP_DIR/$MOD_MEMINFO/enabled
livepatch: '$MOD_MEMINFO': initializing unpatching transition
livepatch: '$MOD_MEMINFO': starting unpatching transition
livepatch: '$MOD_MEMINFO': completing unpatching transition
livepatch: '$MOD_MEMINFO': unpatching complete
% rmmod $MOD_MEMINFO"


# - load a livepatch with provides=2 and obsoletes=[1] (meminfo),
#   then another with provides=1 (cmdline). The second patch does not
#   list provides=2 in its own obsoletes list, so it does not replace
#   the first one: the obsoletes relationship is not symmetric and
#   both livepatches coexist.
# - verify that both livepatches remain active
# - unload both livepatches
#
#   MOD_MEMINFO(provides=2, obsoletes=[1])  -- loaded first
#   MOD_CMDLINE(provides=1)                 -- loaded second, coexists

start_test "obsoletes is not symmetric"

load_lp $MOD_MEMINFO provides=2 obsoletes=1
load_lp $MOD_CMDLINE provides=1

grep 'live patched' /proc/cmdline > /dev/kmsg
grep 'live patched' /proc/meminfo > /dev/kmsg

disable_lp $MOD_CMDLINE
unload_lp $MOD_CMDLINE
disable_lp $MOD_MEMINFO
unload_lp $MOD_MEMINFO

check_result "% insmod test_modules/$MOD_MEMINFO.ko provides=2 obsoletes=1
livepatch: enabling patch '$MOD_MEMINFO'
livepatch: '$MOD_MEMINFO': initializing patching transition
livepatch: '$MOD_MEMINFO': starting patching transition
livepatch: '$MOD_MEMINFO': completing patching transition
livepatch: '$MOD_MEMINFO': patching complete
% insmod test_modules/$MOD_CMDLINE.ko provides=1
livepatch: enabling patch '$MOD_CMDLINE'
livepatch: '$MOD_CMDLINE': initializing patching transition
livepatch: '$MOD_CMDLINE': starting patching transition
livepatch: '$MOD_CMDLINE': completing patching transition
livepatch: '$MOD_CMDLINE': patching complete
$MOD_CMDLINE: this has been live patched
$MOD_MEMINFO: this has been live patched
% echo 0 > $SYSFS_KLP_DIR/$MOD_CMDLINE/enabled
livepatch: '$MOD_CMDLINE': initializing unpatching transition
livepatch: '$MOD_CMDLINE': starting unpatching transition
livepatch: '$MOD_CMDLINE': completing unpatching transition
livepatch: '$MOD_CMDLINE': unpatching complete
% rmmod $MOD_CMDLINE
% echo 0 > $SYSFS_KLP_DIR/$MOD_MEMINFO/enabled
livepatch: '$MOD_MEMINFO': initializing unpatching transition
livepatch: '$MOD_MEMINFO': starting unpatching transition
livepatch: '$MOD_MEMINFO': completing unpatching transition
livepatch: '$MOD_MEMINFO': unpatching complete
% rmmod $MOD_MEMINFO"


# - load a livepatch with provides=1 that registers state ID 1
# - try to load another livepatch with provides=1 that reuses the same
#   state ID. The second one will replace the first one.
# - disable and unload the remaining livepatch

start_test "same state, same provides"

load_lp $MOD_STATE state=1 provides=1
load_lp $MOD_STATE2 state=1 provides=1

disable_lp $MOD_STATE2
unload_lp $MOD_STATE2
unload_lp $MOD_STATE

check_result "% insmod test_modules/$MOD_STATE.ko state=1 provides=1
livepatch: enabling patch '$MOD_STATE'
livepatch: '$MOD_STATE': initializing patching transition
$MOD_STATE: pre_patch_callback: vmlinux
$MOD_STATE: allocate_loglevel_state: allocating space to store console_loglevel
livepatch: '$MOD_STATE': starting patching transition
livepatch: '$MOD_STATE': completing patching transition
$MOD_STATE: post_patch_callback: vmlinux
$MOD_STATE: fix_console_loglevel: fixing console_loglevel
livepatch: '$MOD_STATE': patching complete
% insmod test_modules/$MOD_STATE2.ko state=1 provides=1
livepatch: enabling patch '$MOD_STATE2'
livepatch: '$MOD_STATE2': initializing patching transition
$MOD_STATE2: pre_patch_callback: vmlinux
$MOD_STATE2: allocate_loglevel_state: space to store console_loglevel already allocated
livepatch: '$MOD_STATE2': starting patching transition
livepatch: '$MOD_STATE2': completing patching transition
$MOD_STATE2: post_patch_callback: vmlinux
$MOD_STATE2: fix_console_loglevel: taking over the console_loglevel change
livepatch: '$MOD_STATE2': patching complete
% echo 0 > $SYSFS_KLP_DIR/$MOD_STATE2/enabled
livepatch: '$MOD_STATE2': initializing unpatching transition
$MOD_STATE2: pre_unpatch_callback: vmlinux
$MOD_STATE2: restore_console_loglevel: restoring console_loglevel
livepatch: '$MOD_STATE2': starting unpatching transition
livepatch: '$MOD_STATE2': completing unpatching transition
$MOD_STATE2: post_unpatch_callback: vmlinux
$MOD_STATE2: free_loglevel_state: freeing space for the stored console_loglevel
livepatch: '$MOD_STATE2': unpatching complete
% rmmod $MOD_STATE2
% rmmod $MOD_STATE"


# - load a livepatch with provides=1 that registers state ID 1
# - try to load another livepatch with provides=2 that reuses the same
#   state ID. The second one must be rejected because livepatches with
#   different provides ids must not share the same state id.
# - disable and unload the remaining livepatch

start_test "same state, misc provides"

load_lp $MOD_STATE state=1 provides=1
load_failing_mod $MOD_STATE2 state=1 provides=2

disable_lp $MOD_STATE
unload_lp $MOD_STATE

check_result "% insmod test_modules/$MOD_STATE.ko state=1 provides=1
livepatch: enabling patch '$MOD_STATE'
livepatch: '$MOD_STATE': initializing patching transition
$MOD_STATE: pre_patch_callback: vmlinux
$MOD_STATE: allocate_loglevel_state: allocating space to store console_loglevel
livepatch: '$MOD_STATE': starting patching transition
livepatch: '$MOD_STATE': completing patching transition
$MOD_STATE: post_patch_callback: vmlinux
$MOD_STATE: fix_console_loglevel: fixing console_loglevel
livepatch: '$MOD_STATE': patching complete
% insmod test_modules/$MOD_STATE2.ko state=1 provides=2
livepatch: Livepatch patch ($MOD_STATE2) is not compatible with the already installed livepatches.
insmod: ERROR: could not insert module test_modules/$MOD_STATE2.ko: Invalid parameters
% echo 0 > $SYSFS_KLP_DIR/$MOD_STATE/enabled
livepatch: '$MOD_STATE': initializing unpatching transition
$MOD_STATE: pre_unpatch_callback: vmlinux
$MOD_STATE: restore_console_loglevel: restoring console_loglevel
livepatch: '$MOD_STATE': starting unpatching transition
livepatch: '$MOD_STATE': completing unpatching transition
$MOD_STATE: post_unpatch_callback: vmlinux
$MOD_STATE: free_loglevel_state: freeing space for the stored console_loglevel
livepatch: '$MOD_STATE': unpatching complete
% rmmod $MOD_STATE"


# Take over system state change by a patch that obsoletes the old one.
# Although the provides IDs are different, the second patch's obsoletes
# list includes the first patch's provides ID, so it can replace the
# first patch and reuse the same state ID.

start_test "same states, replaced by obsoletes"

load_lp $MOD_STATE state=1 provides=1
load_lp $MOD_STATE2 state=1 provides=2 obsoletes=1
unload_lp $MOD_STATE
disable_lp $MOD_STATE2
unload_lp $MOD_STATE2

check_result "% insmod test_modules/$MOD_STATE.ko state=1 provides=1
livepatch: enabling patch '$MOD_STATE'
livepatch: '$MOD_STATE': initializing patching transition
$MOD_STATE: pre_patch_callback: vmlinux
$MOD_STATE: allocate_loglevel_state: allocating space to store console_loglevel
livepatch: '$MOD_STATE': starting patching transition
livepatch: '$MOD_STATE': completing patching transition
$MOD_STATE: post_patch_callback: vmlinux
$MOD_STATE: fix_console_loglevel: fixing console_loglevel
livepatch: '$MOD_STATE': patching complete
% insmod test_modules/$MOD_STATE2.ko state=1 provides=2 obsoletes=1
livepatch: enabling patch '$MOD_STATE2'
livepatch: '$MOD_STATE2': initializing patching transition
$MOD_STATE2: pre_patch_callback: vmlinux
$MOD_STATE2: allocate_loglevel_state: space to store console_loglevel already allocated
livepatch: '$MOD_STATE2': starting patching transition
livepatch: '$MOD_STATE2': completing patching transition
$MOD_STATE2: post_patch_callback: vmlinux
$MOD_STATE2: fix_console_loglevel: taking over the console_loglevel change
livepatch: '$MOD_STATE2': patching complete
% rmmod $MOD_STATE
% echo 0 > $SYSFS_KLP_DIR/$MOD_STATE2/enabled
livepatch: '$MOD_STATE2': initializing unpatching transition
$MOD_STATE2: pre_unpatch_callback: vmlinux
$MOD_STATE2: restore_console_loglevel: restoring console_loglevel
livepatch: '$MOD_STATE2': starting unpatching transition
livepatch: '$MOD_STATE2': completing unpatching transition
$MOD_STATE2: post_unpatch_callback: vmlinux
$MOD_STATE2: free_loglevel_state: freeing space for the stored console_loglevel
livepatch: '$MOD_STATE2': unpatching complete
% rmmod $MOD_STATE2"


# - load a livepatch that modifies system state (state=1) with
#   provides=1, then another livepatch with the same provides id=1 that declares
#   a different system state (state=2)
# - the second livepatch would replace the first one due to the same
#   provides id, but it does not handle the system state modified by
#   the first one, therefore it is rejected as incompatible and the
#   insmod must fail.
# - verify the first livepatch is still alive, then disable and
#   unload it.

start_test "misc states, same provides"
load_lp $MOD_STATE state=1 provides=1
load_failing_mod $MOD_STATE2 state=2 provides=1

disable_lp $MOD_STATE
unload_lp $MOD_STATE

check_result "% insmod test_modules/$MOD_STATE.ko state=1 provides=1
livepatch: enabling patch '$MOD_STATE'
livepatch: '$MOD_STATE': initializing patching transition
$MOD_STATE: pre_patch_callback: vmlinux
$MOD_STATE: allocate_loglevel_state: allocating space to store console_loglevel
livepatch: '$MOD_STATE': starting patching transition
livepatch: '$MOD_STATE': completing patching transition
$MOD_STATE: post_patch_callback: vmlinux
$MOD_STATE: fix_console_loglevel: fixing console_loglevel
livepatch: '$MOD_STATE': patching complete
% insmod test_modules/$MOD_STATE2.ko state=2 provides=1
livepatch: Livepatch patch ($MOD_STATE2) is not compatible with the already installed livepatches.
insmod: ERROR: could not insert module test_modules/$MOD_STATE2.ko: Invalid parameters
% echo 0 > $SYSFS_KLP_DIR/$MOD_STATE/enabled
livepatch: '$MOD_STATE': initializing unpatching transition
$MOD_STATE: pre_unpatch_callback: vmlinux
$MOD_STATE: restore_console_loglevel: restoring console_loglevel
livepatch: '$MOD_STATE': starting unpatching transition
livepatch: '$MOD_STATE': completing unpatching transition
$MOD_STATE: post_unpatch_callback: vmlinux
$MOD_STATE: free_loglevel_state: freeing space for the stored console_loglevel
livepatch: '$MOD_STATE': unpatching complete
% rmmod $MOD_STATE"


# - load two livepatches with different provides ids (provides=1 and
#   provides=2) that modify different system states (state=1 and
#   state=2). Neither of them replaces the other, because their
#   provides ids differ (and the obsoletes lists are empty), so they
#   can coexist.
# - verify the provides sysfs value of both livepatches
# - disable and unload both livepatches

start_test "misc states, misc provides"

load_lp $MOD_STATE state=1 provides=1
load_lp $MOD_STATE2 state=2 provides=2

check_sysfs_value "$MOD_STATE" "provides" "1"
check_sysfs_value "$MOD_STATE2" "provides" "2"

disable_lp $MOD_STATE2
unload_lp $MOD_STATE2
disable_lp $MOD_STATE
unload_lp $MOD_STATE

check_result "% insmod test_modules/$MOD_STATE.ko state=1 provides=1
livepatch: enabling patch '$MOD_STATE'
livepatch: '$MOD_STATE': initializing patching transition
$MOD_STATE: pre_patch_callback: vmlinux
$MOD_STATE: allocate_loglevel_state: allocating space to store console_loglevel
livepatch: '$MOD_STATE': starting patching transition
livepatch: '$MOD_STATE': completing patching transition
$MOD_STATE: post_patch_callback: vmlinux
$MOD_STATE: fix_console_loglevel: fixing console_loglevel
livepatch: '$MOD_STATE': patching complete
% insmod test_modules/$MOD_STATE2.ko state=2 provides=2
livepatch: enabling patch '$MOD_STATE2'
livepatch: '$MOD_STATE2': initializing patching transition
$MOD_STATE2: pre_patch_callback: vmlinux
$MOD_STATE2: allocate_loglevel_state: allocating space to store console_loglevel
livepatch: '$MOD_STATE2': starting patching transition
livepatch: '$MOD_STATE2': completing patching transition
$MOD_STATE2: post_patch_callback: vmlinux
$MOD_STATE2: fix_console_loglevel: fixing console_loglevel
livepatch: '$MOD_STATE2': patching complete
% echo 0 > $SYSFS_KLP_DIR/$MOD_STATE2/enabled
livepatch: '$MOD_STATE2': initializing unpatching transition
$MOD_STATE2: pre_unpatch_callback: vmlinux
$MOD_STATE2: restore_console_loglevel: restoring console_loglevel
livepatch: '$MOD_STATE2': starting unpatching transition
livepatch: '$MOD_STATE2': completing unpatching transition
$MOD_STATE2: post_unpatch_callback: vmlinux
$MOD_STATE2: free_loglevel_state: freeing space for the stored console_loglevel
livepatch: '$MOD_STATE2': unpatching complete
% rmmod $MOD_STATE2
% echo 0 > $SYSFS_KLP_DIR/$MOD_STATE/enabled
livepatch: '$MOD_STATE': initializing unpatching transition
$MOD_STATE: pre_unpatch_callback: vmlinux
$MOD_STATE: restore_console_loglevel: restoring console_loglevel
livepatch: '$MOD_STATE': starting unpatching transition
livepatch: '$MOD_STATE': completing unpatching transition
$MOD_STATE: post_unpatch_callback: vmlinux
$MOD_STATE: free_loglevel_state: freeing space for the stored console_loglevel
livepatch: '$MOD_STATE': unpatching complete
% rmmod $MOD_STATE"


# - load two livepatches that modify the same function
#   (meminfo_proc_show), both with provides=1. The second livepatch
#   replaces the first one because of the same provides id, even
#   though they share the patched function.
# - verify that the first livepatch is gone from sysfs (replaced)
#   and that the second one is enabled
# - unload the replacing livepatch, then the replaced one

start_test "same function, replaced by provides"

load_lp $MOD_MEMINFO provides=1

grep 'live patched' /proc/meminfo > /dev/kmsg

load_lp $MOD_MEMINFO2 provides=1

loop_until '[[ ! -e "$SYSFS_KLP_DIR/$MOD_MEMINFO" ]]' ||
	die "failed to replace $MOD_MEMINFO"

grep 'live patched' /proc/meminfo > /dev/kmsg

check_sysfs_value "$MOD_MEMINFO2" "provides" "1"

disable_lp $MOD_MEMINFO2
unload_lp $MOD_MEMINFO2

grep 'live patched' /proc/meminfo > /dev/kmsg

unload_lp $MOD_MEMINFO

check_result "% insmod test_modules/$MOD_MEMINFO.ko provides=1
livepatch: enabling patch '$MOD_MEMINFO'
livepatch: '$MOD_MEMINFO': initializing patching transition
livepatch: '$MOD_MEMINFO': starting patching transition
livepatch: '$MOD_MEMINFO': completing patching transition
livepatch: '$MOD_MEMINFO': patching complete
$MOD_MEMINFO: this has been live patched
% insmod test_modules/$MOD_MEMINFO2.ko provides=1
livepatch: enabling patch '$MOD_MEMINFO2'
livepatch: '$MOD_MEMINFO2': initializing patching transition
livepatch: '$MOD_MEMINFO2': starting patching transition
livepatch: '$MOD_MEMINFO2': completing patching transition
livepatch: '$MOD_MEMINFO2': patching complete
$MOD_MEMINFO2: this has been live patched
% echo 0 > $SYSFS_KLP_DIR/$MOD_MEMINFO2/enabled
livepatch: '$MOD_MEMINFO2': initializing unpatching transition
livepatch: '$MOD_MEMINFO2': starting unpatching transition
livepatch: '$MOD_MEMINFO2': completing unpatching transition
livepatch: '$MOD_MEMINFO2': unpatching complete
% rmmod $MOD_MEMINFO2
% rmmod $MOD_MEMINFO"


# - load a livepatch that modifies meminfo_proc_show with provides=1,
#   then try to load another livepatch that modifies the same
#   function with a different provides id (provides=2).
# - since the provides ids differ, the second livepatch would not
#   replace the first one; the same function can not be handled by
#   two different provides groups in parallel, so the load must fail.
# - unload the first livepatch

start_test "same function, can't be loaded in parallel"

load_lp $MOD_MEMINFO provides=1
load_failing_mod $MOD_MEMINFO2 provides=2

disable_lp $MOD_MEMINFO
unload_lp $MOD_MEMINFO

check_result "% insmod test_modules/$MOD_MEMINFO.ko provides=1
livepatch: enabling patch '$MOD_MEMINFO'
livepatch: '$MOD_MEMINFO': initializing patching transition
livepatch: '$MOD_MEMINFO': starting patching transition
livepatch: '$MOD_MEMINFO': completing patching transition
livepatch: '$MOD_MEMINFO': patching complete
% insmod test_modules/$MOD_MEMINFO2.ko provides=2
livepatch: Livepatch patch ($MOD_MEMINFO2) is not compatible with the already installed livepatches.
insmod: ERROR: could not insert module test_modules/$MOD_MEMINFO2.ko: Invalid parameters
% echo 0 > $SYSFS_KLP_DIR/$MOD_MEMINFO/enabled
livepatch: '$MOD_MEMINFO': initializing unpatching transition
livepatch: '$MOD_MEMINFO': starting unpatching transition
livepatch: '$MOD_MEMINFO': completing unpatching transition
livepatch: '$MOD_MEMINFO': unpatching complete
% rmmod $MOD_MEMINFO"


# - load a livepatch that modifies meminfo_proc_show with provides=1,
#   then another livepatch with provides=1 that modifies a different
#   function (cmdline_proc_show). The second one replaces the first
#   one because of the same provides id.
# - since the patched functions differ, the replacement does not need
#   to restore the old function body; the transition only switches
#   the ftrace nops, i.e. the atomic replace (nops) path.
# - after the replacement /proc/meminfo is no longer patched, while
#   /proc/cmdline is patched
# - unload the replacing livepatch, then the replaced one

start_test "different functions, atomic replace works (nops)"

load_lp $MOD_MEMINFO provides=1

grep 'live patched' /proc/meminfo > /dev/kmsg

load_lp $MOD_CMDLINE provides=1

grep 'live patched' /proc/meminfo > /dev/kmsg
grep 'live patched' /proc/cmdline > /dev/kmsg

disable_lp $MOD_CMDLINE
unload_lp $MOD_CMDLINE
unload_lp $MOD_MEMINFO

check_result "% insmod test_modules/$MOD_MEMINFO.ko provides=1
livepatch: enabling patch '$MOD_MEMINFO'
livepatch: '$MOD_MEMINFO': initializing patching transition
livepatch: '$MOD_MEMINFO': starting patching transition
livepatch: '$MOD_MEMINFO': completing patching transition
livepatch: '$MOD_MEMINFO': patching complete
$MOD_MEMINFO: this has been live patched
% insmod test_modules/$MOD_CMDLINE.ko provides=1
livepatch: enabling patch '$MOD_CMDLINE'
livepatch: '$MOD_CMDLINE': initializing patching transition
livepatch: '$MOD_CMDLINE': starting patching transition
livepatch: '$MOD_CMDLINE': completing patching transition
livepatch: '$MOD_CMDLINE': patching complete
$MOD_CMDLINE: this has been live patched
% echo 0 > $SYSFS_KLP_DIR/$MOD_CMDLINE/enabled
livepatch: '$MOD_CMDLINE': initializing unpatching transition
livepatch: '$MOD_CMDLINE': starting unpatching transition
livepatch: '$MOD_CMDLINE': completing unpatching transition
livepatch: '$MOD_CMDLINE': unpatching complete
% rmmod $MOD_CMDLINE
% rmmod $MOD_MEMINFO"


# - load two livepatches with different provides ids (1 and 2) that
#   modify different functions (meminfo_proc_show and
#   cmdline_proc_show). Neither of them replaces the other, so both
#   livepatches must coexist.
# - verify that both /proc/meminfo and /proc/cmdline are patched
# - disable and unload both livepatches

start_test "different functions, install in parallel"

load_lp $MOD_MEMINFO provides=1

grep 'live patched' /proc/meminfo > /dev/kmsg

load_lp $MOD_CMDLINE provides=2

grep 'live patched' /proc/meminfo > /dev/kmsg
grep 'live patched' /proc/cmdline > /dev/kmsg

disable_lp $MOD_MEMINFO
unload_lp $MOD_MEMINFO
disable_lp $MOD_CMDLINE
unload_lp $MOD_CMDLINE

check_result "% insmod test_modules/$MOD_MEMINFO.ko provides=1
livepatch: enabling patch '$MOD_MEMINFO'
livepatch: '$MOD_MEMINFO': initializing patching transition
livepatch: '$MOD_MEMINFO': starting patching transition
livepatch: '$MOD_MEMINFO': completing patching transition
livepatch: '$MOD_MEMINFO': patching complete
$MOD_MEMINFO: this has been live patched
% insmod test_modules/$MOD_CMDLINE.ko provides=2
livepatch: enabling patch '$MOD_CMDLINE'
livepatch: '$MOD_CMDLINE': initializing patching transition
livepatch: '$MOD_CMDLINE': starting patching transition
livepatch: '$MOD_CMDLINE': completing patching transition
livepatch: '$MOD_CMDLINE': patching complete
$MOD_MEMINFO: this has been live patched
$MOD_CMDLINE: this has been live patched
% echo 0 > $SYSFS_KLP_DIR/$MOD_MEMINFO/enabled
livepatch: '$MOD_MEMINFO': initializing unpatching transition
livepatch: '$MOD_MEMINFO': starting unpatching transition
livepatch: '$MOD_MEMINFO': completing unpatching transition
livepatch: '$MOD_MEMINFO': unpatching complete
% rmmod $MOD_MEMINFO
% echo 0 > $SYSFS_KLP_DIR/$MOD_CMDLINE/enabled
livepatch: '$MOD_CMDLINE': initializing unpatching transition
livepatch: '$MOD_CMDLINE': starting unpatching transition
livepatch: '$MOD_CMDLINE': completing unpatching transition
livepatch: '$MOD_CMDLINE': unpatching complete
% rmmod $MOD_CMDLINE"

exit 0
