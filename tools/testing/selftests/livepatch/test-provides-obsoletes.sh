#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2026 Yafang Shao <laoar.shao@gmail.com>

. $(dirname $0)/functions.sh

MOD_MEMINFO=test_klp_meminfo_lp
MOD_CMDLINE=test_klp_cmdline_lp

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

exit 0
