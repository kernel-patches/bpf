// SPDX-License-Identifier: GPL-2.0
/*
 * A module for the functions of bpf_testmod_retval.c and
 * bpf_testmod_retval_strong.c, see prog_tests/fmodret_retval.c. They are not
 * in bpf_testmod: pahole drops the per-CPU variables of a module which GNU ld
 * links from several objects.
 */
#include <linux/module.h>

MODULE_AUTHOR("Anton Protopopov");
MODULE_DESCRIPTION("BPF selftest module for fmod_ret targets found by bpf_scan_ir");
MODULE_LICENSE("GPL");
