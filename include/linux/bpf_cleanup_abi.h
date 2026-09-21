/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#ifndef _LINUX_BPF_CLEANUP_ABI_H
#define _LINUX_BPF_CLEANUP_ABI_H

/*
 * Value arch_bpf_run_cleanup_pad() leaves in r0 on the way into a landing pad.
 * It has to be a constant the verifier knows: LLVM names r0 as both the
 * exception pointer and the exception selector register, so every pad reads it
 * before anything else and is free to store what it read. It gets a header of
 * its own because the two sides that have to agree on it are the verifier and
 * the arch dispatchers, which are assembly.
 */
#define BPF_PAD_ENTRY_R0	1

#endif /* _LINUX_BPF_CLEANUP_ABI_H */
