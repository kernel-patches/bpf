/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2016 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _UAPI__LINUX_BPF_PERF_EVENT_H__
#define _UAPI__LINUX_BPF_PERF_EVENT_H__

#include <asm/bpf_perf_event.h>

#if __has_attribute(preserve_static_offset) && defined(__bpf__)
#define __bpf_ctx __attribute__((preserve_static_offset))
#elif __has_attribute(btf_decl_tag) && !defined(__cplusplus)
#define __bpf_ctx __attribute__((btf_decl_tag(("preserve_static_offset"))))
#else
#define __bpf_ctx
#endif

struct bpf_perf_event_data {
	bpf_user_pt_regs_t regs;
	__u64 sample_period;
	__u64 addr;
} __bpf_ctx;

#undef __bpf_ctx

#endif /* _UAPI__LINUX_BPF_PERF_EVENT_H__ */
