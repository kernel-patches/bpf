/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2022 Google LLC.
 */

#ifndef _BPF_FUSE_H
#define _BPF_FUSE_H

#include <linux/types.h>
#include <linux/fuse.h>

struct fuse_buffer {
	void *data;
	unsigned size;
	unsigned alloc_size;
	unsigned max_size;
	int flags;
};

/* These flags are used internally to track information about the fuse buffers.
 * Fuse sets some of the flags in init. The helper functions sets others, depending on what
 * was requested by the bpf program.
 */
// Flags set by FUSE
#define BPF_FUSE_IMMUTABLE	(1 << 0) // Buffer may not be written to
#define BPF_FUSE_VARIABLE_SIZE	(1 << 1) // Buffer length may be changed (growth requires alloc)
#define BPF_FUSE_MUST_ALLOCATE	(1 << 2) // Buffer must be re allocated before allowing writes

// Flags set by helper function
#define BPF_FUSE_MODIFIED	(1 << 3) // The helper function allowed writes to the buffer
#define BPF_FUSE_ALLOCATED	(1 << 4) // The helper function allocated the buffer

/*
 * BPF Fuse Args
 *
 * Used to translate between bpf program parameters and their userspace equivalent calls.
 * Variable sized arguments are held in fuse_buffers. To access these, bpf programs must
 * use kfuncs to access them as dynptrs.
 *
 */

#define FUSE_MAX_ARGS_IN 3
#define FUSE_MAX_ARGS_OUT 2

struct bpf_fuse_arg {
	union {
		void *value;
		struct fuse_buffer *buffer;
	};
	unsigned size;
	bool is_buffer;
};

struct bpf_fuse_meta_info {
	uint64_t nodeid;
	uint32_t opcode;
	uint32_t error_in;
};

struct bpf_fuse_args {
	struct bpf_fuse_meta_info info;
	uint32_t in_numargs;
	uint32_t out_numargs;
	uint32_t flags;
	struct bpf_fuse_arg in_args[FUSE_MAX_ARGS_IN];
	struct bpf_fuse_arg out_args[FUSE_MAX_ARGS_OUT];
};

// Mirrors for struct fuse_args flags
#define FUSE_BPF_FORCE (1 << 0)
#define FUSE_BPF_OUT_ARGVAR (1 << 6)
#define FUSE_BPF_IS_LOOKUP (1 << 11)

static inline void *bpf_fuse_arg_value(const struct bpf_fuse_arg *arg)
{
	return arg->is_buffer ? arg->buffer : arg->value;
}

static inline unsigned bpf_fuse_arg_size(const struct bpf_fuse_arg *arg)
{
	return arg->is_buffer ? arg->buffer->size : arg->size;
}

#endif /* _BPF_FUSE_H */
