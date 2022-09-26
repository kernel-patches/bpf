/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2022 Google LLC.
 */

#ifndef _BPF_FUSE_H
#define _BPF_FUSE_H

/*
 * Fuse BPF Args
 *
 * Used to communicate with bpf programs to allow checking or altering certain values.
 * The end_offset allows the bpf verifier to check boundaries statically. This reflects
 * the ends of the buffer. size shows the length that was actually used.
 *
 * In order to write to the output args, you must use the pointer returned by
 * bpf_fuse_get_writeable.
 *
 */

#define FUSE_MAX_ARGS_IN 3
#define FUSE_MAX_ARGS_OUT 2

struct bpf_fuse_arg {
	void *value;		// Start of the buffer
	void *end_offset;	// End of the buffer
	uint32_t size;		// Used size of the buffer
	uint32_t max_size;	// Max permitted size, if buffer is resizable. Otherwise 0
	uint32_t flags;		// Flags indicating buffer status
};

#define FUSE_BPF_FORCE (1 << 0)
#define FUSE_BPF_OUT_ARGVAR (1 << 6)
#define FUSE_BPF_IS_LOOKUP (1 << 11)

struct bpf_fuse_args {
	uint64_t nodeid;
	uint32_t opcode;
	uint32_t error_in;
	uint32_t in_numargs;
	uint32_t out_numargs;
	uint32_t flags;
	uint32_t ret;
	struct bpf_fuse_arg in_args[FUSE_MAX_ARGS_IN];
	struct bpf_fuse_arg out_args[FUSE_MAX_ARGS_OUT];
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

extern void *bpf_fuse_get_writeable(struct bpf_fuse_arg *arg, u64 size, bool copy);
bool bpf_helper_changes_one_pkt_data(void *func);

#endif /* _BPF_FUSE_H */
