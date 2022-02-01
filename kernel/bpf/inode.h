/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2022 Google
 */
#ifndef __BPF_INODE_H_
#define __BPF_INODE_H_

enum tag_type {
	/* The directory is a replicate of a kernfs directory hierarchy. */
	BPF_DIR_KERNFS_REP = 0,
};

/* A tag for bpffs directories. It carries special information about a
 * directory. For example, BPF_DIR_KERNFS_REP denotes that the directory is
 * a replicate of a kernfs hierarchy. Pinning a certain type of objects tags
 * a directory and the tag will be removed at rmdir.
 */
struct bpf_dir_tag {
	enum tag_type type;
	void *private;  /* tag private data */
};

#endif
