/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2022 Google
 */
#ifndef __BPF_INODE_H_
#define __BPF_INODE_H_

#include <linux/bpf.h>
#include <linux/fs.h>

enum bpf_type {
	BPF_TYPE_UNSPEC	= 0,
	BPF_TYPE_PROG,
	BPF_TYPE_MAP,
	BPF_TYPE_LINK,
};

enum tag_type {
	/* The directory is a replicate of a kernfs directory hierarchy. */
	BPF_DIR_KERNFS_REP = 0,
};

/* Entry for bpf_dir_tag->inherit_objects.
 *
 * When a new directory is created from a tagged directory, the new directory
 * will be populated with bpf objects in the tag's inherit_objects list. Each
 * entry holds a reference of a bpf object and the information needed to
 * recreate the object's entry in the new directory.
 */
struct bpf_inherit_entry {
	struct list_head list;
	void *obj; /* bpf object to inherit. */
	enum bpf_type type; /* type of the object (prog, map or link). */
	struct qstr name;  /* name of the entry. */
	umode_t mode;  /* access mode of the entry. */
};

struct obj_list {
	struct list_head list;
	struct kref refcnt;
	struct inode *root;
};

/* A tag for bpffs directories. It carries special information about a
 * directory. For example, BPF_DIR_KERNFS_REP denotes that the directory is
 * a replicate of a kernfs hierarchy. Pinning a certain type of objects tags
 * a directory and the tag will be removed at rmdir.
 */
struct bpf_dir_tag {
	enum tag_type type;
	/* list of bpf objects that a directory inherits from its parent. */
	struct obj_list *inherit_objects;
	void *private;  /* tag private data */
};

#endif
