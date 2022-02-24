/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _BPF_HID_H
#define _BPF_HID_H

#include <linux/mutex.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/bpf_hid.h>
#include <linux/list.h>

struct bpf_prog;
struct bpf_prog_array;
struct hid_device;

enum bpf_hid_attach_type {
	BPF_HID_ATTACH_INVALID = -1,
	BPF_HID_ATTACH_DEVICE_EVENT = 0,
	MAX_BPF_HID_ATTACH_TYPE
};

struct bpf_hid {
	struct hid_bpf_ctx *ctx;

	/* Array of programs to run compiled from links */
	struct bpf_prog_array __rcu *run_array[MAX_BPF_HID_ATTACH_TYPE];
	struct list_head links[MAX_BPF_HID_ATTACH_TYPE];
};

static inline enum bpf_hid_attach_type
to_bpf_hid_attach_type(enum bpf_attach_type attach_type)
{
	switch (attach_type) {
	case BPF_HID_DEVICE_EVENT:
		return BPF_HID_ATTACH_DEVICE_EVENT;
	default:
		return BPF_HID_ATTACH_INVALID;
	}
}

union bpf_attr;
struct bpf_prog;

#if IS_ENABLED(CONFIG_HID)
int bpf_hid_prog_query(const union bpf_attr *attr,
		       union bpf_attr __user *uattr);
int bpf_hid_link_create(const union bpf_attr *attr,
			struct bpf_prog *prog);
#else
static inline int bpf_hid_prog_query(const union bpf_attr *attr,
				     union bpf_attr __user *uattr)
{
	return -EOPNOTSUPP;
}

static inline int bpf_hid_link_create(const union bpf_attr *attr,
				      struct bpf_prog *prog)
{
	return -EOPNOTSUPP;
}
#endif

static inline bool bpf_hid_link_empty(struct bpf_hid *bpf,
				      enum bpf_hid_attach_type type)
{
	return list_empty(&bpf->links[type]);
}

struct bpf_hid_hooks {
	struct hid_device *(*hdev_from_fd)(int fd);
	int (*link_attach)(struct hid_device *hdev, enum bpf_hid_attach_type type);
	void (*array_detached)(struct hid_device *hdev, enum bpf_hid_attach_type type);
};

#ifdef CONFIG_BPF
int bpf_hid_init(struct hid_device *hdev);
void bpf_hid_exit(struct hid_device *hdev);
void bpf_hid_set_hooks(struct bpf_hid_hooks *hooks);
#else
static inline int bpf_hid_init(struct hid_device *hdev)
{
	return 0;
}

static inline void bpf_hid_exit(struct hid_device *hdev) {}
static inline void bpf_hid_set_hooks(struct bpf_hid_hooks *hooks) {}
#endif

#endif /* _BPF_HID_H */
