/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */

#ifndef __HID_BPF_H
#define __HID_BPF_H

#include <linux/spinlock.h>
#include <uapi/linux/hid.h>
#include <uapi/linux/hid_bpf.h>

struct hid_device;

/*
 * The following is the HID BPF API.
 *
 * It should be treated as UAPI, so extra care is required
 * when making change to this file.
 */

/**
 * struct hid_bpf_ctx - User accessible data for all HID programs
 *
 * ``data`` is not directly accessible from the context. We need to issue
 * a call to ``hid_bpf_get_data()`` in order to get a pointer to that field.
 *
 * All of these fields are currently read-only.
 *
 * @index: program index in the jump table. No special meaning (a smaller index
 *         doesn't mean the program will be executed before another program with
 *         a bigger index).
 * @hid: the ``struct hid_device`` representing the device itself
 * @report_type: used for ``hid_bpf_device_event()``
 * @allocated_size: Allocated size of data.
 *
 *                  This is how much memory is available and can be requested
 *                  by the HID program.
 *                  Note that for ``HID_BPF_RDESC_FIXUP``, that memory is set to
 *                  ``4096`` (4 KB)
 * @size: Valid data in the data field.
 *
 *        Programs can get the available valid size in data by fetching this field.
 *        Programs can also change this value by returning a positive number in the
 *        program.
 *        To discard the event, return a negative error code.
 *
 *        ``size`` must always be less or equal than ``allocated_size`` (it is enforced
 *        once all BPF programs have been run).
 * @retval: Return value of the previous program.
 */
struct hid_bpf_ctx {
	__u32 index;
	const struct hid_device *hid;
	__u32 allocated_size;
	enum hid_report_type report_type;
	union {
		__s32 retval;
		__s32 size;
	};
};

/* Following functions are tracepoints that BPF programs can attach to */
int hid_bpf_device_event(struct hid_bpf_ctx *ctx);

/* Following functions are kfunc that we export to BPF programs */
/* available everywhere in HID-BPF */
__u8 *hid_bpf_get_data(struct hid_bpf_ctx *ctx, unsigned int offset, const size_t __sz);

/* only available in syscall */
int hid_bpf_attach_prog(unsigned int hid_id, int prog_fd, __u32 flags);
int hid_bpf_hw_request(struct hid_bpf_ctx *ctx, __u8 *buf, size_t buf__sz,
		       enum hid_report_type rtype, enum hid_class_request reqtype);
struct hid_bpf_ctx *hid_bpf_allocate_context(unsigned int hid_id);
void hid_bpf_release_context(struct hid_bpf_ctx *ctx);

/*
 * Below is HID internal
 */

#define HID_BPF_MAX_PROGS_PER_DEV 64
#define HID_BPF_FLAG_MASK (((HID_BPF_FLAG_MAX - 1) << 1) - 1)

/* types of HID programs to attach to */
enum hid_bpf_prog_type {
	HID_BPF_PROG_TYPE_UNDEF = -1,
	HID_BPF_PROG_TYPE_DEVICE_EVENT,			/* an event is emitted from the device */
	HID_BPF_PROG_TYPE_MAX,
};

struct hid_report_enum;

struct hid_bpf_ops {
	struct hid_report *(*hid_get_report)(struct hid_report_enum *report_enum, const u8 *data);
	int (*hid_hw_raw_request)(struct hid_device *hdev,
				  unsigned char reportnum, __u8 *buf,
				  size_t len, enum hid_report_type rtype,
				  enum hid_class_request reqtype);
	struct module *owner;
	struct bus_type *bus_type;
};

extern struct hid_bpf_ops *hid_bpf_ops;

struct hid_bpf_prog_list {
	u16 prog_idx[HID_BPF_MAX_PROGS_PER_DEV];
	u8 prog_cnt;
};

/* stored in each device */
struct hid_bpf {
	u8 *device_data;		/* allocated when a bpf program of type
					 * SEC(f.../hid_bpf_device_event) has been attached
					 * to this HID device
					 */
	u32 allocated_data;

	struct hid_bpf_prog_list __rcu *progs[HID_BPF_PROG_TYPE_MAX];	/* attached BPF progs */
	bool destroyed;			/* prevents the assignment of any progs */

	spinlock_t progs_lock;		/* protects RCU update of progs */
};

#ifdef CONFIG_BPF
u8 *dispatch_hid_bpf_device_event(struct hid_device *hid, enum hid_report_type type, u8 *data,
				  u32 *size, int interrupt);
int hid_bpf_connect_device(struct hid_device *hdev);
void hid_bpf_disconnect_device(struct hid_device *hdev);
void hid_bpf_destroy_device(struct hid_device *hid);
void hid_bpf_device_init(struct hid_device *hid);
#else /* CONFIG_BPF */
static inline u8 *dispatch_hid_bpf_device_event(struct hid_device *hid, int type, u8 *data,
						u32 *size, int interrupt) { return 0; }
static inline int hid_bpf_connect_device(struct hid_device *hdev) { return 0; }
static inline void hid_bpf_disconnect_device(struct hid_device *hdev) {}
static inline void hid_bpf_destroy_device(struct hid_device *hid) {}
static inline void hid_bpf_device_init(struct hid_device *hid) {}
#endif /* CONFIG_BPF */

#endif /* __HID_BPF_H */
