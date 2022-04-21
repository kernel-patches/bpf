// SPDX-License-Identifier: GPL-2.0

/*
 * Note: for the following code to compile, we need HID to be included
 * in vmlinuz (CONFIG_HID=y).
 * If HID is compiled as a separate module, we need to use the vmlinux.h
 * which contains the various hid symbols, it can be generated through:
 *
 * $> ./tools/bpf/bpftool/bpftool btf dump \
 *        file /sys/kernel/btf/hid format c > samples/bpf/vmlinux.h
 *
 * Once the code is compiled, the fact that HID is a separate module
 * or not is not an issue, the same binary will run similarily.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

extern __u8 *hid_bpf_kfunc_get_data(struct hid_bpf_ctx *ctx,
				    unsigned int offset,
				    const size_t __sz) __ksym;
extern void hid_bpf_kfunc_data_release(__u8 *data) __ksym;
extern int hid_bpf_kfunc_hw_request(struct hid_bpf_ctx *ctx) __ksym;

#define BUS_USB 3

SEC("fentry/hid_bpf_device_event")
int BPF_KPROBE(hid_event, struct hid_bpf_ctx *hctx, __s64 type)
{
	__u8 *rw_data = hid_bpf_kfunc_get_data(hctx, 0, 5);

	if (!rw_data)
		return 0;

	if (hctx->bus == BUS_USB) {
		/* note: the following call prevents the program to be loaded:
		 * hid_bpf_device_event() is not sleepable when this function is.
		 */
		hid_bpf_kfunc_hw_request(hctx);

		bpf_printk("data: %02x %02x %02x", rw_data[0], rw_data[1], rw_data[4]);
	}

	hid_bpf_kfunc_data_release(rw_data);

	return 0;
}

SEC("fmod_ret/hid_bpf_device_event")
int BPF_PROG(hid_mod_event, struct hid_bpf_ctx *hctx, __s64 type)
{
	/* prevent any USB event to go through the HID stack */
	if (hctx->bus == BUS_USB)
		return -1;

	return 0;
}

char _license[] SEC("license") = "GPL";
