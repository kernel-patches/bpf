// SPDX-License-Identifier: GPL-2.0
/* Copyright Leon Hwang */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct xdp_errmsg {
	char msg[64];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} xdp_errmsg_pb SEC(".maps");

struct xdp_attach_error_ctx {
	unsigned long unused;

	/*
	 * bpf does not support tracepoint __data_loc directly.
	 *
	 * Actually, this field is a 32 bit integer whose value encodes
	 * information on where to find the actual data. The first 2 bytes is
	 * the size of the data. The last 2 bytes is the offset from the start
	 * of the tracepoint struct where the data begins.
	 * -- https://github.com/iovisor/bpftrace/pull/1542
	 */
	__u32 msg; // __data_loc char[] msg;
};

/*
 * Catch up the error message at the tracepoint.
 */

SEC("tp/xdp/bpf_xdp_link_attach_failed")
int tp__xdp__bpf_xdp_link_attach_failed(struct xdp_attach_error_ctx *ctx)
{
	struct xdp_errmsg errmsg;
	char *msg = (void *)(__u64) ((void *) ctx + (__u16) ctx->msg);

	bpf_probe_read_kernel_str(&errmsg.msg, sizeof(errmsg.msg), msg);
	bpf_perf_event_output(ctx, &xdp_errmsg_pb, BPF_F_CURRENT_CPU, &errmsg,
			      sizeof(errmsg));
	return 0;
}

/*
 * Reuse the XDP program in xdp_dummy.c.
 */

char LICENSE[] SEC("license") = "GPL";
