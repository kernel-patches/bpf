// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Ibrahim Zein <zeroxjacks@gmail.com> */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * Test that bpf_snprintf() with %pI4/%pI6 does not overflow the
 * internal bin_args buffer when the buffer is nearly full.
 *
 * The bug: sizeof_cur_ip (4 for IPv4) was used for the bounds check,
 * but snprintf() returns the full formatted string length (up to 15
 * for "255.255.255.255"), pushing tmp_buf past tmp_buf_end.
 */

/* Output buffers */
char ip4_out[64] = {};
long ip4_ret = 0;

char ip6_out[128] = {};
long ip6_ret = 0;

/* Test %pI4 with worst-case IP (255.255.255.255) */
char worst_ip4_out[64] = {};
long worst_ip4_ret = 0;

/* Return value for the near-overflow test */
long near_overflow_ret = 0;

__u32 pid = 0;

SEC("raw_tp/sys_enter")
int handler(const void *ctx)
{
	/* Worst-case IPv4: "255.255.255.255" = 15 chars */
	const __u8 ip4_worst[] = {255, 255, 255, 255};
	/* Normal IPv4 */
	const __u8 ip4_normal[] = {192, 168, 1, 1};
	/* IPv6 worst-case */
	const __u8 ip6_worst[] = {0xff, 0xff, 0xff, 0xff,
				   0xff, 0xff, 0xff, 0xff,
				   0xff, 0xff, 0xff, 0xff,
				   0xff, 0xff, 0xff, 0xff};

	if ((int)bpf_get_current_pid_tgid() != pid)
		return 0;

	/* Test 1: normal %pI4 usage */
	ip4_ret = BPF_SNPRINTF(ip4_out, sizeof(ip4_out),
			       "%pI4", &ip4_normal);

	/* Test 2: normal %pI6 usage */
	ip6_ret = BPF_SNPRINTF(ip6_out, sizeof(ip6_out),
			       "%pI6", &ip6_worst);

	/* Test 3: worst-case %pI4 "255.255.255.255" */
	worst_ip4_ret = BPF_SNPRINTF(worst_ip4_out, sizeof(worst_ip4_out),
				     "%pI4", &ip4_worst);

	/*
	 * Test 4: near-overflow scenario.
	 * Fill bin_args with scalar args (%d), then use %pI4.
	 * Before the fix: tmp_buf overflows by 8 bytes.
	 * After the fix: correctly returns -ENOSPC or fits exactly.
	 *
	 * We use fewer args here since BPF_SNPRINTF macro has a limit,
	 * but this validates the format string parsing path.
	 */
	near_overflow_ret = BPF_SNPRINTF(NULL, 0,
		"%d %d %d %d %d %d %d %d "
		"%d %d %d %d %d %d %d %d "
		"%d %d %d %d %d %d %d %d "
		"%pI4",
		1, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24,
		&ip4_worst);

	return 0;
}

char _license[] SEC("license") = "GPL";
