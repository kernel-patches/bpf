// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google LLC. */

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define OUT_LEN 64

/* Integer types */
static const char num_fmt[] = "%d %u %x %li %llu %lX";
#define NUMBERS -8, 9, 150, -424242, 1337, 0xDABBAD00

char num_out[OUT_LEN] = {};
long num_ret = 0;

/* IP addresses */
static const char ip_fmt[] = "%pi4 %pI6";
static const __u8 dummy_ipv4[] = {127, 0, 0, 1}; /* 127.0.0.1 */
static const __u32 dummy_ipv6[] = {0, 0, 0, bpf_htonl(1)}; /* ::1/128 */
#define IPS &dummy_ipv4, &dummy_ipv6

char ip_out[OUT_LEN] = {};
long ip_ret = 0;

/* Symbol lookup formatting */
static const char sym_fmt[] = "%ps %pS %pB";
extern const void schedule __ksym;
#define SYMBOLS &schedule, &schedule, &schedule

char sym_out[OUT_LEN] = {};
long sym_ret = 0;

/* Kernel pointers */
static const char addr_fmt[] = "%pK %px %p";
#define ADDRESSES 0, 0xFFFF00000ADD4E55, 0xFFFF00000ADD4E55

char addr_out[OUT_LEN] = {};
long addr_ret = 0;

/* Strings embedding */
static const char str_fmt[] = "%s %+05s";
static const char str1[] = "str1";
static const char longstr[] = "longstr";
#define STRINGS str1, longstr

char str_out[OUT_LEN] = {};
long str_ret = 0;

/* Overflow */
static const char over_fmt[] = "%%overflow";

#define OVER_OUT_LEN 6
char over_out[OVER_OUT_LEN] = {};
long over_ret = 0;

SEC("raw_tp/sys_enter")
int handler(const void *ctx)
{
	num_ret  = BPF_SNPRINTF(num_out,  OUT_LEN, num_fmt,  NUMBERS);
	ip_ret   = BPF_SNPRINTF(ip_out,   OUT_LEN, ip_fmt,   IPS);
	sym_ret  = BPF_SNPRINTF(sym_out,  OUT_LEN, sym_fmt,  SYMBOLS);
	addr_ret = BPF_SNPRINTF(addr_out, OUT_LEN, addr_fmt, ADDRESSES);
	str_ret  = BPF_SNPRINTF(str_out,  OUT_LEN, str_fmt,  STRINGS);
	over_ret = BPF_SNPRINTF(over_out, OVER_OUT_LEN, over_fmt);

	return 0;
}

char _license[] SEC("license") = "GPL";
