// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Abhishek Khade */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "errno.h"

char _license[] SEC("license") = "GPL";

/* kfunc prototypes */
long bpf_memmem(const void *haystack, u32 haystack__sz,
		const void *needle, u32 needle__sz,
		u64 flags) __ksym;

long bpf_dynptr_memmem(const struct bpf_dynptr *haystack,
		       const void *needle, u32 needle__sz,
		       u64 flags) __ksym;

static char bin_data[] = {
	0x16, 0x03, 0x01, 0x00, 0x02, 0xaa, 0xbb, 0x00, 0xff, 0x00, 0x55
};

static char needle_null[] = { 0x00, 0xff, 0x00 };
static char needle_start[] = { 0x16, 0x03, 0x01 };
static char needle_end[] = { 0x00, 0x55 };
static char needle_single[] = { 0xaa };
static char needle_notfound[] = { 0xde, 0xad };
static char needle_repeat[] = { 0xaa, 0xbb, 0x00, 0xaa, 0xbb };
static char needle_sub_repeat[] = { 0xaa, 0xbb };
static char overlap_haystack[] = { 0xaa, 0xaa, 0xaa, 0xbb };
static char overlap_needle[] = { 0xaa, 0xaa, 0xbb };
static char periodic_buf[] = "abababac";
static char periodic_needle[] = "ababac";
static char rep_buf[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaab";
static char rep_needle[] = "aaaaaab";
static char oversized_buf[2 * 1024 * 1024 + 1];

/* 1. Flat memory buffer tests */

SEC("syscall")
__success __retval(7)
int test_memmem_embedded_null(void *ctx)
{
	return bpf_memmem(bin_data, sizeof(bin_data),
			  needle_null, sizeof(needle_null), 0);
}

SEC("syscall")
__success __retval(0)
int test_memmem_start(void *ctx)
{
	return bpf_memmem(bin_data, sizeof(bin_data),
			  needle_start, sizeof(needle_start), 0);
}

SEC("syscall")
__success __retval(9)
int test_memmem_end(void *ctx)
{
	return bpf_memmem(bin_data, sizeof(bin_data),
			  needle_end, sizeof(needle_end), 0);
}

SEC("syscall")
__success __retval(5)
int test_memmem_single_byte(void *ctx)
{
	return bpf_memmem(bin_data, sizeof(bin_data),
			  needle_single, sizeof(needle_single), 0);
}

SEC("syscall")
__success __retval(-ENOENT)
int test_memmem_not_found(void *ctx)
{
	return bpf_memmem(bin_data, sizeof(bin_data),
			  needle_notfound, sizeof(needle_notfound), 0);
}

SEC("syscall")
__success __retval(0)
int test_memmem_first_occurrence(void *ctx)
{
	return bpf_memmem(needle_repeat, sizeof(needle_repeat),
			  needle_sub_repeat, sizeof(needle_sub_repeat), 0);
}

SEC("syscall")
__success __retval(1)
int test_memmem_overlapping_prefix(void *ctx)
{
	return bpf_memmem(overlap_haystack, sizeof(overlap_haystack),
			  overlap_needle, sizeof(overlap_needle), 0);
}

SEC("syscall")
__success __retval(0)
int test_memmem_exact_match(void *ctx)
{
	return bpf_memmem(needle_start, sizeof(needle_start),
			  needle_start, sizeof(needle_start), 0);
}

SEC("syscall")
__success __retval(-EINVAL)
int test_memmem_needle_too_large(void *ctx)
{
	return bpf_memmem(needle_start, sizeof(needle_start),
			  bin_data, sizeof(bin_data), 0);
}

SEC("syscall")
__success __retval(-EINVAL)
int test_memmem_empty_needle(void *ctx)
{
	return bpf_memmem(bin_data, sizeof(bin_data),
			  needle_start, 0, 0);
}

SEC("syscall")
__success __retval(-EINVAL)
int test_memmem_invalid_flags(void *ctx)
{
	return bpf_memmem(bin_data, sizeof(bin_data),
			  needle_start, sizeof(needle_start), 1);
}

SEC("syscall")
__success __retval(-E2BIG)
int test_memmem_oversized_haystack(void *ctx)
{
	return bpf_memmem(oversized_buf, sizeof(oversized_buf),
			  needle_single, sizeof(needle_single), 0);
}

SEC("syscall")
__success __retval(-ENOENT)
int test_memmem_exact_2mb(void *ctx)
{
	return bpf_memmem(oversized_buf, 2 * 1024 * 1024,
			  needle_single, sizeof(needle_single), 0);
}

SEC("syscall")
__success __retval(-EINVAL)
int test_memmem_zero_len_haystack(void *ctx)
{
	return bpf_memmem(bin_data, 0,
			  needle_single, sizeof(needle_single), 0);
}

SEC("syscall")
__success __retval(2)
int test_memmem_periodic_pattern(void *ctx)
{
	return bpf_memmem(periodic_buf, sizeof(periodic_buf) - 1,
			  periodic_needle, sizeof(periodic_needle) - 1, 0);
}

SEC("syscall")
__success __retval(24)
int test_memmem_repetitive_prefix(void *ctx)
{
	return bpf_memmem(rep_buf, sizeof(rep_buf) - 1,
			  rep_needle, sizeof(rep_needle) - 1, 0);
}

/* 2. Dynamic pointer (bpf_dynptr) tests */

SEC("syscall")
__success __retval(7)
int test_dynptr_memmem_embedded_null(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_from_mem((void *)bin_data, sizeof(bin_data), 0, &ptr);
	return bpf_dynptr_memmem(&ptr, needle_null, sizeof(needle_null), 0);
}

SEC("syscall")
__success __retval(0)
int test_dynptr_memmem_start(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_from_mem((void *)bin_data, sizeof(bin_data), 0, &ptr);
	return bpf_dynptr_memmem(&ptr, needle_start, sizeof(needle_start), 0);
}

SEC("syscall")
__success __retval(9)
int test_dynptr_memmem_end(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_from_mem((void *)bin_data, sizeof(bin_data), 0, &ptr);
	return bpf_dynptr_memmem(&ptr, needle_end, sizeof(needle_end), 0);
}

SEC("syscall")
__success __retval(0)
int test_dynptr_memmem_exact_match(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_from_mem((void *)needle_start, sizeof(needle_start), 0, &ptr);
	return bpf_dynptr_memmem(&ptr, needle_start, sizeof(needle_start), 0);
}

SEC("syscall")
__success __retval(-EINVAL)
int test_dynptr_memmem_needle_too_large(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_from_mem((void *)needle_start, sizeof(needle_start), 0, &ptr);
	return bpf_dynptr_memmem(&ptr, bin_data, sizeof(bin_data), 0);
}

SEC("syscall")
__success __retval(-ENOENT)
int test_dynptr_memmem_not_found(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_from_mem((void *)bin_data, sizeof(bin_data), 0, &ptr);
	return bpf_dynptr_memmem(&ptr, needle_notfound, sizeof(needle_notfound), 0);
}

SEC("syscall")
__success __retval(-EINVAL)
int test_dynptr_memmem_empty_needle(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_from_mem((void *)bin_data, sizeof(bin_data), 0, &ptr);
	return bpf_dynptr_memmem(&ptr, needle_start, 0, 0);
}

SEC("syscall")
__success __retval(-EINVAL)
int test_dynptr_memmem_invalid_flags(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_from_mem((void *)bin_data, sizeof(bin_data), 0, &ptr);
	return bpf_dynptr_memmem(&ptr, needle_start, sizeof(needle_start), 1);
}

SEC("syscall")
__success __retval(-E2BIG)
int test_dynptr_memmem_oversized_haystack(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_from_mem((void *)oversized_buf, sizeof(oversized_buf), 0, &ptr);
	return bpf_dynptr_memmem(&ptr, needle_single, sizeof(needle_single), 0);
}

SEC("syscall")
__success __retval(-ENOENT)
int test_dynptr_memmem_exact_2mb(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_from_mem((void *)oversized_buf, 2 * 1024 * 1024, 0, &ptr);
	return bpf_dynptr_memmem(&ptr, needle_single, sizeof(needle_single), 0);
}

SEC("syscall")
__success __retval(-EINVAL)
int test_dynptr_memmem_zero_len_haystack(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_from_mem((void *)bin_data, 0, 0, &ptr);
	return bpf_dynptr_memmem(&ptr, needle_single, sizeof(needle_single), 0);
}

SEC("syscall")
__success __retval(2)
int test_dynptr_memmem_periodic_pattern(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_from_mem((void *)periodic_buf, sizeof(periodic_buf) - 1, 0, &ptr);
	return bpf_dynptr_memmem(&ptr, periodic_needle, sizeof(periodic_needle) - 1, 0);
}

SEC("syscall")
__success __retval(24)
int test_dynptr_memmem_repetitive_prefix(void *ctx)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_from_mem((void *)rep_buf, sizeof(rep_buf) - 1, 0, &ptr);
	return bpf_dynptr_memmem(&ptr, rep_needle, sizeof(rep_needle) - 1, 0);
}
