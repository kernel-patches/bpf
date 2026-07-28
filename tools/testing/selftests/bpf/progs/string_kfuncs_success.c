// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2025 Red Hat, Inc.*/
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "errno.h"

char str[] = "hello world";
char aligned_str[] __aligned(8) = "0123456789abcdef0123456789ABCDEF";
char unaligned_str[] __aligned(8) = "_0123456789abcdef0123456789ABCDEF";
char scan_order[] __aligned(8) = { 'a', 'H', '\0', 'H', 'x', 'x', 'x', 'x' };
char compare_order1[] __aligned(8) = { 'a', 'b', '\0', 'x', 'x', 'x', 'x', 'x' };
char compare_order2[] __aligned(8) = { 'a', 'b', '\0', 'y', 'y', 'y', 'y', 'y' };

#define __test(retval) SEC("syscall") __success __retval(retval)

/* Functional tests */
__test(0) int test_strcmp_eq(void *ctx) { return bpf_strcmp(str, "hello world"); }
__test(1) int test_strcmp_neq(void *ctx) { return bpf_strcmp(str, "hello"); }
__test(0) int test_strcasecmp_eq1(void *ctx) { return bpf_strcasecmp(str, "hello world"); }
__test(0) int test_strcasecmp_eq2(void *ctx) { return bpf_strcasecmp(str, "HELLO WORLD"); }
__test(0) int test_strcasecmp_eq3(void *ctx) { return bpf_strcasecmp(str, "HELLO world"); }
__test(1) int test_strcasecmp_neq1(void *ctx) { return bpf_strcasecmp(str, "hello"); }
__test(1) int test_strcasecmp_neq2(void *ctx) { return bpf_strcasecmp(str, "HELLO"); }
__test(0) int test_strncasecmp_eq1(void *ctx) { return bpf_strncasecmp(str, "hello world", 11); }
__test(0) int test_strncasecmp_eq2(void *ctx) { return bpf_strncasecmp(str, "HELLO WORLD", 11); }
__test(0) int test_strncasecmp_eq3(void *ctx) { return bpf_strncasecmp(str, "HELLO world", 11); }
__test(0) int test_strncasecmp_eq4(void *ctx) { return bpf_strncasecmp(str, "hello", 5); }
__test(0) int test_strncasecmp_eq5(void *ctx) { return bpf_strncasecmp(str, "hello world!", 11); }
__test(-1) int test_strncasecmp_neq1(void *ctx) { return bpf_strncasecmp(str, "hello!", 6); }
__test(1) int test_strncasecmp_neq2(void *ctx) { return bpf_strncasecmp(str, "abc", 3); }
__test(1) int test_strchr_found(void *ctx) { return bpf_strchr(str, 'e'); }
__test(11) int test_strchr_null(void *ctx) { return bpf_strchr(str, '\0'); }
__test(-ENOENT) int test_strchr_notfound(void *ctx) { return bpf_strchr(str, 'x'); }
__test(1) int test_strchrnul_found(void *ctx) { return bpf_strchrnul(str, 'e'); }
__test(11) int test_strchrnul_notfound(void *ctx) { return bpf_strchrnul(str, 'x'); }
__test(1) int test_strnchr_found(void *ctx) { return bpf_strnchr(str, 5, 'e'); }
__test(11) int test_strnchr_null(void *ctx) { return bpf_strnchr(str, 12, '\0'); }
__test(-ENOENT) int test_strnchr_notfound(void *ctx) { return bpf_strnchr(str, 5, 'w'); }
__test(9) int test_strrchr_found(void *ctx) { return bpf_strrchr(str, 'l'); }
__test(11) int test_strrchr_null(void *ctx) { return bpf_strrchr(str, '\0'); }
__test(-ENOENT) int test_strrchr_notfound(void *ctx) { return bpf_strrchr(str, 'x'); }
__test(11) int test_strlen(void *ctx) { return bpf_strlen(str); }
__test(11) int test_strnlen(void *ctx) { return bpf_strnlen(str, 12); }
__test(5) int test_strspn(void *ctx) { return bpf_strspn(str, "ehlo"); }
__test(2) int test_strcspn(void *ctx) { return bpf_strcspn(str, "lo"); }
__test(6) int test_strstr_found(void *ctx) { return bpf_strstr(str, "world"); }
__test(6) int test_strcasestr_found(void *ctx) { return bpf_strcasestr(str, "woRLD"); }
__test(-ENOENT) int test_strstr_notfound(void *ctx) { return bpf_strstr(str, "hi"); }
__test(-ENOENT) int test_strcasestr_notfound(void *ctx) { return bpf_strcasestr(str, "hi"); }
__test(0) int test_strstr_empty(void *ctx) { return bpf_strstr(str, ""); }
__test(0) int test_strcasestr_empty(void *ctx) { return bpf_strcasestr(str, ""); }
__test(0) int test_strnstr_found1(void *ctx) { return bpf_strnstr("", "", 0); }
__test(0) int test_strnstr_found2(void *ctx) { return bpf_strnstr(str, "hello", 5); }
__test(0) int test_strnstr_found3(void *ctx) { return bpf_strnstr(str, "hello", 6); }
__test(-ENOENT) int test_strnstr_notfound1(void *ctx) { return bpf_strnstr(str, "hi", 10); }
__test(-ENOENT) int test_strnstr_notfound2(void *ctx) { return bpf_strnstr(str, "hello", 4); }
__test(-ENOENT) int test_strnstr_notfound3(void *ctx) { return bpf_strnstr("", "a", 0); }
__test(0) int test_strnstr_empty(void *ctx) { return bpf_strnstr(str, "", 1); }
__test(0) int test_strncasestr_found1(void *ctx) { return bpf_strncasestr("", "", 0); }
__test(0) int test_strncasestr_found2(void *ctx) { return bpf_strncasestr(str, "heLLO", 5); }
__test(0) int test_strncasestr_found3(void *ctx) { return bpf_strncasestr(str, "heLLO", 6); }
__test(-ENOENT) int test_strncasestr_notfound1(void *ctx) { return bpf_strncasestr(str, "hi", 10); }
__test(-ENOENT) int test_strncasestr_notfound2(void *ctx) { return bpf_strncasestr(str, "hello", 4); }
__test(-ENOENT) int test_strncasestr_notfound3(void *ctx) { return bpf_strncasestr("", "a", 0); }
__test(0) int test_strncasestr_empty(void *ctx) { return bpf_strncasestr(str, "", 1); }

/* Exercise aligned word loads, mask ordering, and unaligned prefixes. */
__test(30) int test_strnchr_word(void *ctx) { return bpf_strnchr(aligned_str, 32, 'E'); }

__test(1) int test_strnchr_word_before_null(void *ctx)
{
	return bpf_strnchr(scan_order, sizeof(scan_order), 'H');
}

__test(-ENOENT) int test_strnchr_word_after_null(void *ctx)
{
	return bpf_strnchr(scan_order, sizeof(scan_order), 'x');
}

__test(2) int test_strchrnul_word_after_null(void *ctx)
{
	return bpf_strchrnul(scan_order, 'x');
}

__test(1) int test_strrchr_word_after_null(void *ctx)
{
	return bpf_strrchr(scan_order, 'H');
}

__test(2) int test_strnlen_word_null(void *ctx)
{
	return bpf_strnlen(scan_order, sizeof(scan_order));
}

__test(32) int test_strlen_word(void *ctx) { return bpf_strlen(aligned_str); }

__test(0) int test_strcmp_word(void *ctx) { return bpf_strcmp(aligned_str, unaligned_str + 1); }

__test(0) int test_strcmp_word_after_null(void *ctx)
{
	return bpf_strcmp(compare_order1, compare_order2);
}

__test(-1) int test_strcmp_word_mismatch(void *ctx)
{
	return bpf_strcmp(aligned_str, "0123456789abcdef1123456789abcdef");
}

__test(32) int test_strspn_word(void *ctx)
{
	return bpf_strspn(aligned_str, "0123456789abcdefABCDEF");
}

__test(0) int test_strspn_word_set_after_null(void *ctx)
{
	return bpf_strspn("xx", scan_order);
}

__test(30) int test_strcspn_word(void *ctx) { return bpf_strcspn(unaligned_str + 1, "E"); }

__test(16) int test_strstr_word(void *ctx) { return bpf_strstr(aligned_str, "0123456789ABCDEF"); }

__test(16) int test_strstr_unaligned(void *ctx)
{
	return bpf_strstr(unaligned_str + 1, "0123456789ABCDEF");
}

__test(15) int test_strcasestr_word(void *ctx)
{
	return bpf_strcasestr(aligned_str, "F0123456789ABCDEF");
}

__test(0) int test_strnstr_word_suffix(void *ctx)
{
	return bpf_strnstr(aligned_str, "0123456789abcdef", 16);
}

__test(-ENOENT) int test_strnstr_word_truncated(void *ctx)
{
	return bpf_strnstr(aligned_str, "0123456789abcdef0", 16);
}

__test(0) int test_strnstr_word_after_null(void *ctx)
{
	return bpf_strnstr(compare_order1, compare_order2, sizeof(compare_order1));
}

char _license[] SEC("license") = "GPL";
