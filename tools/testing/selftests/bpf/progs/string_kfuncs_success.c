// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2025 Red Hat, Inc.*/
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char str[] = "hello world";

#define __test(retval) SEC("syscall") __success __retval(retval)

/* Functional tests */
__test(0) int test_strcmp_eq(void *ctx) { return bpf_strcmp(str, "hello world"); }
__test(1) int test_strcmp_neq(void *ctx) { return bpf_strcmp(str, "hello"); }
__test(1) int test_strchr_found(void *ctx) { return bpf_strchr(str, 'e') - str; }
__test(11) int test_strchr_null(void *ctx) { return bpf_strchr(str, '\0') - str; }
__test(0) u64 test_strchr_notfound(void *ctx) { return (u64)bpf_strchr(str, 'x'); }
__test(1) int test_strchrnul_found(void *ctx) { return bpf_strchrnul(str, 'e') - str; }
__test(11) int test_strchrnul_notfound(void *ctx) { return bpf_strchrnul(str, 'x') - str; }
__test(1) int test_strnchr_found(void *ctx) { return bpf_strnchr(str, 5, 'e') - str; }
__test(11) int test_strnchr_null(void *ctx) { return bpf_strnchr(str, 12, '\0') - str; }
__test(0) u64 test_strnchr_notfound(void *ctx) { return (u64)bpf_strnchr(str, 5, 'w'); }
__test(9) int test_strrchr_found(void *ctx) { return bpf_strrchr(str, 'l') - str; }
__test(0) u64 test_strrchr_notfound(void *ctx) { return (u64)bpf_strrchr(str, 'x'); }
__test(11) size_t test_strlen(void *ctx) { return bpf_strlen(str); }
__test(11) size_t test_strnlen(void *ctx) { return bpf_strnlen(str, 12); }
__test(5) size_t test_strspn(void *ctx) { return bpf_strspn(str, "ehlo"); }
__test(2) size_t test_strcspn(void *ctx) { return bpf_strcspn(str, "lo"); }
__test(2) int test_strpbrk_found(void *ctx) { return bpf_strpbrk(str, "lo") - str; }
__test(0) u64 test_strpbrk_notfound(void *ctx) { return (u64)bpf_strpbrk(str, "abc"); }
__test(6) int test_strstr_found(void *ctx) { return bpf_strstr(str, "world") - str; }
__test(0) u64 test_strstr_notfound(void *ctx) { return (u64)bpf_strstr(str, "hi"); }
__test(0) int test_strstr_empty(void *ctx) { return bpf_strstr(str, "") - str; }
__test(0) int test_strnstr_found(void *ctx) { return bpf_strnstr(str, "hello", 6) - str; }
__test(0) u64 test_strnstr_notfound(void *ctx) { return (u64)bpf_strnstr(str, "hi", 10); }
__test(0) int test_strnstr_empty(void *ctx) { return bpf_strnstr(str, "", 1) - str; }

/* The above functional tests pass a global variable (i.e. a map) to the kfuncs.
 * Now check that the kfuncs accept strings in other forms:
 * - string literals (i.e. read-only maps)
 * - stack-allocated buffers
 */
SEC("syscall")
__success __retval(0)
int test_string_kfuncs_literal(void *ctx)
{
	if (bpf_strcmp("abc", "abc") != 0) return -1;
	if (bpf_strchr("abc", 'x') != NULL) return -1;
	if (bpf_strchrnul("abc", 'x') == NULL) return -1;
	if (bpf_strnchr("abc", 3, 'x') != NULL) return -1;
	if (bpf_strrchr("abc", 'x') != NULL) return -1;
	if (bpf_strlen("abc") != 3) return -1;
	if (bpf_strnlen("abc", 3) != 3) return -1;
	if (bpf_strspn("abc", "abc") != 3) return -1;
	if (bpf_strcspn("abc", "abc") != 0) return -1;
	if (bpf_strpbrk("abc", "def") != NULL) return -1;
	if (bpf_strstr("abc", "def") != NULL) return -1;
	if (bpf_strnstr("abc", "def", 3) != NULL) return -1;

	return 0;
}

SEC("syscall")
__success __retval(0)
int test_string_kfuncs_buffer(void *ctx)
{
	char buffer[16];

	__builtin_memset(buffer, 'a', sizeof(buffer));
	buffer[sizeof(buffer) - 1] = '\0';

	if (bpf_strcmp(buffer, buffer) != 0) return -1;
	if (bpf_strchr(buffer, 'a') != buffer) return -1;
	if (bpf_strchrnul(buffer, 'a') != buffer) return -1;
	if (bpf_strnchr(buffer, sizeof(buffer), 'a') != buffer) return -1;
	if (bpf_strrchr(buffer, 'b') != NULL) return -1;
	if (bpf_strlen(buffer) != sizeof(buffer) - 1) return -1;
	if (bpf_strnlen(buffer, sizeof(buffer)) != sizeof(buffer) - 1) return -1;
	if (bpf_strspn(buffer, buffer) != sizeof(buffer) - 1) return -1;
	if (bpf_strcspn(buffer, buffer) != 0) return -1;
	if (bpf_strpbrk(buffer, buffer) != buffer) return -1;
	if (bpf_strstr(buffer, buffer) != buffer) return -1;
	if (bpf_strnstr(buffer, buffer, sizeof(buffer)) != buffer) return -1;

	return 0;
}

char _license[] SEC("license") = "GPL";
