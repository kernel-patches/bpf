// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2025 Red Hat, Inc.*/
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

int bpf_strcmp(const char *cs, const char *ct) __ksym;
char *bpf_strchr(const char *s, int c) __ksym;
char *bpf_strchrnul(const char *s, int c) __ksym;
char *bpf_strnchr(void *s, u32 s__sz, int c) __ksym;
char *bpf_strnchrnul(void *s, u32 s__sz, int c) __ksym;
char *bpf_strrchr(const char *s, int c) __ksym;
size_t bpf_strlen(const char *s) __ksym;
size_t bpf_strnlen(void *s, u32 s__sz) __ksym;
size_t bpf_strspn(const char *s, const char *accept) __ksym;
size_t bpf_strcspn(const char *s, const char *reject) __ksym;
char *bpf_strpbrk(const char *cs, const char *ct) __ksym;
char *bpf_strstr(const char *s1, const char *s2) __ksym;
char *bpf_strstr(const char *s1, const char *s2) __ksym;
char *bpf_strnstr(void *s1, u32 s1__sz, void *s2, u32 s2__sz) __ksym;

char str1[] = "hello world";
char str2[] = "hello";
char str3[] = "world";
char str4[] = "abc";
char str5[] = "";

#define __test(retval) SEC("syscall") __success __retval(retval)

__test(0) int test_strcmp_eq(void *ctx) { return bpf_strcmp(str1, str1); }
__test(1) int test_strcmp_neq(void *ctx) { return bpf_strcmp(str1, str2); }
__test(1) int test_strchr_found(void *ctx) { return bpf_strchr(str1, 'e') - str1; }
__test(11) int test_strchr_null(void *ctx) { return bpf_strchr(str1, '\0') - str1; }
__test(0) u64 test_strchr_notfound(void *ctx) { return (u64)bpf_strchr(str1, 'x'); }
__test(1) int test_strchrnul_found(void *ctx) { return bpf_strchrnul(str1, 'e') - str1; }
__test(11) int test_strchrnul_notfound(void *ctx) { return bpf_strchrnul(str1, 'x') - str1; }
__test(1) int test_strnchr_found(void *ctx) { return bpf_strnchr(str1, 5, 'e') - str1; }
__test(11) int test_strnchr_null(void *ctx) { return bpf_strnchr(str1, 12, '\0') - str1; }
__test(0) u64 test_strnchr_notfound(void *ctx) { return (u64)bpf_strnchr(str1, 5, 'w'); }
__test(1) int test_strnchrnul_found(void *ctx) { return bpf_strnchrnul(str1, 5, 'e') - str1; }
__test(11) int test_strnchrnul_notfound(void *ctx) { return bpf_strnchrnul(str1, 12, 'x') - str1; }
__test(9) int test_strrchr_found(void *ctx) { return bpf_strrchr(str1, 'l') - str1; }
__test(0) u64 test_strrchr_notfound(void *ctx) { return (u64)bpf_strrchr(str1, 'x'); }
__test(11) size_t test_strlen(void *ctx) { return bpf_strlen(str1); }
__test(11) size_t test_strnlen(void *ctx) { return bpf_strnlen(str1, 12); }
__test(5) size_t test_strspn(void *ctx) { return bpf_strspn(str1, str2); }
__test(2) size_t test_strcspn(void *ctx) { return bpf_strcspn(str1, str3); }
__test(2) int test_strpbrk_found(void *ctx) { return bpf_strpbrk(str1, str3) - str1; }
__test(0) u64 test_strpbrk_notfound(void *ctx) { return (u64)bpf_strpbrk(str1, str4); }
__test(6) int test_strstr_found(void *ctx) { return bpf_strstr(str1, str3) - str1; }
__test(0) u64 test_strstr_notfound(void *ctx) { return (u64)bpf_strstr(str1, str4); }
__test(0) int test_strstr_empty(void *ctx) { return bpf_strstr(str1, str5) - str1; }
__test(6) int test_strnstr_found(void *ctx) { return bpf_strnstr(str1, 12, str3, 6) - str1; }
__test(0) u64 test_strnstr_unsafe(void *ctx) { return (u64)bpf_strnstr(str1, 5, str3, 5); }
__test(0) u64 test_strnstr_notfound(void *ctx) { return (u64)bpf_strnstr(str1, 12, str4, 4); }
__test(0) int test_strnstr_empty(void *ctx) { return bpf_strnstr(str1, 5, str5, 1) - str1; }

char _license[] SEC("license") = "GPL";
