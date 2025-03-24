// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2025. Red Hat, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define STR_SZ 4096

size_t bpf_strlen(const char *s) __ksym;
size_t bpf_strnlen(void *s, u32 s__sz) __ksym;
char *bpf_strchr(const char *s, int c) __ksym;
char *bpf_strnchr(void *s, u32 s__sz, int c) __ksym;
char *bpf_strchrnul(const char *s, int c) __ksym;
char *bpf_strnchrnul(void *s, u32 s__sz, int c) __ksym;
char *bpf_strstr(const char *s1, const char *s2) __ksym;
char *bpf_strnstr(void *s1, u32 s1__sz, void *s2, u32 s2__sz) __ksym;

/* Will be updated by benchmark before program loading */
const volatile unsigned int str_len = 1;
long hits = 0;
char str[STR_SZ];
char substr[STR_SZ];

char _license[] SEC("license") = "GPL";

SEC("tp/syscalls/sys_enter_getpgid")
int strlen_bench(void *ctx)
{
	if (bpf_strlen(str) > 0)
		__sync_add_and_fetch(&hits, 1);
	return 0;
}

SEC("tp/syscalls/sys_enter_getpgid")
int strnlen_bench(void *ctx)
{
	if (bpf_strnlen(str, str_len + 1) > 0)
		__sync_add_and_fetch(&hits, 1);
	return 0;
}

SEC("tp/syscalls/sys_enter_getpgid")
int strchr_bench(void *ctx)
{
	if (bpf_strchr(str, '0') != NULL)
		__sync_add_and_fetch(&hits, 1);
	return 0;
}

SEC("tp/syscalls/sys_enter_getpgid")
int strnchr_bench(void *ctx)
{
	if (bpf_strnchr(str, str_len + 1, '0') != NULL)
		__sync_add_and_fetch(&hits, 1);
	return 0;
}

SEC("tp/syscalls/sys_enter_getpgid")
int strchrnul_bench(void *ctx)
{
	if (*bpf_strchrnul(str, '0') != '\0')
		__sync_add_and_fetch(&hits, 1);
	return 0;
}

SEC("tp/syscalls/sys_enter_getpgid")
int strnchrnul_bench(void *ctx)
{
	if (*bpf_strnchrnul(str, str_len + 1, '0') != '\0')
		__sync_add_and_fetch(&hits, 1);
	return 0;
}

SEC("tp/syscalls/sys_enter_getpgid")
int strstr_bench(void *ctx)
{
	if (bpf_strstr(str, substr) != NULL)
		__sync_add_and_fetch(&hits, 1);
	return 0;
}

SEC("tp/syscalls/sys_enter_getpgid")
int strnstr_bench(void *ctx)
{
	if (bpf_strnstr(str, str_len + 1, substr, str_len / 4 + 1) != NULL)
		__sync_add_and_fetch(&hits, 1);
	return 0;
}
