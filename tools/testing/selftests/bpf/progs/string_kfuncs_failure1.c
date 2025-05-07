// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2025 Red Hat, Inc.*/
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char *nullptr = NULL;
char *invalid_ptr = (char *)0x12345678;

/* Passing NULL by value to string kfuncs is allowed by the verifier but the kfunc should return -EINVAL */
SEC("syscall") __retval(-14) int test_strcmp_null(void *ctx) { return bpf_strcmp(NULL, NULL); }
SEC("syscall") __retval(-14) int test_strchr_null(void *ctx) { return (u64)bpf_strchr(NULL, 'a'); }
SEC("syscall") __retval(-14) int test_strchrnul_null(void *ctx) { return (u64)bpf_strchrnul(NULL, 'a'); }
SEC("syscall") __retval(-14) int test_strnchr_null(void *ctx) { return (u64)bpf_strnchr(NULL, 1, 'a'); }
SEC("syscall") __retval(-14) int test_strrchr_null(void *ctx) { return (u64)bpf_strrchr(NULL, 'a'); }
SEC("syscall") __retval(-14) int test_strlen_null(void *ctx) { return bpf_strlen(NULL); }
SEC("syscall") __retval(-14) int test_strnlen_null(void *ctx) { return bpf_strnlen(NULL, 1); }
SEC("syscall") __retval(-14) int test_strspn_null(void *ctx) { return bpf_strspn(NULL, NULL); }
SEC("syscall") __retval(-14) int test_strcspn_null(void *ctx) { return bpf_strcspn(NULL, NULL); }
SEC("syscall") __retval(-14) int test_strpbrk_null(void *ctx) { return (u64)bpf_strpbrk(NULL, NULL); }
SEC("syscall") __retval(-14) int test_strstr_null(void *ctx) { return (u64)bpf_strstr(NULL, NULL); }
SEC("syscall") __retval(-14) int test_strnstr_null(void *ctx) { return (u64)bpf_strnstr(NULL, NULL, 1); }

/* Passing a NULL or an invalid pointer to string kfuncs should be rejected by the verifier*/
SEC("syscall") __failure int test_strcmp_nullptr(void *ctx) { return bpf_strcmp(nullptr, nullptr); }
SEC("syscall") __failure int test_strchr_nullptr(void *ctx) { return (u64)bpf_strchr(nullptr, 'a'); }
SEC("syscall") __failure int test_strchrnul_nullptr(void *ctx) { return (u64)bpf_strchrnul(nullptr, 'a'); }
SEC("syscall") __failure int test_strnchr_nullptr(void *ctx) { return (u64)bpf_strnchr(nullptr, 1, 'a'); }
SEC("syscall") __failure int test_strrchr_nullptr(void *ctx) { return (u64)bpf_strrchr(nullptr, 'a'); }
SEC("syscall") __failure int test_strlen_nullptr(void *ctx) { return bpf_strlen(nullptr); }
SEC("syscall") __failure int test_strnlen_nullptr(void *ctx) { return bpf_strnlen(nullptr, 1); }
SEC("syscall") __failure int test_strspn_nullptr(void *ctx) { return bpf_strspn(nullptr, nullptr); }
SEC("syscall") __failure int test_strcspn_nullptr(void *ctx) { return bpf_strcspn(nullptr, nullptr); }
SEC("syscall") __failure int test_strpbrk_nullptr(void *ctx) { return (u64)bpf_strpbrk(nullptr, nullptr); }
SEC("syscall") __failure int test_strstr_nullptr(void *ctx) { return (u64)bpf_strstr(nullptr, nullptr); }
SEC("syscall") __failure int test_strnstr_nullptr(void *ctx) { return (u64)bpf_strnstr(nullptr, nullptr, 1); }

SEC("syscall") __failure int test_strcmp_invalid_ptr(void *ctx) { return bpf_strcmp(invalid_ptr, invalid_ptr); }
SEC("syscall") __failure int test_strchr_invalid_ptr(void *ctx) { return (u64)bpf_strchr(invalid_ptr, 'a'); }
SEC("syscall") __failure int test_strchrnul_invalid_ptr(void *ctx) { return (u64)bpf_strchrnul(invalid_ptr, 'a'); }
SEC("syscall") __failure int test_strnchr_invalid_ptr(void *ctx) { return (u64)bpf_strnchr(invalid_ptr, 1, 'a'); }
SEC("syscall") __failure int test_strrchr_invalid_ptr(void *ctx) { return (u64)bpf_strrchr(invalid_ptr, 'a'); }
SEC("syscall") __failure int test_strlen_invalid_ptr(void *ctx) { return bpf_strlen(invalid_ptr); }
SEC("syscall") __failure int test_strnlen_invalid_ptr(void *ctx) { return bpf_strnlen(invalid_ptr, 1); }
SEC("syscall") __failure int test_strspn_invalid_ptr(void *ctx) { return bpf_strspn(invalid_ptr, invalid_ptr); }
SEC("syscall") __failure int test_strcspn_invalid_ptr(void *ctx) { return bpf_strcspn(invalid_ptr, invalid_ptr); }
SEC("syscall") __failure int test_strpbrk_invalid_ptr(void *ctx) { return (u64)bpf_strpbrk(invalid_ptr, invalid_ptr); }
SEC("syscall") __failure int test_strstr_invalid_ptr(void *ctx) { return (u64)bpf_strstr(invalid_ptr, invalid_ptr); }
SEC("syscall") __failure int test_strnstr_invalid_ptr(void *ctx) { return (u64)bpf_strnstr(invalid_ptr, invalid_ptr, 1); }

char _license[] SEC("license") = "GPL";
