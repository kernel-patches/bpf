// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "../bpf_testmod/bpf_testmod.h"

#define BUFSZ 10

int bpf_strcmp(const char *cs, const char *ct) __ksym;
char *bpf_strchr(const char *s, int c) __ksym;
char *bpf_strrchr(const char *s, int c) __ksym;
char *bpf_strnchr(const char *s, size_t count, int c) __ksym;
char *bpf_strstr(const char *s1, const char *s2) __ksym;
char *bpf_strnstr(const char *s1, const char *s2, size_t len) __ksym;
size_t bpf_strlen(const char *) __ksym;
size_t bpf_strnlen(const char *s, size_t count) __ksym;
char *bpf_strpbrk(const char *cs, const char *ct) __ksym;
size_t bpf_strspn(const char *s, const char *accept) __ksym;
size_t bpf_strcspn(const char *s, const char *reject) __ksym;

__u32 strcmp_check = 0;

SEC("raw_tp/bpf_testmod_test_write_bare")
int BPF_PROG(test_strcmp,
	     struct task_struct *task, struct bpf_testmod_test_write_ctx *write_ctx)
{
	char buf[BUFSZ], *buf_ptr;
	char expected[] = "aaaaaaaaa";

	buf_ptr = BPF_PROBE_READ(write_ctx, buf);
	bpf_probe_read_kernel_str(buf, sizeof(buf), buf_ptr);

	if (bpf_strcmp(buf, expected) == 0)
		strcmp_check = 1;

	return 0;
}

__u32 strchr_check = 0;

SEC("raw_tp/bpf_testmod_test_write_bare")
int BPF_PROG(test_strchr,
	     struct task_struct *task, struct bpf_testmod_test_write_ctx *write_ctx)
{
	char buf[BUFSZ], *buf_ptr;

	buf_ptr = BPF_PROBE_READ(write_ctx, buf);
	bpf_probe_read_kernel_str(buf, sizeof(buf), buf_ptr);

	if (bpf_strchr(buf, 'a') == buf)
		strchr_check = 1;

	return 0;
}

__u32 strrchr_check = 0;

SEC("raw_tp/bpf_testmod_test_write_bare")
int BPF_PROG(test_strrchr,
	     struct task_struct *task, struct bpf_testmod_test_write_ctx *write_ctx)
{
	char buf[BUFSZ], *buf_ptr;

	buf_ptr = BPF_PROBE_READ(write_ctx, buf);
	bpf_probe_read_kernel_str(buf, sizeof(buf), buf_ptr);

	if (bpf_strrchr(buf, 'a') == &buf[8])
		strrchr_check = 1;

	return 0;
}

__u32 strnchr_check = 0;

SEC("raw_tp/bpf_testmod_test_write_bare")
int BPF_PROG(test_strnchr,
	     struct task_struct *task, struct bpf_testmod_test_write_ctx *write_ctx)
{
	char buf[BUFSZ], *buf_ptr;

	buf_ptr = BPF_PROBE_READ(write_ctx, buf);
	bpf_probe_read_kernel_str(buf, sizeof(buf), buf_ptr);

	if (bpf_strnchr(buf, 1, 'a') == buf)
		strnchr_check = 1;

	return 0;
}

__u32 strstr_check = 0;

SEC("raw_tp/bpf_testmod_test_write_bare")
int BPF_PROG(test_strstr,
	     struct task_struct *task, struct bpf_testmod_test_write_ctx *write_ctx)
{
	char buf[BUFSZ], *buf_ptr;
	char substr[] = "aaa";

	buf_ptr = BPF_PROBE_READ(write_ctx, buf);
	bpf_probe_read_kernel_str(buf, sizeof(buf), buf_ptr);

	if (bpf_strstr(buf, substr) == buf)
		strstr_check = 1;

	return 0;
}

__u32 strnstr_check = 0;

SEC("raw_tp/bpf_testmod_test_write_bare")
int BPF_PROG(test_strnstr,
	     struct task_struct *task, struct bpf_testmod_test_write_ctx *write_ctx)
{
	char buf[BUFSZ], *buf_ptr;
	char substr[] = "aaa";

	buf_ptr = BPF_PROBE_READ(write_ctx, buf);
	bpf_probe_read_kernel_str(buf, sizeof(buf), buf_ptr);

	if (bpf_strnstr(buf, substr, 3) == buf)
		strnstr_check = 1;

	return 0;
}

__u32 strlen_check = 0;

SEC("raw_tp/bpf_testmod_test_write_bare")
int BPF_PROG(test_strlen,
	     struct task_struct *task, struct bpf_testmod_test_write_ctx *write_ctx)
{
	char buf[BUFSZ], *buf_ptr;

	buf_ptr = BPF_PROBE_READ(write_ctx, buf);
	bpf_probe_read_kernel_str(buf, sizeof(buf), buf_ptr);

	if (bpf_strlen(buf) == 9)
		strlen_check = 1;

	return 0;
}

__u32 strnlen_check = 0;

SEC("raw_tp/bpf_testmod_test_write_bare")
int BPF_PROG(test_strnlen,
	     struct task_struct *task, struct bpf_testmod_test_write_ctx *write_ctx)
{
	char buf[BUFSZ], *buf_ptr;

	buf_ptr = BPF_PROBE_READ(write_ctx, buf);
	bpf_probe_read_kernel_str(buf, sizeof(buf), buf_ptr);

	if (bpf_strnlen(buf, 5) == 5)
		strnlen_check = 1;

	return 0;
}

__u32 strpbrk_check = 0;

SEC("raw_tp/bpf_testmod_test_write_bare")
int BPF_PROG(test_strpbrk,
	     struct task_struct *task, struct bpf_testmod_test_write_ctx *write_ctx)
{
	char buf[BUFSZ], *buf_ptr;
	char accept[] = "abc";

	buf_ptr = BPF_PROBE_READ(write_ctx, buf);
	bpf_probe_read_kernel_str(buf, sizeof(buf), buf_ptr);

	if (bpf_strpbrk(buf, accept) == buf)
		strpbrk_check = 1;

	return 0;
}

__u32 strspn_check = 0;

SEC("raw_tp/bpf_testmod_test_write_bare")
int BPF_PROG(test_strspn,
	     struct task_struct *task, struct bpf_testmod_test_write_ctx *write_ctx)
{
	char buf[BUFSZ], *buf_ptr;
	char accept[] = "abc";

	buf_ptr = BPF_PROBE_READ(write_ctx, buf);
	bpf_probe_read_kernel_str(buf, sizeof(buf), buf_ptr);

	if (bpf_strspn(buf, accept) == 9)
		strspn_check = 1;

	return 0;
}

__u32 strcspn_check = 0;

SEC("raw_tp/bpf_testmod_test_write_bare")
int BPF_PROG(test_strcspn,
	     struct task_struct *task, struct bpf_testmod_test_write_ctx *write_ctx)
{
	char buf[BUFSZ], *buf_ptr;
	char reject[] = "abc";

	buf_ptr = BPF_PROBE_READ(write_ctx, buf);
	bpf_probe_read_kernel_str(buf, sizeof(buf), buf_ptr);

	if (bpf_strcspn(buf, reject) == 0)
		strcspn_check = 1;

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
