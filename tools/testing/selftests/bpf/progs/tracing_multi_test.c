// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 ByteDance */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct bpf_testmod_struct_arg_1 {
	int a;
};
struct bpf_testmod_struct_arg_2 {
	long a;
	long b;
};

__u64 test_result = 0;

int pid = 0;
int test_cookie = 0;

__u64 fentry_test1_result = 0;
__u64 fentry_test2_result = 0;
__u64 fentry_test3_result = 0;
__u64 fentry_test4_result = 0;
__u64 fentry_test5_result = 0;
__u64 fentry_test6_result = 0;
__u64 fentry_test7_result = 0;
__u64 fentry_test8_result = 0;

extern const void bpf_fentry_test1 __ksym;
extern const void bpf_fentry_test2 __ksym;
extern const void bpf_fentry_test3 __ksym;
extern const void bpf_fentry_test4 __ksym;
extern const void bpf_fentry_test5 __ksym;
extern const void bpf_fentry_test6 __ksym;
extern const void bpf_fentry_test7 __ksym;
extern const void bpf_fentry_test8 __ksym;

SEC("fentry.multi/bpf_testmod_test_struct_arg_1,bpf_testmod_test_struct_arg_9")
int BPF_PROG2(fentry_success_test1, struct bpf_testmod_struct_arg_2, a)
{
	test_result = a.a + a.b;
	return 0;
}

SEC("fentry.multi/bpf_testmod_test_struct_arg_2,bpf_testmod_test_struct_arg_10")
int BPF_PROG2(fentry_success_test2, int, a, struct bpf_testmod_struct_arg_2, b)
{
	test_result = a + b.a + b.b;
	return 0;
}

SEC("fentry.multi/bpf_testmod_test_arg_ptr_2,bpf_testmod_test_arg_ptr_4")
int BPF_PROG(fentry_success_test3, struct bpf_testmod_struct_arg_2 *a)
{
	test_result = a->a + a->b;
	return 0;
}

SEC("fentry.multi/bpf_testmod_test_struct_arg_1,bpf_testmod_test_struct_arg_4")
int BPF_PROG2(fentry_success_test4, struct bpf_testmod_struct_arg_2, a, int, b,
	      int, c)
{
	test_result = c;
	return 0;
}

SEC("fentry.multi/bpf_testmod_test_struct_arg_1,bpf_testmod_test_struct_arg_2")
int BPF_PROG2(fentry_success_test5, struct bpf_testmod_struct_arg_2, a, int, b,
	      int, c)
{
	test_result = c;
	return 0;
}

SEC("fentry.multi/bpf_testmod_test_struct_arg_1,bpf_testmod_test_struct_arg_1")
int BPF_PROG2(fentry_fail_test1, struct bpf_testmod_struct_arg_2, a)
{
	test_result = a.a + a.b;
	return 0;
}

SEC("fentry.multi/bpf_testmod_test_struct_arg_1,bpf_testmod_test_struct_arg_2")
int BPF_PROG2(fentry_fail_test2, struct bpf_testmod_struct_arg_2, a)
{
	test_result = a.a + a.b;
	return 0;
}

SEC("fentry.multi/bpf_testmod_test_struct_arg_1,bpf_testmod_test_arg_ptr_2")
int BPF_PROG2(fentry_fail_test3, struct bpf_testmod_struct_arg_2, a)
{
	test_result = a.a + a.b;
	return 0;
}

SEC("fentry.multi/bpf_testmod_test_struct_arg_2,bpf_testmod_test_struct_arg_2")
int BPF_PROG2(fentry_fail_test4, int, a, struct bpf_testmod_struct_arg_2, b)
{
	test_result = a + b.a + b.b;
	return 0;
}

SEC("fentry.multi/bpf_testmod_test_struct_arg_2,bpf_testmod_test_struct_arg_9")
int BPF_PROG2(fentry_fail_test5, int, a, struct bpf_testmod_struct_arg_2, b)
{
	test_result = a + b.a + b.b;
	return 0;
}

SEC("fentry.multi/bpf_testmod_test_struct_arg_2,bpf_testmod_test_arg_ptr_3")
int BPF_PROG2(fentry_fail_test6, int, a, struct bpf_testmod_struct_arg_2, b)
{
	test_result = a + b.a + b.b;
	return 0;
}

SEC("fentry.multi/bpf_testmod_test_arg_ptr_2,bpf_testmod_test_arg_ptr_3")
int BPF_PROG(fentry_fail_test7, struct bpf_testmod_struct_arg_2 *a)
{
	test_result = a->a + a->b;
	return 0;
}

SEC("fentry.multi/bpf_testmod_test_struct_arg_1,bpf_testmod_test_struct_arg_12")
int BPF_PROG2(fentry_fail_test8, struct bpf_testmod_struct_arg_2, a, int, b,
	      int, c)
{
	test_result = c;
	return 0;
}

SEC("fexit.multi/bpf_testmod_test_struct_arg_1,bpf_testmod_test_struct_arg_2,bpf_testmod_test_struct_arg_3")
int BPF_PROG2(fexit_success_test1, struct bpf_testmod_struct_arg_2, a, int, b,
	      int, c, int, retval)
{
	test_result = retval;
	return 0;
}

SEC("fexit.multi/bpf_testmod_test_struct_arg_2,bpf_testmod_test_struct_arg_12")
int BPF_PROG2(fexit_success_test2, int, a, struct bpf_testmod_struct_arg_2, b,
	      int, c, int, retval)
{
	test_result = a + b.a + b.b + retval;
	return 0;
}

SEC("fexit.multi/bpf_testmod_test_struct_arg_1,bpf_testmod_test_struct_arg_4")
int BPF_PROG2(fexit_fail_test1, struct bpf_testmod_struct_arg_2, a, int, b,
	      int, c, int, retval)
{
	test_result = retval;
	return 0;
}

SEC("fexit.multi/bpf_testmod_test_struct_arg_2,bpf_testmod_test_struct_arg_10")
int BPF_PROG2(fexit_fail_test2, int, a, struct bpf_testmod_struct_arg_2, b,
	      int, c, int, retval)
{
	test_result = a + b.a + b.b + retval;
	return 0;
}

SEC("fexit.multi/bpf_testmod_test_struct_arg_2,bpf_testmod_test_struct_arg_11")
int BPF_PROG2(fexit_fail_test3, int, a, struct bpf_testmod_struct_arg_2, b,
	      int, c, int, retval)
{
	test_result = a + b.a + b.b + retval;
	return 0;
}

SEC("fmod_ret.multi/bpf_modify_return_test,bpf_modify_return_test2")
int BPF_PROG(fmod_ret_success_test1, int a, int *b)
{
	return 0;
}

static void tracing_multi_check(unsigned long long *ctx)
{
	if (bpf_get_current_pid_tgid() >> 32 != pid)
		return;

	__u64 cookie = test_cookie ? bpf_get_attach_cookie(ctx) : 0;
	__u64 addr = bpf_get_func_ip(ctx);

#define SET(__var, __addr, __cookie) ({			\
	if (((const void *) addr == __addr) &&		\
	     (!test_cookie || (cookie == __cookie)))	\
		__var = 1;				\
})
	SET(fentry_test1_result, &bpf_fentry_test1, 1);
	SET(fentry_test2_result, &bpf_fentry_test2, 7);
	SET(fentry_test3_result, &bpf_fentry_test3, 2);
	SET(fentry_test4_result, &bpf_fentry_test4, 3);
	SET(fentry_test5_result, &bpf_fentry_test5, 4);
	SET(fentry_test6_result, &bpf_fentry_test6, 5);
	SET(fentry_test7_result, &bpf_fentry_test7, 6);
	SET(fentry_test8_result, &bpf_fentry_test8, 8);
}

SEC("fentry.multi/bpf_fentry_test1")
int BPF_PROG(fentry_manual_test1)
{
	tracing_multi_check(ctx);
	return 0;
}
