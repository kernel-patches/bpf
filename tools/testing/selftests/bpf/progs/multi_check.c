// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

extern const void bpf_fentry_test1 __ksym;
extern const void bpf_fentry_test2 __ksym;
extern const void bpf_fentry_test3 __ksym;
extern const void bpf_fentry_test4 __ksym;
extern const void bpf_fentry_test5 __ksym;
extern const void bpf_fentry_test6 __ksym;
extern const void bpf_fentry_test7 __ksym;
extern const void bpf_fentry_test8 __ksym;

void multi_arg_check(__u64 *ctx, __u64 *test_result)
{
	void *ip = (void *) bpf_get_func_ip(ctx);

	if (ip == &bpf_fentry_test1) {
		int a = (int) ctx[0];

		*test_result += a == 1;
	} else if (ip == &bpf_fentry_test2) {
		int a = (int) ctx[0];
		__u64 b = ctx[1];

		*test_result += a == 2 && b == 3;
	} else if (ip == &bpf_fentry_test3) {
		int a = (int) ctx[0];
		int b = (int) ctx[1];
		__u64 c = ctx[2];

		*test_result += a == 4 && b == 5 && c == 6;
	} else if (ip == &bpf_fentry_test4) {
		void *a = (void *) ctx[0];
		int b = (int) ctx[1];
		int c = (int) ctx[2];
		__u64 d = ctx[3];

		*test_result += a == (void *) 7 && b == 8 && c == 9 && d == 10;
	} else if (ip == &bpf_fentry_test5) {
		__u64 a = ctx[0];
		void *b = (void *) ctx[1];
		short c = (short) ctx[2];
		int d = (int) ctx[3];
		__u64 e = ctx[4];

		*test_result += a == 11 && b == (void *) 12 && c == 13 && d == 14 && e == 15;
	} else if (ip == &bpf_fentry_test6) {
		__u64 a = ctx[0];
		void *b = (void *) ctx[1];
		short c = (short) ctx[2];
		int d = (int) ctx[3];
		void *e = (void *) ctx[4];
		__u64 f = ctx[5];

		*test_result += a == 16 && b == (void *) 17 && c == 18 && d == 19 && e == (void *) 20 && f == 21;
	} else if (ip == &bpf_fentry_test7) {
		*test_result += 1;
	} else if (ip == &bpf_fentry_test8) {
		*test_result += 1;
	}
}

void multi_ret_check(void *ctx, int ret, __u64 *test_result)
{
	void *ip = (void *) bpf_get_func_ip(ctx);

	if (ip == &bpf_fentry_test1)
		*test_result += ret == 2;
	else if (ip == &bpf_fentry_test2)
		*test_result += ret == 5;
	else if (ip == &bpf_fentry_test3)
		*test_result += ret == 15;
	else if (ip == &bpf_fentry_test4)
		*test_result += ret == 34;
	else if (ip == &bpf_fentry_test5)
		*test_result += ret == 65;
	else if (ip == &bpf_fentry_test6)
		*test_result += ret == 111;
	else if (ip == &bpf_fentry_test7)
		*test_result += ret == 0;
	else if (ip == &bpf_fentry_test8)
		*test_result += ret == 0;
}
