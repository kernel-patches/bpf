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
	__u64 value = 0;

	if (ip == &bpf_fentry_test1) {
		int a;

		if (bpf_get_func_arg(ctx, 0, &value))
			return;
		a = (int) value;

		*test_result += a == 1;
	} else if (ip == &bpf_fentry_test2) {
		__u64 b;
		int a;

		if (bpf_get_func_arg(ctx, 0, &value))
			return;
		a = (int) value;
		if (bpf_get_func_arg(ctx, 1, &value))
			return;
		b = value;

		*test_result += a == 2 && b == 3;
	} else if (ip == &bpf_fentry_test3) {
		char a, b;
		__u64 c;

		if (bpf_get_func_arg(ctx, 0, &value))
			return;
		a = (int) value;
		if (bpf_get_func_arg(ctx, 1, &value))
			return;
		b = (int) value;
		if (bpf_get_func_arg(ctx, 2, &value))
			return;
		c = value;

		*test_result += a == 4 && b == 5 && c == 6;
	} else if (ip == &bpf_fentry_test4) {
		void *a;
		char b;
		int c;
		__u64 d;

		if (bpf_get_func_arg(ctx, 0, &value))
			return;
		a = (void*) value;
		if (bpf_get_func_arg(ctx, 1, &value))
			return;
		b = (char) value;
		if (bpf_get_func_arg(ctx, 2, &value))
			return;
		c = (int) value;
		if (bpf_get_func_arg(ctx, 3, &value))
			return;
		d = value;

		*test_result += a == (void *) 7 && b == 8 && c == 9 && d == 10;
	} else if (ip == &bpf_fentry_test5) {
		__u64 a;
		void *b;
		short c;
		int d;
		__u64 e;

		if (bpf_get_func_arg(ctx, 0, &value))
			return;
		a = value;
		if (bpf_get_func_arg(ctx, 1, &value))
			return;
		b = (void*) value;
		if (bpf_get_func_arg(ctx, 2, &value))
			return;
		c = (short) value;
		if (bpf_get_func_arg(ctx, 3, &value))
			return;
		d = (int) value;
		if (bpf_get_func_arg(ctx, 4, &value))
			return;
		e = value;

		*test_result += a == 11 && b == (void *) 12 && c == 13 && d == 14 && e == 15;
	} else if (ip == &bpf_fentry_test6) {
		__u64 a;
		void *b;
		short c;
		int d;
		void *e;
		__u64 f;

		if (bpf_get_func_arg(ctx, 0, &value))
			return;
		a = value;
		if (bpf_get_func_arg(ctx, 1, &value))
			return;
		b = (void*) value;
		if (bpf_get_func_arg(ctx, 2, &value))
			return;
		c = (short) value;
		if (bpf_get_func_arg(ctx, 3, &value))
			return;
		d = (int) value;
		if (bpf_get_func_arg(ctx, 4, &value))
			return;
		e = (void*) value;;
		if (bpf_get_func_arg(ctx, 5, &value))
			return;
		f = value;;

		*test_result += a == 16 && b == (void *) 17 && c == 18 && d == 19 && e == (void *) 20 && f == 21;
	} else if (ip == &bpf_fentry_test7) {
		*test_result += 1;
	} else if (ip == &bpf_fentry_test8) {
		*test_result += 1;
	}
}
