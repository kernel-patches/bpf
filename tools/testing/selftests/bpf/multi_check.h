/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __MULTI_CHECK_H
#define __MULTI_CHECK_H

extern unsigned long long bpf_fentry_test[8];

#define MULTI_ARG_CHECK(_name) \
static __attribute__((unused)) inline \
void _name ## _multi_arg_check(unsigned long ip, __u64 a, __u64 b, __u64 c, __u64 d, __u64 e, __u64 f, __u64 *test_result)						\
{																					\
	if (ip == bpf_fentry_test[0]) {																	\
		*test_result +=	(int) a == 1;																\
	} else if (ip == bpf_fentry_test[1]) {																\
		*test_result +=	(int) a == 2 && (__u64) b == 3;														\
	} else if (ip == bpf_fentry_test[2]) {																\
		*test_result +=	(char) a == 4 && (int) b == 5 && (__u64) c == 6;											\
	} else if (ip == bpf_fentry_test[3]) {																\
		*test_result +=	(void *) a == (void *) 7 && (char) b == 8 && (int) c == 9 && (__u64) d == 10;								\
	} else if (ip == bpf_fentry_test[4]) {																\
		*test_result +=	(__u64) a == 11 && (void *) b == (void *) 12 && (short) c == 13 && (int) d == 14 && (__u64) e == 15;					\
	} else if (ip == bpf_fentry_test[5]) {																\
		*test_result +=	(__u64) a == 16 && (void *) b == (void *) 17 && (short) c == 18 && (int) d == 19 && (void *) e == (void *) 20 && (__u64) f == 21;	\
	} else if (ip == bpf_fentry_test[6]) {																\
		*test_result += 1;																	\
	} else if (ip == bpf_fentry_test[7]) {																\
		*test_result += 1;																	\
	}																				\
}

static __attribute__((unused)) inline
void multi_ret_check(unsigned long ip, int ret, __u64 *test_result)
{
	if (ip == bpf_fentry_test[0]) {
		*test_result += ret == 2;
	} else if (ip == bpf_fentry_test[1]) {
		*test_result += ret == 5;
	} else if (ip == bpf_fentry_test[2]) {
		*test_result += ret == 15;
	} else if (ip == bpf_fentry_test[3]) {
		*test_result += ret == 34;
	} else if (ip == bpf_fentry_test[4]) {
		*test_result += ret == 65;
	} else if (ip == bpf_fentry_test[5]) {
		*test_result += ret == 111;
	} else if (ip == bpf_fentry_test[6]) {
		*test_result += ret == 0;
	} else if (ip == bpf_fentry_test[7]) {
		*test_result += ret == 0;
	}
}

#endif /* __MULTI_CHECK_H */
