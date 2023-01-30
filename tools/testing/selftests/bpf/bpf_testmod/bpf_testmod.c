// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Facebook */
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/error-injection.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/percpu-defs.h>
#include <linux/sysfs.h>
#include <linux/tracepoint.h>
#include "bpf_testmod.h"
#define __ksym
#include "bpf_testmod_kfunc.h"

#define CREATE_TRACE_POINTS
#include "bpf_testmod-events.h"

typedef int (*func_proto_typedef)(long);
typedef int (*func_proto_typedef_nested1)(func_proto_typedef);
typedef int (*func_proto_typedef_nested2)(func_proto_typedef_nested1);

DEFINE_PER_CPU(int, bpf_testmod_ksym_percpu) = 123;
long bpf_testmod_test_struct_arg_result;

struct bpf_testmod_struct_arg_1 {
	int a;
};
struct bpf_testmod_struct_arg_2 {
	long a;
	long b;
};

noinline int
bpf_testmod_test_struct_arg_1(struct bpf_testmod_struct_arg_2 a, int b, int c) {
	bpf_testmod_test_struct_arg_result = a.a + a.b  + b + c;
	return bpf_testmod_test_struct_arg_result;
}

noinline int
bpf_testmod_test_struct_arg_2(int a, struct bpf_testmod_struct_arg_2 b, int c) {
	bpf_testmod_test_struct_arg_result = a + b.a + b.b + c;
	return bpf_testmod_test_struct_arg_result;
}

noinline int
bpf_testmod_test_struct_arg_3(int a, int b, struct bpf_testmod_struct_arg_2 c) {
	bpf_testmod_test_struct_arg_result = a + b + c.a + c.b;
	return bpf_testmod_test_struct_arg_result;
}

noinline int
bpf_testmod_test_struct_arg_4(struct bpf_testmod_struct_arg_1 a, int b,
			      int c, int d, struct bpf_testmod_struct_arg_2 e) {
	bpf_testmod_test_struct_arg_result = a.a + b + c + d + e.a + e.b;
	return bpf_testmod_test_struct_arg_result;
}

noinline int
bpf_testmod_test_struct_arg_5(void) {
	bpf_testmod_test_struct_arg_result = 1;
	return bpf_testmod_test_struct_arg_result;
}

noinline void
bpf_testmod_test_mod_kfunc(int i)
{
	*(int *)this_cpu_ptr(&bpf_testmod_ksym_percpu) = i;
}

struct bpf_testmod_btf_type_tag_1 {
	int a;
};

struct bpf_testmod_btf_type_tag_2 {
	struct bpf_testmod_btf_type_tag_1 __user *p;
};

struct bpf_testmod_btf_type_tag_3 {
	struct bpf_testmod_btf_type_tag_1 __percpu *p;
};

noinline int
bpf_testmod_test_btf_type_tag_user_1(struct bpf_testmod_btf_type_tag_1 __user *arg) {
	BTF_TYPE_EMIT(func_proto_typedef);
	BTF_TYPE_EMIT(func_proto_typedef_nested1);
	BTF_TYPE_EMIT(func_proto_typedef_nested2);
	return arg->a;
}

noinline int
bpf_testmod_test_btf_type_tag_user_2(struct bpf_testmod_btf_type_tag_2 *arg) {
	return arg->p->a;
}

noinline int
bpf_testmod_test_btf_type_tag_percpu_1(struct bpf_testmod_btf_type_tag_1 __percpu *arg) {
	return arg->a;
}

noinline int
bpf_testmod_test_btf_type_tag_percpu_2(struct bpf_testmod_btf_type_tag_3 *arg) {
	return arg->p->a;
}

noinline int bpf_testmod_loop_test(int n)
{
	int i, sum = 0;

	/* the primary goal of this test is to test LBR. Create a lot of
	 * branches in the function, so we can catch it easily.
	 */
	for (i = 0; i < n; i++)
		sum += i;
	return sum;
}

__weak noinline struct file *bpf_testmod_return_ptr(int arg)
{
	static struct file f = {};

	switch (arg) {
	case 1: return (void *)EINVAL;		/* user addr */
	case 2: return (void *)0xcafe4a11;	/* user addr */
	case 3: return (void *)-EINVAL;		/* canonical, but invalid */
	case 4: return (void *)(1ull << 60);	/* non-canonical and invalid */
	case 5: return (void *)~(1ull << 30);	/* trigger extable */
	case 6: return &f;			/* valid addr */
	case 7: return (void *)((long)&f | 1);	/* kernel tricks */
	default: return NULL;
	}
}

noinline int bpf_testmod_fentry_test1(int a)
{
	return a + 1;
}

noinline int bpf_testmod_fentry_test2(int a, u64 b)
{
	return a + b;
}

noinline int bpf_testmod_fentry_test3(char a, int b, u64 c)
{
	return a + b + c;
}

int bpf_testmod_fentry_ok;

noinline ssize_t
bpf_testmod_test_read(struct file *file, struct kobject *kobj,
		      struct bin_attribute *bin_attr,
		      char *buf, loff_t off, size_t len)
{
	struct bpf_testmod_test_read_ctx ctx = {
		.buf = buf,
		.off = off,
		.len = len,
	};
	struct bpf_testmod_struct_arg_1 struct_arg1 = {10};
	struct bpf_testmod_struct_arg_2 struct_arg2 = {2, 3};
	int i = 1;

	while (bpf_testmod_return_ptr(i))
		i++;

	(void)bpf_testmod_test_struct_arg_1(struct_arg2, 1, 4);
	(void)bpf_testmod_test_struct_arg_2(1, struct_arg2, 4);
	(void)bpf_testmod_test_struct_arg_3(1, 4, struct_arg2);
	(void)bpf_testmod_test_struct_arg_4(struct_arg1, 1, 2, 3, struct_arg2);
	(void)bpf_testmod_test_struct_arg_5();

	/* This is always true. Use the check to make sure the compiler
	 * doesn't remove bpf_testmod_loop_test.
	 */
	if (bpf_testmod_loop_test(101) > 100)
		trace_bpf_testmod_test_read(current, &ctx);

	/* Magic number to enable writable tp */
	if (len == 64) {
		struct bpf_testmod_test_writable_ctx writable = {
			.val = 1024,
		};
		trace_bpf_testmod_test_writable_bare(&writable);
		if (writable.early_ret)
			return snprintf(buf, len, "%d\n", writable.val);
	}

	if (bpf_testmod_fentry_test1(1) != 2 ||
	    bpf_testmod_fentry_test2(2, 3) != 5 ||
	    bpf_testmod_fentry_test3(4, 5, 6) != 15)
		goto out;

	bpf_testmod_fentry_ok = 1;
out:
	return -EIO; /* always fail */
}
EXPORT_SYMBOL(bpf_testmod_test_read);
ALLOW_ERROR_INJECTION(bpf_testmod_test_read, ERRNO);

noinline ssize_t
bpf_testmod_test_write(struct file *file, struct kobject *kobj,
		      struct bin_attribute *bin_attr,
		      char *buf, loff_t off, size_t len)
{
	struct bpf_testmod_test_write_ctx ctx = {
		.buf = buf,
		.off = off,
		.len = len,
	};

	trace_bpf_testmod_test_write_bare(current, &ctx);

	return -EIO; /* always fail */
}
EXPORT_SYMBOL(bpf_testmod_test_write);
ALLOW_ERROR_INJECTION(bpf_testmod_test_write, ERRNO);

static struct bin_attribute bin_attr_bpf_testmod_file __ro_after_init = {
	.attr = { .name = "bpf_testmod", .mode = 0666, },
	.read = bpf_testmod_test_read,
	.write = bpf_testmod_test_write,
};

noinline u64 bpf_kfunc_call_test1(struct sock *sk, u32 a, u64 b, u32 c, u64 d)
{
	return a + b + c + d;
}

noinline int bpf_kfunc_call_test2(struct sock *sk, u32 a, u32 b)
{
	return a + b;
}

struct sock *noinline bpf_kfunc_call_test3(struct sock *sk)
{
	return sk;
}

noinline long bpf_kfunc_call_test4(signed char a, short b, int c, long d)
{
	/* Provoke the compiler to assume that the caller has sign-extended a,
	 * b and c on platforms where this is required (e.g. s390x).
	 */
	return (long)a + (long)b + (long)c + d;
}

static struct prog_test_ref_kfunc prog_test_struct = {
	.a = 42,
	.b = 108,
	.next = &prog_test_struct,
	.cnt = REFCOUNT_INIT(1),
};

noinline struct prog_test_ref_kfunc *
bpf_kfunc_call_test_acquire(unsigned long *scalar_ptr)
{
	refcount_inc(&prog_test_struct.cnt);
	return &prog_test_struct;
}

noinline struct prog_test_member *
bpf_kfunc_call_memb_acquire(void)
{
	WARN_ON_ONCE(1);
	return NULL;
}

noinline void bpf_kfunc_call_test_release(struct prog_test_ref_kfunc *p)
{
	if (!p)
		return;

	refcount_dec(&p->cnt);
}

noinline void bpf_kfunc_call_memb_release(struct prog_test_member *p)
{
}

noinline void bpf_kfunc_call_memb1_release(struct prog_test_member1 *p)
{
	WARN_ON_ONCE(1);
}

static int *__bpf_kfunc_call_test_get_mem(struct prog_test_ref_kfunc *p, const int size)
{
	if (size > 2 * sizeof(int))
		return NULL;

	return (int *)p;
}

noinline int *bpf_kfunc_call_test_get_rdwr_mem(struct prog_test_ref_kfunc *p, const int rdwr_buf_size)
{
	return __bpf_kfunc_call_test_get_mem(p, rdwr_buf_size);
}

noinline int *bpf_kfunc_call_test_get_rdonly_mem(struct prog_test_ref_kfunc *p, const int rdonly_buf_size)
{
	return __bpf_kfunc_call_test_get_mem(p, rdonly_buf_size);
}

/* the next 2 ones can't be really used for testing expect to ensure
 * that the verifier rejects the call.
 * Acquire functions must return struct pointers, so these ones are
 * failing.
 */
noinline int *bpf_kfunc_call_test_acq_rdonly_mem(struct prog_test_ref_kfunc *p, const int rdonly_buf_size)
{
	return __bpf_kfunc_call_test_get_mem(p, rdonly_buf_size);
}

noinline void bpf_kfunc_call_int_mem_release(int *p)
{
}

noinline struct prog_test_ref_kfunc *
bpf_kfunc_call_test_kptr_get(struct prog_test_ref_kfunc **pp, int a, int b)
{
	struct prog_test_ref_kfunc *p = READ_ONCE(*pp);

	if (!p)
		return NULL;
	refcount_inc(&p->cnt);
	return p;
}

noinline void bpf_kfunc_call_test_pass_ctx(struct __sk_buff *skb)
{
}

noinline void bpf_kfunc_call_test_pass1(struct prog_test_pass1 *p)
{
}

noinline void bpf_kfunc_call_test_pass2(struct prog_test_pass2 *p)
{
}

noinline void bpf_kfunc_call_test_fail1(struct prog_test_fail1 *p)
{
}

noinline void bpf_kfunc_call_test_fail2(struct prog_test_fail2 *p)
{
}

noinline void bpf_kfunc_call_test_fail3(struct prog_test_fail3 *p)
{
}

noinline void bpf_kfunc_call_test_mem_len_pass1(void *mem, int mem__sz)
{
}

noinline void bpf_kfunc_call_test_mem_len_fail1(void *mem, int len)
{
}

noinline void bpf_kfunc_call_test_mem_len_fail2(u64 *mem, int len)
{
}

noinline void bpf_kfunc_call_test_ref(struct prog_test_ref_kfunc *p)
{
}

noinline void bpf_kfunc_call_test_destructive(void)
{
}

BTF_SET8_START(bpf_testmod_check_kfunc_ids)
BTF_ID_FLAGS(func, bpf_kfunc_call_test1)
BTF_ID_FLAGS(func, bpf_kfunc_call_test2)
BTF_ID_FLAGS(func, bpf_kfunc_call_test3)
BTF_ID_FLAGS(func, bpf_kfunc_call_test4)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_acquire, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_kfunc_call_memb_acquire, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_kfunc_call_memb_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_kfunc_call_memb1_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_get_rdwr_mem, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_get_rdonly_mem, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_acq_rdonly_mem, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_kfunc_call_int_mem_release, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_kptr_get, KF_ACQUIRE | KF_RET_NULL | KF_KPTR_GET)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_pass_ctx)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_pass1)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_pass2)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_fail1)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_fail2)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_fail3)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_mem_len_pass1)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_mem_len_fail1)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_mem_len_fail2)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_ref, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_kfunc_call_test_destructive, KF_DESTRUCTIVE)
BTF_ID_FLAGS(func, bpf_testmod_test_mod_kfunc)
BTF_SET8_END(bpf_testmod_check_kfunc_ids)

static const struct btf_kfunc_id_set bpf_testmod_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_testmod_check_kfunc_ids,
};

BTF_ID_LIST(bpf_prog_test_dtor_kfunc_ids)
BTF_ID(struct, prog_test_ref_kfunc)
BTF_ID(func, bpf_kfunc_call_test_release)
BTF_ID(struct, prog_test_member)
BTF_ID(func, bpf_kfunc_call_memb_release)

extern int bpf_fentry_test1(int a);

static int __init bpf_testmod_init(void)
{
	const struct btf_id_dtor_kfunc bpf_prog_test_dtor_kfunc[] = {
		{
		  .btf_id       = bpf_prog_test_dtor_kfunc_ids[0],
		  .kfunc_btf_id = bpf_prog_test_dtor_kfunc_ids[1]
		},
		{
		  .btf_id	= bpf_prog_test_dtor_kfunc_ids[2],
		  .kfunc_btf_id = bpf_prog_test_dtor_kfunc_ids[3],
		},
	};
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &bpf_testmod_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &bpf_testmod_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &bpf_testmod_kfunc_set);
	ret = ret ?: register_btf_id_dtor_kfuncs(bpf_prog_test_dtor_kfunc,
						  ARRAY_SIZE(bpf_prog_test_dtor_kfunc),
						  THIS_MODULE);
	if (ret < 0)
		return ret;
	if (bpf_fentry_test1(0) < 0)
		return -EINVAL;
	return sysfs_create_bin_file(kernel_kobj, &bin_attr_bpf_testmod_file);
}

static void bpf_testmod_exit(void)
{
	return sysfs_remove_bin_file(kernel_kobj, &bin_attr_bpf_testmod_file);
}

module_init(bpf_testmod_init);
module_exit(bpf_testmod_exit);

MODULE_AUTHOR("Andrii Nakryiko");
MODULE_DESCRIPTION("BPF selftests module");
MODULE_LICENSE("Dual BSD/GPL");
