// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../test_kmods/bpf_testmod.h"

char _license[] SEC("license") = "GPL";

/* int bpf_fentry_test3(char a, int b, u64 c), called as (4, 5, 6) */
struct fentry_test3_args {
#ifndef __clang__
	/* GCC doesn't support BTF decl tags on types, see __bpf_func_args;
	 * with clang, this struct relies on the struct-level tag only
	 */
	__bpf_func_args_marker;
#endif
	/* deliberately in a different order to the target */
	__u64 c;
	int b;
	char a;
	/* no such parameter */
	long missing;
	/* flavor of a parameter that doesn't exist */
	long missing___v2;
	/* parameter exists, but the type isn't compatible */
	struct task_struct *a___bad_type;
	/* flavor of an existing parameter */
	int b___alias;
	int ret __bpf_func_ret;
} __bpf_func_args;

__u64 t3_a, t3_b, t3_c, t3_b_alias, t3_ret;
int t3_missing_exists = -1, t3_bad_type_exists = -1, t3_missing_flavor_exists = -1;
int t3_supported = -1, t3_untagged_supported = -1;

/* without the bpf_func_args tag, as for libbpf or kernel versions without
 * support for function argument relocations; no kernel type has this name
 */
struct func_args_core_untagged {
	int a;
} __attribute__((preserve_access_index));
int t3_fentry_ret_exists = -1, t3_ret_exists = -1;

SEC("fentry/bpf_fentry_test3")
int fentry3(struct fentry_test3_args *args)
{
	struct func_args_core_untagged *untagged = (void *)args;

	t3_supported = bpf_func_args_supported(args);
	t3_untagged_supported = bpf_func_args_supported(untagged);
	t3_a = args->a;
	t3_b = args->b;
	t3_c = args->c;
	t3_b_alias = args->b___alias;
	t3_missing_exists = bpf_core_field_exists(args->missing);
	t3_bad_type_exists = bpf_core_field_exists(args->a___bad_type);
	t3_missing_flavor_exists = bpf_core_field_exists(args->missing___v2);
	/* the return value isn't available on entry */
	t3_fentry_ret_exists = bpf_core_field_exists(args->ret);
	return 0;
}

SEC("fexit/bpf_fentry_test3")
int fexit3(struct fentry_test3_args *args)
{
	t3_ret_exists = bpf_core_field_exists(args->ret);
	t3_ret = args->ret;
	return 0;
}

/* typedef'd anonymous struct, for which relocations have the typedef rather
 * than the (tagged) struct as their root type
 */
typedef struct {
	__bpf_func_args_marker;
	__u64 c;
	long missing;
} __bpf_func_args fentry_test3_td_args_t;

__u64 td_c;
int td_missing_exists = -1;

SEC("fentry/bpf_fentry_test3")
int fentry3_typedef(fentry_test3_td_args_t *args)
{
	td_c = args->c;
	td_missing_exists = bpf_core_field_exists(args->missing);
	return 0;
}

/* int bpf_modify_return_test(int a, int *b), called as (1, &b) */
struct modify_return_args {
	__bpf_func_args_marker;
	int *b;
	int a;
	long missing;
	int ret __bpf_func_ret;
} __bpf_func_args;

int fm_a, fm_calls, fm_ret = -1, fm_ret_exists = -1, fm_missing_exists = -1;
bool fm_b_set;

SEC("fmod_ret/bpf_modify_return_test")
int fmod_ret_test(struct modify_return_args *args)
{
	fm_calls++;
	fm_a = args->a;
	fm_b_set = args->b != NULL;
	fm_ret = args->ret;
	fm_ret_exists = bpf_core_field_exists(args->ret);
	fm_missing_exists = bpf_core_field_exists(args->missing);
	/* don't override the return value */
	return 0;
}

/* fsession on bpf_fentry_test3(char a, int b, u64 c), called as (4, 5, 6) */
__u64 fs_entry_c, fs_exit_c;
int fs_entry_ret = -1, fs_exit_ret = -1, fs_ret_exists = -1;
int fs_entry_calls, fs_exit_calls;

SEC("fsession/bpf_fentry_test3")
int BPF_PROG_CORE(fsession3, __u64, c, __bpf_func_ret int, ret)
{
	fs_ret_exists = bpf_func_arg_exists(ret);
	if (!bpf_session_is_return(ctx)) {
		fs_entry_calls++;
		fs_entry_c = c;
		fs_entry_ret = ret;
	} else {
		fs_exit_calls++;
		fs_exit_c = c;
		fs_exit_ret = ret;
	}
	return 0;
}

/* int bpf_testmod_test_struct_arg_1(struct bpf_testmod_struct_arg_2 a,
 *				     int b, int c), called as ({2, 3}, 1, 4);
 * 'a' is passed by value and occupies two context slots.
 */
struct bpf_testmod_struct_arg_2 {
	long a;
	long b;
};

struct struct_arg_1_args {
	__bpf_func_args_marker;
	int c;
	int b;
	struct bpf_testmod_struct_arg_2 a;
	int ret __bpf_func_ret;
} __bpf_func_args;

long s1_a_a, s1_a_b, s1_b, s1_c, s1_ret;

SEC("fexit/bpf_testmod_test_struct_arg_1")
int fexit_struct_arg(struct struct_arg_1_args *args)
{
	s1_a_a = args->a.a;
	s1_a_b = args->a.b;
	s1_b = args->b;
	s1_c = args->c;
	s1_ret = args->ret;
	return 0;
}

/* TP_PROTO(struct task_struct *task, struct bpf_testmod_test_read_ctx *ctx) */
struct task_struct___fwd;

struct test_read_args {
	__bpf_func_args_marker;
	struct bpf_testmod_test_read_ctx *ctx;
	struct task_struct *task;
	/* pointer to a different type than the parameter's: no match */
	struct file *task___bad_ptr;
	/* forward-declared pointee with the same essential name: match */
	struct task_struct___fwd *task___fwd;
	/* void pointers match any pointer */
	void *ctx___void;
} __bpf_func_args;

int tp_pid, tp_len;
int tp_bad_ptr_exists = -1, tp_fwd_exists = -1, tp_void_exists = -1, tp_void_same = -1;

SEC("tp_btf/bpf_testmod_test_read")
int tp_read(struct test_read_args *args)
{
	tp_pid = args->task->pid;
	tp_len = args->ctx->len;
	tp_bad_ptr_exists = bpf_core_field_exists(args->task___bad_ptr);
	tp_fwd_exists = bpf_core_field_exists(args->task___fwd);
	tp_void_exists = bpf_core_field_exists(args->ctx___void);
	tp_void_same = args->ctx___void == (void *)args->ctx;
	return 0;
}

/* BPF_PROG_CORE() versions, with the arguments struct declared implicitly */
__u64 m3_a, m3_b, m3_c, m3_missing = -1, m3_ret;
int m3_missing_exists = -1, m3_ret_exists = -1, m3_supported = -1;

SEC("fexit/bpf_fentry_test3")
int BPF_PROG_CORE(fexit3_macro, __u64, c, int, b, char, a, long, missing,
		  __bpf_func_ret int, ret)
{
	m3_supported = bpf_func_args_supported(ctx);
	m3_a = a;
	m3_b = b;
	m3_c = c;
	m3_missing = missing;
	m3_missing_exists = bpf_func_arg_exists(missing);
	m3_ret = ret;
	m3_ret_exists = bpf_func_arg_exists(ret);
	return 0;
}

__u64 mf_b, mf_ret = -1, mf_a = -1;
int mf_ret_exists = -1, mf_a_exists = -1;

SEC("fentry/bpf_fentry_test3")
int BPF_PROG_CORE(fentry3_macro, int, b, __bpf_func_ret int, ret,
		  struct task_struct *, a)
{
	mf_b = b;
	/* 'a' is a char, so a pointer isn't compatible: it reads as zero */
	mf_a = (__u64)a;
	mf_a_exists = bpf_func_arg_exists(a);
	/* no return value on entry, so it reads as zero */
	mf_ret = ret;
	mf_ret_exists = bpf_func_arg_exists(ret);
	return 0;
}

int mtp_pid;

SEC("tp_btf/bpf_testmod_test_read")
int BPF_PROG_CORE(tp_read_macro, struct task_struct *, task)
{
	mtp_pid = task->pid;
	return 0;
}
