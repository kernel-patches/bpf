// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

int pid;
__u64 fentry_a, fentry_b, fentry_c, fentry_nope, fentry_ret, fentry_alt, fentry_c32;
__u64 fexit_c, fexit_ret;
__u64 fmod_ret_c, fmod_ret_d, fmod_ret_f, fmod_ret_g, fmod_ret_ret;
long tp_nr;
__u64 tp_hits, tp_match, tp_mismatch, tp_variant;
__u64 lsm_inode, lsm_ret;

/* bpf_fentry_test3(char a, int b, u64 c): reordered, plus a missing one */
struct bpf_func_args___test3 {
	__u64 c;
	int b;
	char a;
	long nope;
	int __ret;
} __attribute__((preserve_access_index));

/* u64 c as a __u32: loads of unsigned integers are resized to the argument */
struct bpf_func_args___test3_u32 {
	__u32 c;
} __attribute__((preserve_access_index));

SEC("fentry/bpf_fentry_test3")
int fentry(struct bpf_func_args___test3 *ctx)
{
	if ((bpf_get_current_pid_tgid() >> 32) != pid)
		return 0;
	fentry_a = ctx->a;
	fentry_b = ctx->b;
	fentry_c = ctx->c;
	fentry_nope = bpf_core_field_exists(ctx->nope);
	/* the return value is not in the context of fentry */
	fentry_ret = bpf_core_field_exists(ctx->__ret);
	/*
	 * A field variant, as for an argument renamed on another kernel: the
	 * access to the missing one is poisoned. Clang turns the two loads of
	 * the same size into one, from ctx plus the offset each branch sets,
	 * which the verifier allows from Linux 7.1.
	 */
	if (bpf_core_field_exists(ctx->nope))
		fentry_alt = ctx->nope;
	else
		fentry_alt = ctx->c;
	fentry_c32 = ((struct bpf_func_args___test3_u32 *)ctx)->c;
	return 0;
}

/* a typedef'd anonymous struct, named after its typedef */
typedef struct {
	__u64 c;
	int __ret;
} __attribute__((preserve_access_index)) bpf_func_args___test3_t;

SEC("fexit/bpf_fentry_test3")
int fexit(bpf_func_args___test3_t *ctx)
{
	if ((bpf_get_current_pid_tgid() >> 32) != pid)
		return 0;
	fexit_c = ctx->c;
	fexit_ret = ctx->__ret;
	return 0;
}

/*
 * bpf_modify_return_test2(int a, int *b, short c, int d, void *e, char f,
 * int g). Unlike for bpf_modify_return_test(), other tests' fmod_ret programs
 * on it only return non-zero for their own process, which would skip this one.
 */
struct bpf_func_args___modify2 {
	int __ret;
	int g;
	char f;
	short c;
	/* int, as long as on a kernel where it would be wider */
	long d;
} __attribute__((preserve_access_index));

SEC("fmod_ret/bpf_modify_return_test2")
int fmod_ret(struct bpf_func_args___modify2 *ctx)
{
	if ((bpf_get_current_pid_tgid() >> 32) != pid)
		return 0;
	fmod_ret_c = ctx->c;
	/* a plain load of a signed integer of another size would be poisoned */
	fmod_ret_d = BPF_CORE_READ_BITFIELD(ctx, d);
	fmod_ret_f = ctx->f;
	fmod_ret_g = ctx->g;
	fmod_ret_ret = bpf_core_field_exists(ctx->__ret);
	return 0;
}

/* sys_enter(struct pt_regs *regs, long id), without void *__data */
struct bpf_func_args___sys_enter {
	long id;
	struct pt_regs *regs;
} __attribute__((preserve_access_index));

/*
 * Flavors with just the argument whose type is checked, as for an argument
 * pointing to another type on another kernel. bpf_core_type_matches() also
 * compares the names of integer types, and clang's "long" is "long int" in
 * kernel BTF, so only check pointers here.
 * The flavor starts with and contains triple underscores, which only
 * matches as the candidate is named after the struct.
 */
struct bpf_func_args____sys_enter___good {
	struct pt_regs *regs;
} __attribute__((preserve_access_index));

struct bpf_func_args___sys_enter_bad {
	struct file *regs;
} __attribute__((preserve_access_index));

/* a struct variant, as for another kernel where the argument is renamed */
struct bpf_func_args___sys_enter_old {
	struct pt_regs *uregs;
} __attribute__((preserve_access_index));

SEC("tp_btf/sys_enter")
int tp_btf(struct bpf_func_args___sys_enter *ctx)
{
	struct pt_regs *regs;

	if ((bpf_get_current_pid_tgid() >> 32) != pid)
		return 0;
	/* other syscalls of this process trigger it too */
	if (ctx->id == tp_nr)
		tp_hits++;
	tp_match = bpf_core_type_matches(struct bpf_func_args____sys_enter___good);
	tp_mismatch = bpf_core_type_matches(struct bpf_func_args___sys_enter_bad);
	/* a struct variant: the access through the one not matching is poisoned */
	if (bpf_core_type_matches(struct bpf_func_args____sys_enter___good))
		regs = ((struct bpf_func_args____sys_enter___good *)ctx)->regs;
	else
		regs = ((struct bpf_func_args___sys_enter_old *)ctx)->uregs;
	tp_variant = regs && regs == ctx->regs;
	return 0;
}

/* file_open(struct file *file) */
struct bpf_func_args___file_open {
	struct file *file;
	int __ret;
} __attribute__((preserve_access_index));

SEC("lsm/file_open")
int lsm(struct bpf_func_args___file_open *ctx)
{
	if ((bpf_get_current_pid_tgid() >> 32) != pid)
		return 0;
	lsm_inode = !!ctx->file->f_inode;
	lsm_ret = ctx->__ret + 1;
	return 0;
}

/* an unguarded access to a missing argument fails to load */
SEC("?fentry/bpf_fentry_test3")
int missing(struct bpf_func_args___test3 *ctx)
{
	fentry_nope = ctx->nope;
	return 0;
}

/* a missing attach target fails the load of the program, not the prepare */
SEC("?fentry/bpf_fentry_test_nonexistent")
int no_target(struct bpf_func_args___test3 *ctx)
{
	if (bpf_core_field_exists(ctx->a))
		fentry_a = ctx->a;
	return 0;
}
