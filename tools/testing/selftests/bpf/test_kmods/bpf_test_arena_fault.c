// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/module.h>

static u64 *stashed_ptr;

__bpf_kfunc_start_defs();

__bpf_kfunc void bpf_test_arena_fault_stash(u64 *ptr__arena)
{
	WRITE_ONCE(stashed_ptr, ptr__arena);
}

__bpf_kfunc u64 bpf_test_arena_fault_load_stashed(void)
{
	u64 *ptr = READ_ONCE(stashed_ptr);

	return ptr ? READ_ONCE(*ptr) : U64_MAX;
}

__bpf_kfunc void bpf_test_arena_fault_clear_stashed(void)
{
	WRITE_ONCE(stashed_ptr, NULL);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_test_arena_fault_kfunc_ids)
BTF_ID_FLAGS(func, bpf_test_arena_fault_stash)
BTF_ID_FLAGS(func, bpf_test_arena_fault_load_stashed)
BTF_ID_FLAGS(func, bpf_test_arena_fault_clear_stashed)
BTF_KFUNCS_END(bpf_test_arena_fault_kfunc_ids)

static const struct btf_kfunc_id_set bpf_test_arena_fault_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_test_arena_fault_kfunc_ids,
};

static int __init bpf_test_arena_fault_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,
					 &bpf_test_arena_fault_kfunc_set);
}

static void __exit bpf_test_arena_fault_exit(void)
{
}

module_init(bpf_test_arena_fault_init);
module_exit(bpf_test_arena_fault_exit);

MODULE_DESCRIPTION("BPF arena fault selftest module");
MODULE_LICENSE("GPL");
