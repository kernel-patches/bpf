// SPDX-License-Identifier: GPL-2.0
#include <linux/btf.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/btf_ids.h>
#include <linux/percpu-defs.h>
#include <linux/error-injection.h>

extern int bpf_fentry_test1(int a);

DEFINE_PER_CPU(int, bpf_mod_kfunc_race_ksym) = 123;

noinline void bpf_mod_kfunc_race_test(void)
{
}

BTF_SET_START(bpf_mod_kfunc_race_check_ids)
BTF_ID(func, bpf_mod_kfunc_race_test)
BTF_SET_END(bpf_mod_kfunc_race_check_ids)

static const struct btf_kfunc_id_set bpf_mod_kfunc_race_kfunc_set = {
	.owner     = THIS_MODULE,
	.check_set = &bpf_mod_kfunc_race_check_ids,
};

static int bpf_mod_kfunc_race_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BTF_KFUNC_HOOK_TC, &bpf_mod_kfunc_race_kfunc_set);
	if (ret < 0)
		return ret;
	/* fentry program will attach to this, and block us */
	if (bpf_fentry_test1(0) < 0) /* also allow fmod_ret to fail module init */
		return -EINVAL;
	return 0;
}

static void bpf_mod_kfunc_race_exit(void)
{
}

module_init(bpf_mod_kfunc_race_init);
module_exit(bpf_mod_kfunc_race_exit);

MODULE_AUTHOR("Kumar Kartikeya Dwivedi <memxor@gmail.com>");
MODULE_DESCRIPTION("BPF selftests module to test race condition");
MODULE_LICENSE("Dual BSD/GPL");
