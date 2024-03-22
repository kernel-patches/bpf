// SPDX-License-Identifier: GPL-2.0
/*
 * LED BPF Trigger
 *
 * Author: Daniel Hodges <hodges.daniel.scott@gmail.com>
 */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/leds.h>


DEFINE_LED_TRIGGER(ledtrig_bpf);

__bpf_hook_start()

__bpf_kfunc void bpf_ledtrig_blink(unsigned long delay_on, unsigned long delay_off, int invert)
{
	led_trigger_blink_oneshot(ledtrig_bpf, delay_on, delay_off, invert);
}
__bpf_hook_end();

BTF_SET8_START(ledtrig_bpf_kfunc_ids)
BTF_ID_FLAGS(func, bpf_ledtrig_blink)
BTF_SET8_END(ledtrig_bpf_kfunc_ids)

static const struct btf_kfunc_id_set ledtrig_bpf_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &ledtrig_bpf_kfunc_ids,
};

static int init_bpf(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,
			&ledtrig_bpf_kfunc_set);
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING,
			&ledtrig_bpf_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
			&ledtrig_bpf_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SK_SKB,
			&ledtrig_bpf_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
			&ledtrig_bpf_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_ACT,
			&ledtrig_bpf_kfunc_set);
	return ret;
}

static int ledtrig_bpf_init(void)
{
	led_trigger_register_simple("bpf", &ledtrig_bpf);

	return init_bpf();
}

static void __exit ledtrig_bpf_exit(void)
{
	led_trigger_unregister_simple(ledtrig_bpf);
}

module_init(ledtrig_bpf_init);
module_exit(ledtrig_bpf_exit);

MODULE_AUTHOR("Daniel Hodges <hodges.daniel.scott@gmail.com>");
MODULE_DESCRIPTION("BPF LED trigger");
MODULE_LICENSE("GPL v2");
