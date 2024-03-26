// SPDX-License-Identifier: GPL-2.0
/*
 * LED BPF Trigger
 *
 * Author: Daniel Hodges <hodges.daniel.scott@gmail.com>
 */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/leds.h>
#include <linux/module.h>
#include <linux/rcupdate.h>


DEFINE_LED_TRIGGER(ledtrig_bpf);

__bpf_kfunc_start_defs();
__bpf_kfunc void bpf_ledtrig_blink(const char *led_name__str, unsigned long
		delay_on, unsigned long delay_off, int invert)
{
	struct led_classdev *led_cdev;

	rcu_read_lock();
	list_for_each_entry_rcu(led_cdev, &ledtrig_bpf->led_cdevs, trig_list) {
		if (strcmp(led_name__str, led_cdev->name) == 0) {
			led_blink_set_oneshot(led_cdev, &delay_on, &delay_off,
					invert);
			break;
		}
	}
	rcu_read_unlock();
}
__bpf_kfunc_end_defs();

BTF_KFUNCS_START(ledtrig_bpf_kfunc_ids)
BTF_ID_FLAGS(func, bpf_ledtrig_blink, KF_TRUSTED_ARGS)
BTF_KFUNCS_END(ledtrig_bpf_kfunc_ids)

static const struct btf_kfunc_id_set ledtrig_bpf_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &ledtrig_bpf_kfunc_ids,
};

static int init_bpf(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,
			&ledtrig_bpf_kfunc_set);
	return ret;
}

static int __init ledtrig_bpf_init(void)
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
