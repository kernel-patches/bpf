// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/init.h>
#include <linux/module.h>
#include <linux/bpf_preload.h>
#include "iterators/iterators.lskel.h"

late_initcall(load_skel);
module_exit(free_objs_and_skel);
MODULE_LICENSE("GPL");
