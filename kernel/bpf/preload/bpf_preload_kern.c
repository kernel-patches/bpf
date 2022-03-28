// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/init.h>
#include <linux/module.h>
#include <linux/bpf_preload.h>
#include "iterators/iterators.lskel.h"

static void free_links_and_skel(void)
{
	if (!IS_ERR_OR_NULL(dump_bpf_map_link))
		bpf_link_put(dump_bpf_map_link);
	if (!IS_ERR_OR_NULL(dump_bpf_prog_link))
		bpf_link_put(dump_bpf_prog_link);
	iterators_bpf__destroy(skel);
}

static int preload(struct dentry *parent)
{
	int err;

	bpf_link_inc(dump_bpf_map_link);
	bpf_link_inc(dump_bpf_prog_link);

	err = bpf_obj_do_pin_kernel(parent, "maps.debug", dump_bpf_map_link,
				    BPF_TYPE_LINK);
	if (err)
		goto undo;

	err = bpf_obj_do_pin_kernel(parent, "progs.debug", dump_bpf_prog_link,
				    BPF_TYPE_LINK);
	if (err)
		goto undo;

	return 0;
undo:
	bpf_link_put(dump_bpf_map_link);
	bpf_link_put(dump_bpf_prog_link);
	return err;
}

static struct bpf_preload_ops ops = {
	.preload = preload,
	.owner = THIS_MODULE,
};

static int load_skel(void)
{
	int err;

	skel = iterators_bpf__open();
	if (!skel)
		return -ENOMEM;
	err = iterators_bpf__load(skel);
	if (err)
		goto out;
	err = iterators_bpf__attach(skel);
	if (err)
		goto out;
	dump_bpf_map_link = bpf_link_get_from_fd(skel->links.dump_bpf_map_fd);
	if (IS_ERR(dump_bpf_map_link)) {
		err = PTR_ERR(dump_bpf_map_link);
		goto out;
	}
	dump_bpf_prog_link = bpf_link_get_from_fd(skel->links.dump_bpf_prog_fd);
	if (IS_ERR(dump_bpf_prog_link)) {
		err = PTR_ERR(dump_bpf_prog_link);
		goto out;
	}
	/* Avoid taking over stdin/stdout/stderr of init process. Zeroing out
	 * makes skel_closenz() a no-op later in iterators_bpf__destroy().
	 */
	close_fd(skel->links.dump_bpf_map_fd);
	skel->links.dump_bpf_map_fd = 0;
	close_fd(skel->links.dump_bpf_prog_fd);
	skel->links.dump_bpf_prog_fd = 0;
	return 0;
out:
	free_links_and_skel();
	return err;
}

static int __init load(void)
{
	int err;

	err = load_skel();
	if (err)
		return err;
	bpf_preload_ops = &ops;
	return err;
}

static void __exit fini(void)
{
	bpf_preload_ops = NULL;
	free_links_and_skel();
}
late_initcall(load);
module_exit(fini);
MODULE_LICENSE("GPL");
