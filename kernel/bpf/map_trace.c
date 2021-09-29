// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2021 Google */

#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/rcupdate.h>

struct bpf_map_trace_target_info {
	struct list_head list;
	const struct bpf_map_trace_reg *reg_info;
	u32 btf_id;
};

static struct list_head targets = LIST_HEAD_INIT(targets);
static DEFINE_MUTEX(targets_mutex);

struct bpf_map_trace_link {
	struct bpf_link link;
	struct bpf_map *map;
	struct bpf_map_trace_target_info *tinfo;
};

static DEFINE_MUTEX(link_mutex);

int bpf_map_trace_reg_target(const struct bpf_map_trace_reg *reg_info)
{
	struct bpf_map_trace_target_info *tinfo;

	tinfo = kmalloc(sizeof(*tinfo), GFP_KERNEL);
	if (!tinfo)
		return -ENOMEM;

	INIT_LIST_HEAD(&tinfo->list);
	tinfo->reg_info = reg_info;
	tinfo->btf_id = 0;

	mutex_lock(&targets_mutex);
	list_add(&tinfo->list, &targets);
	mutex_unlock(&targets_mutex);

	return 0;
}

bool bpf_map_trace_prog_supported(struct bpf_prog *prog)
{
	const char *attach_fname = prog->aux->attach_func_name;
	u32 prog_btf_id = prog->aux->attach_btf_id;
	struct bpf_map_trace_target_info *tinfo;
	bool supported = false;

	mutex_lock(&targets_mutex);
	list_for_each_entry(tinfo, &targets, list) {
		if (tinfo->btf_id && tinfo->btf_id == prog_btf_id) {
			supported = true;
			break;
		}
		if (!strcmp(attach_fname, tinfo->reg_info->target)) {
			tinfo->btf_id = prog->aux->attach_btf_id;
			supported = true;
			break;
		}
	}
	mutex_unlock(&targets_mutex);

	return supported;
}

int bpf_map_initialize_trace_progs(struct bpf_map *map)
{
	struct bpf_map_trace_progs *new_trace_progs;
	int i;

	if (!READ_ONCE(map->trace_progs)) {
		new_trace_progs = kzalloc(sizeof(struct bpf_map_trace_progs),
					  GFP_KERNEL);
		if (!new_trace_progs)
			return -ENOMEM;
		mutex_init(&new_trace_progs->mutex);
		for (i = 0; i < MAX_BPF_MAP_TRACE_TYPE; i++)
			INIT_LIST_HEAD(&new_trace_progs->progs[i].list);
		if (cmpxchg(&map->trace_progs, NULL, new_trace_progs))
			kfree(new_trace_progs);
	}

	return 0;
}

static void bpf_map_trace_link_release(struct bpf_link *link)
{
	struct bpf_map_trace_link *map_trace_link =
			container_of(link, struct bpf_map_trace_link, link);
	enum bpf_map_trace_type trace_type =
			map_trace_link->tinfo->reg_info->trace_type;
	struct bpf_map_trace_prog *cur_prog;
	struct bpf_map_trace_progs *progs;

	progs = map_trace_link->map->trace_progs;
	mutex_lock(&progs->mutex);
	list_for_each_entry(cur_prog, &progs->progs[trace_type].list, list) {
		if (cur_prog->prog == link->prog) {
			progs->length[trace_type] -= 1;
			list_del_rcu(&cur_prog->list);
			kfree_rcu(cur_prog, rcu);
		}
	}
	mutex_unlock(&progs->mutex);
	bpf_map_put_with_uref(map_trace_link->map);
}

static void bpf_map_trace_link_dealloc(struct bpf_link *link)
{
	struct bpf_map_trace_link *map_trace_link =
			container_of(link, struct bpf_map_trace_link, link);

	kfree(map_trace_link);
}

static int bpf_map_trace_link_replace(struct bpf_link *link,
				      struct bpf_prog *new_prog,
				      struct bpf_prog *old_prog)
{
	int ret = 0;

	mutex_lock(&link_mutex);
	if (old_prog && link->prog != old_prog) {
		ret = -EPERM;
		goto out_unlock;
	}

	if (link->prog->type != new_prog->type ||
	    link->prog->expected_attach_type != new_prog->expected_attach_type ||
	    link->prog->aux->attach_btf_id != new_prog->aux->attach_btf_id) {
		ret = -EINVAL;
		goto out_unlock;
	}

	old_prog = xchg(&link->prog, new_prog);
	bpf_prog_put(old_prog);

out_unlock:
	mutex_unlock(&link_mutex);
	return ret;
}

static const struct bpf_link_ops bpf_map_trace_link_ops = {
	.release = bpf_map_trace_link_release,
	.dealloc = bpf_map_trace_link_dealloc,
	.update_prog = bpf_map_trace_link_replace,
};

int bpf_map_attach_trace(struct bpf_prog *prog,
			 struct bpf_map *map,
			 struct bpf_map_trace_link_info *linfo)
{
	u32 key_acc_size, value_acc_size, key_size, value_size;
	struct bpf_map_trace_progs *trace_progs;
	struct bpf_map_trace_prog *trace_prog;
	bool is_percpu = false;
	int err = -EINVAL;

	if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY)
		is_percpu = true;
	else if (map->map_type != BPF_MAP_TYPE_HASH &&
		 map->map_type != BPF_MAP_TYPE_LRU_HASH &&
		 map->map_type != BPF_MAP_TYPE_ARRAY)
		goto put_map;

	key_acc_size = prog->aux->max_rdonly_access;
	value_acc_size = prog->aux->max_rdwr_access;
	key_size = map->key_size;
	if (!is_percpu)
		value_size = map->value_size;
	else
		value_size = round_up(map->value_size, 8) * num_possible_cpus();

	if (key_acc_size > key_size || value_acc_size > value_size) {
		err = -EACCES;
		goto put_map;
	}

	trace_prog = kmalloc(sizeof(*trace_prog), GFP_KERNEL);
	if (!trace_prog) {
		err = -ENOMEM;
		goto put_map;
	}
	INIT_LIST_HEAD(&trace_prog->list);
	trace_prog->prog = prog;

	err = bpf_map_initialize_trace_progs(map);
	if (err)
		goto put_map;

	trace_progs = map->trace_progs;
	mutex_lock(&trace_progs->mutex);
	if (trace_progs->length[linfo->trace_type] >= BPF_MAP_TRACE_MAX_PROGS)
		err = -E2BIG;
	else {
		err = 0;
		trace_progs->length[linfo->trace_type] += 1;
		list_add_tail_rcu(&trace_prog->list,
				  &trace_progs->progs[linfo->trace_type].list);
	}
	mutex_unlock(&trace_progs->mutex);

	return err;

put_map:
	bpf_map_put_with_uref(map);
	return err;
}

int bpf_map_trace_link_attach(const union bpf_attr *attr, bpfptr_t uattr,
			      struct bpf_prog *prog)
{
	struct bpf_map_trace_target_info *tinfo;
	struct bpf_map_trace_link_info linfo;
	struct bpf_link_primer link_primer;
	struct bpf_map_trace_link *link;
	u32 prog_btf_id, linfo_len;
	bool existed = false;
	struct bpf_map *map;
	bpfptr_t ulinfo;
	int err;

	if (attr->link_create.target_fd || attr->link_create.flags)
		return -EINVAL;

	memset(&linfo, 0, sizeof(struct bpf_map_trace_link_info));

	ulinfo = make_bpfptr(attr->link_create.map_trace_info,
			     uattr.is_kernel);
	linfo_len = attr->link_create.iter_info_len;
	if (bpfptr_is_null(ulinfo) || !linfo_len)
		return -EINVAL;

	err = bpf_check_uarg_tail_zero(ulinfo, sizeof(linfo),
				       linfo_len);
	if (err)
		return err;
	linfo_len = min_t(u32, linfo_len, sizeof(linfo));
	if (copy_from_bpfptr(&linfo, ulinfo, linfo_len))
		return -EFAULT;

	if (!linfo.map_fd)
		return -EBADF;

	prog_btf_id = prog->aux->attach_btf_id;
	mutex_lock(&targets_mutex);
	list_for_each_entry(tinfo, &targets, list) {
		if (tinfo->btf_id == prog_btf_id) {
			existed = true;
			break;
		}
	}
	mutex_unlock(&targets_mutex);
	if (!existed)
		return -ENOENT;

	map = bpf_map_get_with_uref(linfo.map_fd);
	if (IS_ERR(map))
		return PTR_ERR(map);
	if (tinfo->reg_info->trace_type != linfo.trace_type) {
		err = -EINVAL;
		goto map_put;
	}

	link = kzalloc(sizeof(*link), GFP_USER | __GFP_NOWARN);
	if (!link) {
		err = -ENOMEM;
		goto map_put;
	}

	bpf_link_init(&link->link, BPF_LINK_TYPE_MAP_TRACE,
		      &bpf_map_trace_link_ops, prog);
	link->tinfo = tinfo;
	link->map = map;

	err = bpf_link_prime(&link->link, &link_primer);
	if (err) {
		kfree(link);
		goto map_put;
	}

	err = bpf_map_attach_trace(prog, map, &linfo);
	if (err) {
		bpf_link_cleanup(&link_primer);
		goto map_put;
	}

	return bpf_link_settle(&link_primer);
map_put:
	bpf_map_put_with_uref(map);
	return err;
}

