// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 Facebook */
/* BPF-specific BTF extensions */

#include <uapi/linux/btf.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/types.h>
#include <linux/compiler.h>
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/sort.h>
#include <linux/seq_file.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/bsearch.h>
#include <linux/string.h>
#include <linux/overflow.h>
#include <linux/kobject.h>

#include <uapi/linux/bpf_perf_event.h>
#include <linux/anon_inodes.h>
#include <linux/uaccess.h>
#include <linux/idr.h>
#include <linux/bpf.h>
#include <linux/bpf_lsm.h>
#include <linux/skmsg.h>
#include <linux/perf_event.h>
#include <linux/sysfs.h>

#include <net/netfilter/nf_bpf_link.h>

#include <net/sock.h>
#include <net/xdp.h>
#include "../tools/lib/bpf/relo_core.h"

#include "btf.h"

DEFINE_IDR(btf_idr);
DEFINE_SPINLOCK(btf_idr_lock);

enum btf_kfunc_hook {
	BTF_KFUNC_HOOK_COMMON,
	BTF_KFUNC_HOOK_XDP,
	BTF_KFUNC_HOOK_TC,
	BTF_KFUNC_HOOK_STRUCT_OPS,
	BTF_KFUNC_HOOK_TRACING,
	BTF_KFUNC_HOOK_SYSCALL,
	BTF_KFUNC_HOOK_FMODRET,
	BTF_KFUNC_HOOK_CGROUP,
	BTF_KFUNC_HOOK_SCHED_ACT,
	BTF_KFUNC_HOOK_SK_SKB,
	BTF_KFUNC_HOOK_SOCKET_FILTER,
	BTF_KFUNC_HOOK_LWT,
	BTF_KFUNC_HOOK_NETFILTER,
	BTF_KFUNC_HOOK_KPROBE,
	BTF_KFUNC_HOOK_MAX,
};

enum {
	BTF_KFUNC_SET_MAX_CNT = 256,
	BTF_DTOR_KFUNC_MAX_CNT = 256,
	BTF_KFUNC_FILTER_MAX_CNT = 16,
};

struct btf_kfunc_hook_filter {
	btf_kfunc_filter_t filters[BTF_KFUNC_FILTER_MAX_CNT];
	u32 nr_filters;
};

struct btf_kfunc_set_tab {
	struct btf_id_set8 *sets[BTF_KFUNC_HOOK_MAX];
	struct btf_kfunc_hook_filter hook_filters[BTF_KFUNC_HOOK_MAX];
};

struct btf_id_dtor_kfunc_tab {
	u32 cnt;
	struct btf_id_dtor_kfunc dtors[];
};

struct btf_struct_ops_tab {
	u32 cnt;
	u32 capacity;
	struct bpf_struct_ops_desc ops[];
};
	u32 id;
	struct rcu_head rcu;
	struct btf_kfunc_set_tab *kfunc_set_tab;
	struct btf_id_dtor_kfunc_tab *dtor_kfunc_tab;
	struct btf_struct_metas *struct_meta_tab;
	struct btf_struct_ops_tab *struct_ops_tab;
s32 bpf_find_btf_id(const char *name, u32 kind, struct btf **btf_p)
{
	struct btf *btf;
	s32 ret;
	int id;

	btf = bpf_get_btf_vmlinux();
	if (IS_ERR(btf))
		return PTR_ERR(btf);
	if (!btf)
		return -EINVAL;

	ret = btf_find_by_name_kind(btf, name, kind);
	/* ret is never zero, since btf_find_by_name_kind returns
	 * positive btf_id or negative error.
	 */
	if (ret > 0) {
		btf_get(btf);
		*btf_p = btf;
		return ret;
	}

	/* If name is not found in vmlinux's BTF then search in module's BTFs */
	spin_lock_bh(&btf_idr_lock);
	idr_for_each_entry(&btf_idr, btf, id) {
		if (!btf_is_module(btf))
			continue;
		/* linear search could be slow hence unlock/lock
		 * the IDR to avoiding holding it for too long
		 */
		btf_get(btf);
		spin_unlock_bh(&btf_idr_lock);
		ret = btf_find_by_name_kind(btf, name, kind);
		if (ret > 0) {
			*btf_p = btf;
			return ret;
		}
		btf_put(btf);
		spin_lock_bh(&btf_idr_lock);
	}
	spin_unlock_bh(&btf_idr_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(bpf_find_btf_id);
static int btf_alloc_id(struct btf *btf)
{
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock_bh(&btf_idr_lock);
	id = idr_alloc_cyclic(&btf_idr, btf, 1, INT_MAX, GFP_ATOMIC);
	if (id > 0)
		btf->id = id;
	spin_unlock_bh(&btf_idr_lock);
	idr_preload_end();

	if (WARN_ON_ONCE(!id))
		return -ENOSPC;

	return id > 0 ? 0 : id;
}

static void btf_free_id(struct btf *btf)
{
	unsigned long flags;

	/*
	 * In map-in-map, calling map_delete_elem() on outer
	 * map will call bpf_map_put on the inner map.
	 * It will then eventually call btf_free_id()
	 * on the inner map.  Some of the map_delete_elem()
	 * implementation may have irq disabled, so
	 * we need to use the _irqsave() version instead
	 * of the _bh() version.
	 */
	spin_lock_irqsave(&btf_idr_lock, flags);
	if (btf->id) {
		idr_remove(&btf_idr, btf->id);
		/*
		 * Clear the id here to make this function idempotent, since it will get
		 * called a couple of times for module BTFs: on module unload, and then
		 * the final btf_put(). btf_alloc_id() starts IDs with 1, so we can use
		 * 0 as sentinel value.
		 */
		WRITE_ONCE(btf->id, 0);
	}
	spin_unlock_irqrestore(&btf_idr_lock, flags);
}

static void btf_free_kfunc_set_tab(struct btf *btf)
{
	struct btf_kfunc_set_tab *tab = btf->kfunc_set_tab;
	int hook;

	if (!tab)
		return;
	for (hook = 0; hook < ARRAY_SIZE(tab->sets); hook++)
		kfree(tab->sets[hook]);
	kfree(tab);
	btf->kfunc_set_tab = NULL;
}

static void btf_free_dtor_kfunc_tab(struct btf *btf)
{
	struct btf_id_dtor_kfunc_tab *tab = btf->dtor_kfunc_tab;

	if (!tab)
		return;
	kfree(tab);
	btf->dtor_kfunc_tab = NULL;
}

static void btf_struct_metas_free(struct btf_struct_metas *tab)
{
	int i;

	if (!tab)
		return;
	for (i = 0; i < tab->cnt; i++)
		btf_record_free(tab->types[i].record);
	kfree(tab);
}

static void btf_free_struct_meta_tab(struct btf *btf)
{
	struct btf_struct_metas *tab = btf->struct_meta_tab;

	btf_struct_metas_free(tab);
	btf->struct_meta_tab = NULL;
}

static void btf_free_struct_ops_tab(struct btf *btf)
{
	struct btf_struct_ops_tab *tab = btf->struct_ops_tab;
	u32 i;

	if (!tab)
		return;

	for (i = 0; i < tab->cnt; i++)
		bpf_struct_ops_desc_release(&tab->ops[i]);

	kfree(tab);
	btf->struct_ops_tab = NULL;
}

void btf_free_bpf_data(struct btf *btf)
{
	btf_free_struct_meta_tab(btf);
	btf_free_dtor_kfunc_tab(btf);
	btf_free_kfunc_set_tab(btf);
	btf_free_struct_ops_tab(btf);
}

static void btf_free_rcu(struct rcu_head *rcu)
{
	struct btf *btf = container_of(rcu, struct btf, rcu);

	btf_free(btf);
}

void btf_put_bpf(struct btf *btf)
{
	btf_free_id(btf);
	call_rcu(&btf->rcu, btf_free_rcu);
}
enum {
	BTF_FIELD_IGNORE = 0,
	BTF_FIELD_FOUND  = 1,
};

struct btf_field_info {
	enum btf_field_type type;
	u32 off;
	union {
		struct {
			u32 type_id;
		} kptr;
		struct {
			const char *node_name;
			u32 value_btf_id;
		} graph_root;
	};
};

static int btf_find_struct(const struct btf *btf, const struct btf_type *t,
			   u32 off, int sz, enum btf_field_type field_type,
			   struct btf_field_info *info)
{
	if (!__btf_type_is_struct(t))
		return BTF_FIELD_IGNORE;
	if (t->size != sz)
		return BTF_FIELD_IGNORE;
	info->type = field_type;
	info->off = off;
	return BTF_FIELD_FOUND;
}

static int btf_find_kptr(const struct btf *btf, const struct btf_type *t,
			 u32 off, int sz, struct btf_field_info *info, u32 field_mask)
{
	enum btf_field_type type;
	const char *tag_value;
	bool is_type_tag;
	u32 res_id;

	/* Permit modifiers on the pointer itself */
	if (btf_type_is_volatile(t))
		t = btf_type_by_id(btf, t->type);
	/* For PTR, sz is always == 8 */
	if (!btf_type_is_ptr(t))
		return BTF_FIELD_IGNORE;
	t = btf_type_by_id(btf, t->type);
	is_type_tag = btf_type_is_type_tag(t) && !btf_type_kflag(t);
	if (!is_type_tag)
		return BTF_FIELD_IGNORE;
	/* Reject extra tags */
	if (btf_type_is_type_tag(btf_type_by_id(btf, t->type)))
		return -EINVAL;
	tag_value = __btf_name_by_offset(btf, t->name_off);
	if (!strcmp("kptr_untrusted", tag_value))
		type = BPF_KPTR_UNREF;
	else if (!strcmp("kptr", tag_value))
		type = BPF_KPTR_REF;
	else if (!strcmp("percpu_kptr", tag_value))
		type = BPF_KPTR_PERCPU;
	else if (!strcmp("uptr", tag_value))
		type = BPF_UPTR;
	else
		return -EINVAL;

	if (!(type & field_mask))
		return BTF_FIELD_IGNORE;

	/* Get the base type */
	t = btf_type_skip_modifiers(btf, t->type, &res_id);
	/* Only pointer to struct is allowed */
	if (!__btf_type_is_struct(t))
		return -EINVAL;

	info->type = type;
	info->off = off;
	info->kptr.type_id = res_id;
	return BTF_FIELD_FOUND;
}

int btf_find_next_decl_tag(const struct btf *btf, const struct btf_type *pt,
			   int comp_idx, const char *tag_key, int last_id)
{
	int len = strlen(tag_key);
	int i, n;

	for (i = last_id + 1, n = btf_nr_types(btf); i < n; i++) {
		const struct btf_type *t = btf_type_by_id(btf, i);

		if (!btf_type_is_decl_tag(t))
			continue;
		if (pt != btf_type_by_id(btf, t->type))
			continue;
		if (btf_type_decl_tag(t)->component_idx != comp_idx)
			continue;
		if (strncmp(__btf_name_by_offset(btf, t->name_off), tag_key, len))
			continue;
		return i;
	}
	return -ENOENT;
}

const char *btf_find_decl_tag_value(const struct btf *btf, const struct btf_type *pt,
				    int comp_idx, const char *tag_key)
{
	const char *value = NULL;
	const struct btf_type *t;
	int len, id;

	id = btf_find_next_decl_tag(btf, pt, comp_idx, tag_key,
				    btf_named_start_id(btf, false) - 1);
	if (id < 0)
		return ERR_PTR(id);

	t = btf_type_by_id(btf, id);
	len = strlen(tag_key);
	value = __btf_name_by_offset(btf, t->name_off) + len;

	/* Prevent duplicate entries for same type */
	id = btf_find_next_decl_tag(btf, pt, comp_idx, tag_key, id);
	if (id >= 0)
		return ERR_PTR(-EEXIST);

	return value;
}

static int
btf_find_graph_root(const struct btf *btf, const struct btf_type *pt,
		    const struct btf_type *t, int comp_idx, u32 off,
		    int sz, struct btf_field_info *info,
		    enum btf_field_type head_type)
{
	const char *node_field_name;
	const char *value_type;
	s32 id;

	if (!__btf_type_is_struct(t))
		return BTF_FIELD_IGNORE;
	if (t->size != sz)
		return BTF_FIELD_IGNORE;
	value_type = btf_find_decl_tag_value(btf, pt, comp_idx, "contains:");
	if (IS_ERR(value_type))
		return -EINVAL;
	node_field_name = strstr(value_type, ":");
	if (!node_field_name)
		return -EINVAL;
	value_type = kstrndup(value_type, node_field_name - value_type,
			      GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
	if (!value_type)
		return -ENOMEM;
	id = btf_find_by_name_kind(btf, value_type, BTF_KIND_STRUCT);
	kfree(value_type);
	if (id < 0)
		return id;
	node_field_name++;
	if (str_is_empty(node_field_name))
		return -EINVAL;
	info->type = head_type;
	info->off = off;
	info->graph_root.value_btf_id = id;
	info->graph_root.node_name = node_field_name;
	return BTF_FIELD_FOUND;
}

static int btf_get_field_type(const struct btf *btf, const struct btf_type *var_type,
			      u32 field_mask, u32 *seen_mask, int *align, int *sz)
{
	const struct {
		enum btf_field_type type;
		const char *const name;
		const bool is_unique;
	} field_types[] = {
		{ BPF_SPIN_LOCK, "bpf_spin_lock", true },
		{ BPF_RES_SPIN_LOCK, "bpf_res_spin_lock", true },
		{ BPF_TIMER, "bpf_timer", true },
		{ BPF_WORKQUEUE, "bpf_wq", true },
		{ BPF_TASK_WORK, "bpf_task_work", true },
		{ BPF_LIST_HEAD, "bpf_list_head", false },
		{ BPF_LIST_NODE, "bpf_list_node", false },
		{ BPF_RB_ROOT, "bpf_rb_root", false },
		{ BPF_RB_NODE, "bpf_rb_node", false },
		{ BPF_REFCOUNT, "bpf_refcount", false },
	};
	int type = 0, i;
	const char *name = __btf_name_by_offset(btf, var_type->name_off);
	const char *field_type_name;
	enum btf_field_type field_type;
	bool is_unique;

	for (i = 0; i < ARRAY_SIZE(field_types); ++i) {
		field_type = field_types[i].type;
		field_type_name = field_types[i].name;
		is_unique = field_types[i].is_unique;
		if (!(field_mask & field_type) || strcmp(name, field_type_name))
			continue;
		if (is_unique) {
			if (*seen_mask & field_type)
				return -E2BIG;
			*seen_mask |= field_type;
		}
		type = field_type;
		goto end;
	}

	/* Only return BPF_KPTR when all other types with matchable names fail */
	if (field_mask & (BPF_KPTR | BPF_UPTR) && !__btf_type_is_struct(var_type)) {
		type = BPF_KPTR_REF;
		goto end;
	}
	return 0;
end:
	*sz = btf_field_type_size(type);
	*align = btf_field_type_align(type);
	return type;
}

/* Repeat a number of fields for a specified number of times.
 *
 * Copy the fields starting from the first field and repeat them for
 * repeat_cnt times. The fields are repeated by adding the offset of each
 * field with
 *   (i + 1) * elem_size
 * where i is the repeat index and elem_size is the size of an element.
 */
static int btf_repeat_fields(struct btf_field_info *info, int info_cnt,
			     u32 field_cnt, u32 repeat_cnt, u32 elem_size)
{
	u32 i, j;
	u32 cur;

	/* Ensure not repeating fields that should not be repeated. */
	for (i = 0; i < field_cnt; i++) {
		switch (info[i].type) {
		case BPF_KPTR_UNREF:
		case BPF_KPTR_REF:
		case BPF_KPTR_PERCPU:
		case BPF_UPTR:
		case BPF_LIST_HEAD:
		case BPF_RB_ROOT:
			break;
		default:
			return -EINVAL;
		}
	}

	/* The type of struct size or variable size is u32,
	 * so the multiplication will not overflow.
	 */
	if (field_cnt * (repeat_cnt + 1) > info_cnt)
		return -E2BIG;

	cur = field_cnt;
	for (i = 0; i < repeat_cnt; i++) {
		memcpy(&info[cur], &info[0], field_cnt * sizeof(info[0]));
		for (j = 0; j < field_cnt; j++)
			info[cur++].off += (i + 1) * elem_size;
	}

	return 0;
}

static int btf_find_struct_field(const struct btf *btf,
				 const struct btf_type *t, u32 field_mask,
				 struct btf_field_info *info, int info_cnt,
				 u32 level);

/* Find special fields in the struct type of a field.
 *
 * This function is used to find fields of special types that is not a
 * global variable or a direct field of a struct type. It also handles the
 * repetition if it is the element type of an array.
 */
static int btf_find_nested_struct(const struct btf *btf, const struct btf_type *t,
				  u32 off, u32 nelems,
				  u32 field_mask, struct btf_field_info *info,
				  int info_cnt, u32 level)
{
	int ret, err, i;

	level++;
	if (level >= MAX_RESOLVE_DEPTH)
		return -E2BIG;

	ret = btf_find_struct_field(btf, t, field_mask, info, info_cnt, level);

	if (ret <= 0)
		return ret;

	/* Shift the offsets of the nested struct fields to the offsets
	 * related to the container.
	 */
	for (i = 0; i < ret; i++)
		info[i].off += off;

	if (nelems > 1) {
		err = btf_repeat_fields(info, info_cnt, ret, nelems - 1, t->size);
		if (err == 0)
			ret *= nelems;
		else
			ret = err;
	}

	return ret;
}

static int btf_find_field_one(const struct btf *btf,
			      const struct btf_type *var,
			      const struct btf_type *var_type,
			      int var_idx,
			      u32 off, u32 expected_size,
			      u32 field_mask, u32 *seen_mask,
			      struct btf_field_info *info, int info_cnt,
			      u32 level)
{
	int ret, align, sz, field_type;
	struct btf_field_info tmp;
	const struct btf_array *array;
	u32 i, nelems = 1;

	/* Walk into array types to find the element type and the number of
	 * elements in the (flattened) array.
	 */
	for (i = 0; i < MAX_RESOLVE_DEPTH && btf_type_is_array(var_type); i++) {
		array = btf_array(var_type);
		nelems *= array->nelems;
		var_type = btf_type_by_id(btf, array->type);
	}
	if (i == MAX_RESOLVE_DEPTH)
		return -E2BIG;
	if (nelems == 0)
		return 0;

	field_type = btf_get_field_type(btf, var_type,
					field_mask, seen_mask, &align, &sz);
	/* Look into variables of struct types */
	if (!field_type && __btf_type_is_struct(var_type)) {
		sz = var_type->size;
		if (expected_size && expected_size != sz * nelems)
			return 0;
		ret = btf_find_nested_struct(btf, var_type, off, nelems, field_mask,
					     &info[0], info_cnt, level);
		return ret;
	}

	if (field_type == 0)
		return 0;
	if (field_type < 0)
		return field_type;

	if (expected_size && expected_size != sz * nelems)
		return 0;
	if (off % align)
		return 0;

	switch (field_type) {
	case BPF_SPIN_LOCK:
	case BPF_RES_SPIN_LOCK:
	case BPF_TIMER:
	case BPF_WORKQUEUE:
	case BPF_LIST_NODE:
	case BPF_RB_NODE:
	case BPF_REFCOUNT:
	case BPF_TASK_WORK:
		ret = btf_find_struct(btf, var_type, off, sz, field_type,
				      info_cnt ? &info[0] : &tmp);
		if (ret < 0)
			return ret;
		break;
	case BPF_KPTR_UNREF:
	case BPF_KPTR_REF:
	case BPF_KPTR_PERCPU:
	case BPF_UPTR:
		ret = btf_find_kptr(btf, var_type, off, sz,
				    info_cnt ? &info[0] : &tmp, field_mask);
		if (ret < 0)
			return ret;
		break;
	case BPF_LIST_HEAD:
	case BPF_RB_ROOT:
		ret = btf_find_graph_root(btf, var, var_type,
					  var_idx, off, sz,
					  info_cnt ? &info[0] : &tmp,
					  field_type);
		if (ret < 0)
			return ret;
		break;
	default:
		return -EFAULT;
	}

	if (ret == BTF_FIELD_IGNORE)
		return 0;
	if (!info_cnt)
		return -E2BIG;
	if (nelems > 1) {
		ret = btf_repeat_fields(info, info_cnt, 1, nelems - 1, sz);
		if (ret < 0)
			return ret;
	}
	return nelems;
}

static int btf_find_struct_field(const struct btf *btf,
				 const struct btf_type *t, u32 field_mask,
				 struct btf_field_info *info, int info_cnt,
				 u32 level)
{
	int ret, idx = 0;
	const struct btf_member *member;
	u32 i, off, seen_mask = 0;

	for_each_member(i, t, member) {
		const struct btf_type *member_type = btf_type_by_id(btf,
								    member->type);

		off = __btf_member_bit_offset(t, member);
		if (off % 8)
			/* valid C code cannot generate such BTF */
			return -EINVAL;
		off /= 8;

		ret = btf_find_field_one(btf, t, member_type, i,
					 off, 0,
					 field_mask, &seen_mask,
					 &info[idx], info_cnt - idx, level);
		if (ret < 0)
			return ret;
		idx += ret;
	}
	return idx;
}

static int btf_find_datasec_var(const struct btf *btf, const struct btf_type *t,
				u32 field_mask, struct btf_field_info *info,
				int info_cnt, u32 level)
{
	int ret, idx = 0;
	const struct btf_var_secinfo *vsi;
	u32 i, off, seen_mask = 0;

	for_each_vsi(i, t, vsi) {
		const struct btf_type *var = btf_type_by_id(btf, vsi->type);
		const struct btf_type *var_type = btf_type_by_id(btf, var->type);

		off = vsi->offset;
		ret = btf_find_field_one(btf, var, var_type, -1, off, vsi->size,
					 field_mask, &seen_mask,
					 &info[idx], info_cnt - idx,
					 level);
		if (ret < 0)
			return ret;
		idx += ret;
	}
	return idx;
}

static int btf_find_field(const struct btf *btf, const struct btf_type *t,
			  u32 field_mask, struct btf_field_info *info,
			  int info_cnt)
{
	if (__btf_type_is_struct(t))
		return btf_find_struct_field(btf, t, field_mask, info, info_cnt, 0);
	else if (btf_type_is_datasec(t))
		return btf_find_datasec_var(btf, t, field_mask, info, info_cnt, 0);
	return -EINVAL;
}

/* Callers have to ensure the life cycle of btf if it is program BTF */
static int btf_parse_kptr(const struct btf *btf, struct btf_field *field,
			  struct btf_field_info *info)
{
	struct module *mod = NULL;
	const struct btf_type *t;
	/* If a matching btf type is found in kernel or module BTFs, kptr_ref
	 * is that BTF, otherwise it's program BTF
	 */
	struct btf *kptr_btf;
	int ret;
	s32 id;

	/* Find type in map BTF, and use it to look up the matching type
	 * in vmlinux or module BTFs, by name and kind.
	 */
	t = btf_type_by_id(btf, info->kptr.type_id);
	id = bpf_find_btf_id(__btf_name_by_offset(btf, t->name_off), BTF_INFO_KIND(t->info),
			     &kptr_btf);
	if (id == -ENOENT) {
		/* btf_parse_kptr should only be called w/ btf = program BTF */
		WARN_ON_ONCE(btf_is_kernel(btf));

		/* Type exists only in program BTF. Assume that it's a MEM_ALLOC
		 * kptr allocated via bpf_obj_new
		 */
		field->kptr.dtor = NULL;
		id = info->kptr.type_id;
		kptr_btf = (struct btf *)btf;
		goto found_dtor;
	}
	if (id < 0)
		return id;

	/* Find and stash the function pointer for the destruction function that
	 * needs to be eventually invoked from the map free path.
	 */
	if (info->type == BPF_KPTR_REF) {
		const struct btf_type *dtor_func;
		const char *dtor_func_name;
		unsigned long addr;
		s32 dtor_btf_id;

		/* This call also serves as a whitelist of allowed objects that
		 * can be used as a referenced pointer and be stored in a map at
		 * the same time.
		 */
		dtor_btf_id = btf_find_dtor_kfunc(kptr_btf, id);
		if (dtor_btf_id < 0) {
			ret = dtor_btf_id;
			goto end_btf;
		}

		dtor_func = btf_type_by_id(kptr_btf, dtor_btf_id);
		if (!dtor_func) {
			ret = -ENOENT;
			goto end_btf;
		}

		if (btf_is_module(kptr_btf)) {
			mod = btf_try_get_module(kptr_btf);
			if (!mod) {
				ret = -ENXIO;
				goto end_btf;
			}
		}

		/* We already verified dtor_func to be btf_type_is_func
		 * in register_btf_id_dtor_kfuncs.
		 */
		dtor_func_name = __btf_name_by_offset(kptr_btf, dtor_func->name_off);
		addr = kallsyms_lookup_name(dtor_func_name);
		if (!addr) {
			ret = -EINVAL;
			goto end_mod;
		}
		field->kptr.dtor = (void *)addr;
	}

found_dtor:
	field->kptr.btf_id = id;
	field->kptr.btf = kptr_btf;
	field->kptr.module = mod;
	return 0;
end_mod:
	module_put(mod);
end_btf:
	btf_put(kptr_btf);
	return ret;
}

static int btf_parse_graph_root(const struct btf *btf,
				struct btf_field *field,
				struct btf_field_info *info,
				const char *node_type_name,
				size_t node_type_align)
{
	const struct btf_type *t, *n = NULL;
	const struct btf_member *member;
	u32 offset;
	int i;

	t = btf_type_by_id(btf, info->graph_root.value_btf_id);
	/* We've already checked that value_btf_id is a struct type. We
	 * just need to figure out the offset of the list_node, and
	 * verify its type.
	 */
	for_each_member(i, t, member) {
		if (strcmp(info->graph_root.node_name,
			   __btf_name_by_offset(btf, member->name_off)))
			continue;
		/* Invalid BTF, two members with same name */
		if (n)
			return -EINVAL;
		n = btf_type_by_id(btf, member->type);
		if (!__btf_type_is_struct(n))
			return -EINVAL;
		if (strcmp(node_type_name, __btf_name_by_offset(btf, n->name_off)))
			return -EINVAL;
		offset = __btf_member_bit_offset(n, member);
		if (offset % 8)
			return -EINVAL;
		offset /= 8;
		if (offset % node_type_align)
			return -EINVAL;

		field->graph_root.btf = (struct btf *)btf;
		field->graph_root.value_btf_id = info->graph_root.value_btf_id;
		field->graph_root.node_offset = offset;
	}
	if (!n)
		return -ENOENT;
	return 0;
}

static int btf_parse_list_head(const struct btf *btf, struct btf_field *field,
			       struct btf_field_info *info)
{
	return btf_parse_graph_root(btf, field, info, "bpf_list_node",
					    __alignof__(struct bpf_list_node));
}

static int btf_parse_rb_root(const struct btf *btf, struct btf_field *field,
			     struct btf_field_info *info)
{
	return btf_parse_graph_root(btf, field, info, "bpf_rb_node",
					    __alignof__(struct bpf_rb_node));
}

static int btf_field_cmp(const void *_a, const void *_b, const void *priv)
{
	const struct btf_field *a = (const struct btf_field *)_a;
	const struct btf_field *b = (const struct btf_field *)_b;

	if (a->offset < b->offset)
		return -1;
	else if (a->offset > b->offset)
		return 1;
	return 0;
}

struct btf_record *btf_parse_fields(const struct btf *btf, const struct btf_type *t,
				    u32 field_mask, u32 value_size)
{
	struct btf_field_info info_arr[BTF_FIELDS_MAX];
	u32 next_off = 0, field_type_size;
	struct btf_record *rec;
	int ret, i, cnt;

	ret = btf_find_field(btf, t, field_mask, info_arr, ARRAY_SIZE(info_arr));
	if (ret < 0)
		return ERR_PTR(ret);
	if (!ret)
		return NULL;

	cnt = ret;
	/* This needs to be kzalloc to zero out padding and unused fields, see
	 * comment in btf_record_equal.
	 */
	rec = kzalloc_flex(*rec, fields, cnt, GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
	if (!rec)
		return ERR_PTR(-ENOMEM);

	rec->spin_lock_off = -EINVAL;
	rec->res_spin_lock_off = -EINVAL;
	rec->timer_off = -EINVAL;
	rec->wq_off = -EINVAL;
	rec->refcount_off = -EINVAL;
	rec->task_work_off = -EINVAL;
	for (i = 0; i < cnt; i++) {
		field_type_size = btf_field_type_size(info_arr[i].type);
		if (info_arr[i].off + field_type_size > value_size) {
			WARN_ONCE(1, "verifier bug off %d size %d", info_arr[i].off, value_size);
			ret = -EFAULT;
			goto end;
		}
		if (info_arr[i].off < next_off) {
			ret = -EEXIST;
			goto end;
		}
		next_off = info_arr[i].off + field_type_size;

		rec->field_mask |= info_arr[i].type;
		rec->fields[i].offset = info_arr[i].off;
		rec->fields[i].type = info_arr[i].type;
		rec->fields[i].size = field_type_size;

		switch (info_arr[i].type) {
		case BPF_SPIN_LOCK:
			WARN_ON_ONCE(rec->spin_lock_off >= 0);
			/* Cache offset for faster lookup at runtime */
			rec->spin_lock_off = rec->fields[i].offset;
			break;
		case BPF_RES_SPIN_LOCK:
			WARN_ON_ONCE(rec->spin_lock_off >= 0);
			/* Cache offset for faster lookup at runtime */
			rec->res_spin_lock_off = rec->fields[i].offset;
			break;
		case BPF_TIMER:
			WARN_ON_ONCE(rec->timer_off >= 0);
			/* Cache offset for faster lookup at runtime */
			rec->timer_off = rec->fields[i].offset;
			break;
		case BPF_WORKQUEUE:
			WARN_ON_ONCE(rec->wq_off >= 0);
			/* Cache offset for faster lookup at runtime */
			rec->wq_off = rec->fields[i].offset;
			break;
		case BPF_TASK_WORK:
			WARN_ON_ONCE(rec->task_work_off >= 0);
			rec->task_work_off = rec->fields[i].offset;
			break;
		case BPF_REFCOUNT:
			WARN_ON_ONCE(rec->refcount_off >= 0);
			/* Cache offset for faster lookup at runtime */
			rec->refcount_off = rec->fields[i].offset;
			break;
		case BPF_KPTR_UNREF:
		case BPF_KPTR_REF:
		case BPF_KPTR_PERCPU:
		case BPF_UPTR:
			ret = btf_parse_kptr(btf, &rec->fields[i], &info_arr[i]);
			if (ret < 0)
				goto end;
			break;
		case BPF_LIST_HEAD:
			ret = btf_parse_list_head(btf, &rec->fields[i], &info_arr[i]);
			if (ret < 0)
				goto end;
			break;
		case BPF_RB_ROOT:
			ret = btf_parse_rb_root(btf, &rec->fields[i], &info_arr[i]);
			if (ret < 0)
				goto end;
			break;
		case BPF_LIST_NODE:
		case BPF_RB_NODE:
			break;
		default:
			ret = -EFAULT;
			goto end;
		}
		rec->cnt++;
	}

	if (rec->spin_lock_off >= 0 && rec->res_spin_lock_off >= 0) {
		ret = -EINVAL;
		goto end;
	}

	/* bpf_{list_head, rb_node} require bpf_spin_lock */
	if ((btf_record_has_field(rec, BPF_LIST_HEAD) ||
	     btf_record_has_field(rec, BPF_RB_ROOT)) &&
		 (rec->spin_lock_off < 0 && rec->res_spin_lock_off < 0)) {
		ret = -EINVAL;
		goto end;
	}

	if (rec->refcount_off < 0 &&
	    btf_record_has_field(rec, BPF_LIST_NODE) &&
	    btf_record_has_field(rec, BPF_RB_NODE)) {
		ret = -EINVAL;
		goto end;
	}

	sort_r(rec->fields, rec->cnt, sizeof(struct btf_field), btf_field_cmp,
	       NULL, rec);

	return rec;
end:
	btf_record_free(rec);
	return ERR_PTR(ret);
}

int btf_check_and_fixup_fields(const struct btf *btf, struct btf_record *rec)
{
	int i;

	/* There are three types that signify ownership of some other type:
	 *  kptr_ref, bpf_list_head, bpf_rb_root.
	 * kptr_ref only supports storing kernel types, which can't store
	 * references to program allocated local types.
	 *
	 * Hence we only need to ensure that bpf_{list_head,rb_root} ownership
	 * does not form cycles.
	 */
	if (IS_ERR_OR_NULL(rec) || !(rec->field_mask & (BPF_GRAPH_ROOT | BPF_UPTR)))
		return 0;
	for (i = 0; i < rec->cnt; i++) {
		struct btf_struct_meta *meta;
		const struct btf_type *t;
		u32 btf_id;

		if (rec->fields[i].type == BPF_UPTR) {
			/* The uptr only supports pinning one page and cannot
			 * point to a kernel struct
			 */
			if (btf_is_kernel(rec->fields[i].kptr.btf))
				return -EINVAL;
			t = btf_type_by_id(rec->fields[i].kptr.btf,
					   rec->fields[i].kptr.btf_id);
			if (!t->size)
				return -EINVAL;
			if (t->size > PAGE_SIZE)
				return -E2BIG;
			continue;
		}

		if (!(rec->fields[i].type & BPF_GRAPH_ROOT))
			continue;
		btf_id = rec->fields[i].graph_root.value_btf_id;
		meta = btf_find_struct_meta(btf, btf_id);
		if (!meta)
			return -EFAULT;
		rec->fields[i].graph_root.value_rec = meta->record;

		/* We need to set value_rec for all root types, but no need
		 * to check ownership cycle for a type unless it's also a
		 * node type.
		 */
		if (!(rec->field_mask & BPF_GRAPH_NODE))
			continue;

		/* We need to ensure ownership acyclicity among all types. The
		 * proper way to do it would be to topologically sort all BTF
		 * IDs based on the ownership edges, since there can be multiple
		 * bpf_{list_head,rb_node} in a type. Instead, we use the
		 * following resaoning:
		 *
		 * - A type can only be owned by another type in user BTF if it
		 *   has a bpf_{list,rb}_node. Let's call these node types.
		 * - A type can only _own_ another type in user BTF if it has a
		 *   bpf_{list_head,rb_root}. Let's call these root types.
		 *
		 * We ensure that if a type is both a root and node, its
		 * element types cannot be root types.
		 *
		 * To ensure acyclicity:
		 *
		 * When A is an root type but not a node, its ownership
		 * chain can be:
		 *	A -> B -> C
		 * Where:
		 * - A is an root, e.g. has bpf_rb_root.
		 * - B is both a root and node, e.g. has bpf_rb_node and
		 *   bpf_list_head.
		 * - C is only an root, e.g. has bpf_list_node
		 *
		 * When A is both a root and node, some other type already
		 * owns it in the BTF domain, hence it can not own
		 * another root type through any of the ownership edges.
		 *	A -> B
		 * Where:
		 * - A is both an root and node.
		 * - B is only an node.
		 */
		if (meta->record->field_mask & BPF_GRAPH_ROOT)
			return -ELOOP;
	}
	return 0;
}
static const char *alloc_obj_fields[] = {
	"bpf_spin_lock",
	"bpf_list_head",
	"bpf_list_node",
	"bpf_rb_root",
	"bpf_rb_node",
	"bpf_refcount",
};

static struct btf_struct_metas *
btf_parse_struct_metas(struct bpf_verifier_log *log, struct btf *btf)
{
	struct btf_struct_metas *tab = NULL;
	struct btf_id_set *aof;
	int i, n, id, ret;

	BUILD_BUG_ON(offsetof(struct btf_id_set, cnt) != 0);
	BUILD_BUG_ON(sizeof(struct btf_id_set) != sizeof(u32));

	aof = kmalloc_obj(*aof, GFP_KERNEL | __GFP_NOWARN);
	if (!aof)
		return ERR_PTR(-ENOMEM);
	aof->cnt = 0;

	for (i = 0; i < ARRAY_SIZE(alloc_obj_fields); i++) {
		/* Try to find whether this special type exists in user BTF, and
		 * if so remember its ID so we can easily find it among members
		 * of structs that we iterate in the next loop.
		 */
		struct btf_id_set *new_aof;

		id = btf_find_by_name_kind(btf, alloc_obj_fields[i], BTF_KIND_STRUCT);
		if (id < 0)
			continue;

		new_aof = krealloc(aof, struct_size(new_aof, ids, aof->cnt + 1),
				   GFP_KERNEL | __GFP_NOWARN);
		if (!new_aof) {
			ret = -ENOMEM;
			goto free_aof;
		}
		aof = new_aof;
		aof->ids[aof->cnt++] = id;
	}

	n = btf_nr_types(btf);
	for (i = 1; i < n; i++) {
		/* Try to find if there are kptrs in user BTF and remember their ID */
		struct btf_id_set *new_aof;
		struct btf_field_info tmp;
		const struct btf_type *t;

		t = btf_type_by_id(btf, i);
		if (!t) {
			ret = -EINVAL;
			goto free_aof;
		}

		ret = btf_find_kptr(btf, t, 0, 0, &tmp, BPF_KPTR);
		if (ret != BTF_FIELD_FOUND)
			continue;

		new_aof = krealloc(aof, struct_size(new_aof, ids, aof->cnt + 1),
				   GFP_KERNEL | __GFP_NOWARN);
		if (!new_aof) {
			ret = -ENOMEM;
			goto free_aof;
		}
		aof = new_aof;
		aof->ids[aof->cnt++] = i;
	}

	if (!aof->cnt) {
		kfree(aof);
		return NULL;
	}
	sort(&aof->ids, aof->cnt, sizeof(aof->ids[0]), btf_id_cmp_func, NULL);

	for (i = 1; i < n; i++) {
		struct btf_struct_metas *new_tab;
		const struct btf_member *member;
		struct btf_struct_meta *type;
		struct btf_record *record;
		const struct btf_type *t;
		int j, tab_cnt;

		t = btf_type_by_id(btf, i);
		if (!__btf_type_is_struct(t))
			continue;

		cond_resched();

		for_each_member(j, t, member) {
			if (btf_id_set_contains(aof, member->type))
				goto parse;
		}
		continue;
	parse:
		tab_cnt = tab ? tab->cnt : 0;
		new_tab = krealloc(tab, struct_size(new_tab, types, tab_cnt + 1),
				   GFP_KERNEL | __GFP_NOWARN);
		if (!new_tab) {
			ret = -ENOMEM;
			goto free;
		}
		if (!tab)
			new_tab->cnt = 0;
		tab = new_tab;

		type = &tab->types[tab->cnt];
		type->btf_id = i;
		record = btf_parse_fields(btf, t, BPF_SPIN_LOCK | BPF_RES_SPIN_LOCK | BPF_LIST_HEAD | BPF_LIST_NODE |
						  BPF_RB_ROOT | BPF_RB_NODE | BPF_REFCOUNT |
						  BPF_KPTR, t->size);
		/* The record cannot be unset, treat it as an error if so */
		if (IS_ERR_OR_NULL(record)) {
			ret = PTR_ERR_OR_ZERO(record) ?: -EFAULT;
			goto free;
		}
		type->record = record;
		tab->cnt++;
	}
	kfree(aof);
	return tab;
free:
	btf_struct_metas_free(tab);
free_aof:
	kfree(aof);
	return ERR_PTR(ret);
}

struct btf_struct_meta *btf_find_struct_meta(const struct btf *btf, u32 btf_id)
{
	struct btf_struct_metas *tab;

	BUILD_BUG_ON(offsetof(struct btf_struct_meta, btf_id) != 0);
	tab = btf->struct_meta_tab;
	if (!tab)
		return NULL;
	return bsearch(&btf_id, tab->types, tab->cnt, sizeof(tab->types[0]), btf_id_cmp_func);
}
static int finalize_log(struct bpf_verifier_log *log, bpfptr_t uattr, u32 uattr_size)
{
	u32 log_true_size;
	int err;

	err = bpf_vlog_finalize(log, &log_true_size);

	if (uattr_size >= offsetofend(union bpf_attr, btf_log_true_size) &&
	    copy_to_bpfptr_offset(uattr, offsetof(union bpf_attr, btf_log_true_size),
				  &log_true_size, sizeof(log_true_size)))
		err = -EFAULT;

	return err;
}

static struct btf *btf_parse(const union bpf_attr *attr, bpfptr_t uattr, u32 uattr_size)
{
	bpfptr_t btf_data = make_bpfptr(attr->btf, uattr.is_kernel);
	char __user *log_ubuf = u64_to_user_ptr(attr->btf_log_buf);
	struct btf_struct_metas *struct_meta_tab;
	struct btf_verifier_env *env = NULL;
	struct btf *btf = NULL;
	u8 *data;
	int err, ret;

	if (attr->btf_size > BTF_MAX_SIZE)
		return ERR_PTR(-E2BIG);

	env = kzalloc_obj(*env, GFP_KERNEL | __GFP_NOWARN);
	if (!env)
		return ERR_PTR(-ENOMEM);

	/* user could have requested verbose verifier output
	 * and supplied buffer to store the verification trace
	 */
	err = bpf_vlog_init(&env->log, attr->btf_log_level,
			    log_ubuf, attr->btf_log_size);
	if (err)
		goto errout_free;

	btf = kzalloc_obj(*btf, GFP_KERNEL | __GFP_NOWARN);
	if (!btf) {
		err = -ENOMEM;
		goto errout;
	}
	env->btf = btf;
	btf->named_start_id = 0;

	data = kvmalloc(attr->btf_size, GFP_KERNEL | __GFP_NOWARN);
	if (!data) {
		err = -ENOMEM;
		goto errout;
	}

	btf->data = data;
	btf->data_size = attr->btf_size;

	if (copy_from_bpfptr(data, btf_data, attr->btf_size)) {
		err = -EFAULT;
		goto errout;
	}

	err = btf_parse_hdr(env);
	if (err)
		goto errout;

	btf->nohdr_data = btf->data + btf->hdr.hdr_len;

	err = btf_parse_str_sec(env);
	if (err)
		goto errout;

	err = btf_parse_type_sec(env);
	if (err)
		goto errout;

	err = btf_check_type_tags(env, btf, 1);
	if (err)
		goto errout;

	struct_meta_tab = btf_parse_struct_metas(&env->log, btf);
	if (IS_ERR(struct_meta_tab)) {
		err = PTR_ERR(struct_meta_tab);
		goto errout;
	}
	btf->struct_meta_tab = struct_meta_tab;

	if (struct_meta_tab) {
		int i;

		for (i = 0; i < struct_meta_tab->cnt; i++) {
			err = btf_check_and_fixup_fields(btf, struct_meta_tab->types[i].record);
			if (err < 0)
				goto errout_meta;
		}
	}

	err = finalize_log(&env->log, uattr, uattr_size);
	if (err)
		goto errout_free;

	btf_verifier_env_free(env);
	refcount_set(&btf->refcnt, 1);
	return btf;

errout_meta:
	btf_free_struct_meta_tab(btf);
errout:
	/* overwrite err with -ENOSPC or -EFAULT */
	ret = finalize_log(&env->log, uattr, uattr_size);
	if (ret)
		err = ret;
errout_free:
	btf_verifier_env_free(env);
	if (btf)
		btf_free(btf);
	return ERR_PTR(err);
}

extern char __start_BTF[];
extern char __stop_BTF[];
extern struct btf *btf_vmlinux;

#define BPF_MAP_TYPE(_id, _ops)
#define BPF_LINK_TYPE(_id, _name)
static union {
	struct bpf_ctx_convert {
#define BPF_PROG_TYPE(_id, _name, prog_ctx_type, kern_ctx_type) \
	prog_ctx_type _id##_prog; \
	kern_ctx_type _id##_kern;
#include <linux/bpf_types.h>
#undef BPF_PROG_TYPE
	} *__t;
	/* 't' is written once under lock. Read many times. */
	const struct btf_type *t;
} bpf_ctx_convert;
enum {
#define BPF_PROG_TYPE(_id, _name, prog_ctx_type, kern_ctx_type) \
	__ctx_convert##_id,
#include <linux/bpf_types.h>
#undef BPF_PROG_TYPE
	__ctx_convert_unused, /* to avoid empty enum in extreme .config */
};
static u8 bpf_ctx_convert_map[] = {
#define BPF_PROG_TYPE(_id, _name, prog_ctx_type, kern_ctx_type) \
	[_id] = __ctx_convert##_id,
#include <linux/bpf_types.h>
#undef BPF_PROG_TYPE
	0, /* avoid empty array */
};
#undef BPF_MAP_TYPE
#undef BPF_LINK_TYPE

static const struct btf_type *find_canonical_prog_ctx_type(enum bpf_prog_type prog_type)
{
	const struct btf_type *conv_struct;
	const struct btf_member *ctx_type;

	conv_struct = bpf_ctx_convert.t;
	if (!conv_struct)
		return NULL;
	/* prog_type is valid bpf program type. No need for bounds check. */
	ctx_type = btf_type_member(conv_struct) + bpf_ctx_convert_map[prog_type] * 2;
	/* ctx_type is a pointer to prog_ctx_type in vmlinux.
	 * Like 'struct __sk_buff'
	 */
	return btf_type_by_id(btf_vmlinux, ctx_type->type);
}

static int find_kern_ctx_type_id(enum bpf_prog_type prog_type)
{
	const struct btf_type *conv_struct;
	const struct btf_member *ctx_type;

	conv_struct = bpf_ctx_convert.t;
	if (!conv_struct)
		return -EFAULT;
	/* prog_type is valid bpf program type. No need for bounds check. */
	ctx_type = btf_type_member(conv_struct) + bpf_ctx_convert_map[prog_type] * 2 + 1;
	/* ctx_type is a pointer to prog_ctx_type in vmlinux.
	 * Like 'struct sk_buff'
	 */
	return ctx_type->type;
}

bool btf_is_projection_of(const char *pname, const char *tname)
{
	if (strcmp(pname, "__sk_buff") == 0 && strcmp(tname, "sk_buff") == 0)
		return true;
	if (strcmp(pname, "xdp_md") == 0 && strcmp(tname, "xdp_buff") == 0)
		return true;
	return false;
}

bool btf_is_prog_ctx_type(struct bpf_verifier_log *log, const struct btf *btf,
			  const struct btf_type *t, enum bpf_prog_type prog_type,
			  int arg)
{
	const struct btf_type *ctx_type;
	const char *tname, *ctx_tname;

	t = btf_type_by_id(btf, t->type);

	/* KPROBE programs allow bpf_user_pt_regs_t typedef, which we need to
	 * check before we skip all the typedef below.
	 */
	if (prog_type == BPF_PROG_TYPE_KPROBE) {
		while (btf_type_is_modifier(t) && !btf_type_is_typedef(t))
			t = btf_type_by_id(btf, t->type);

		if (btf_type_is_typedef(t)) {
			tname = btf_name_by_offset(btf, t->name_off);
			if (tname && strcmp(tname, "bpf_user_pt_regs_t") == 0)
				return true;
		}
	}

	while (btf_type_is_modifier(t))
		t = btf_type_by_id(btf, t->type);
	if (!btf_type_is_struct(t)) {
		/* Only pointer to struct is supported for now.
		 * That means that BPF_PROG_TYPE_TRACEPOINT with BTF
		 * is not supported yet.
		 * BPF_PROG_TYPE_RAW_TRACEPOINT is fine.
		 */
		return false;
	}
	tname = btf_name_by_offset(btf, t->name_off);
	if (!tname) {
		bpf_log(log, "arg#%d struct doesn't have a name\n", arg);
		return false;
	}

	ctx_type = find_canonical_prog_ctx_type(prog_type);
	if (!ctx_type) {
		bpf_log(log, "btf_vmlinux is malformed\n");
		/* should not happen */
		return false;
	}
again:
	ctx_tname = btf_name_by_offset(btf_vmlinux, ctx_type->name_off);
	if (!ctx_tname) {
		/* should not happen */
		bpf_log(log, "Please fix kernel include/linux/bpf_types.h\n");
		return false;
	}
	/* program types without named context types work only with arg:ctx tag */
	if (ctx_tname[0] == '\0')
		return false;
	/* only compare that prog's ctx type name is the same as
	 * kernel expects. No need to compare field by field.
	 * It's ok for bpf prog to do:
	 * struct __sk_buff {};
	 * int socket_filter_bpf_prog(struct __sk_buff *skb)
	 * { // no fields of skb are ever used }
	 */
	if (btf_is_projection_of(ctx_tname, tname))
		return true;
	if (strcmp(ctx_tname, tname)) {
		/* bpf_user_pt_regs_t is a typedef, so resolve it to
		 * underlying struct and check name again
		 */
		if (!btf_type_is_modifier(ctx_type))
			return false;
		while (btf_type_is_modifier(ctx_type))
			ctx_type = btf_type_by_id(btf_vmlinux, ctx_type->type);
		goto again;
	}
	return true;
}

/* forward declarations for arch-specific underlying types of
 * bpf_user_pt_regs_t; this avoids the need for arch-specific #ifdef
 * compilation guards below for BPF_PROG_TYPE_PERF_EVENT checks, but still
 * works correctly with __builtin_types_compatible_p() on respective
 * architectures
 */
struct user_regs_struct;
struct user_pt_regs;

static int btf_validate_prog_ctx_type(struct bpf_verifier_log *log, const struct btf *btf,
				      const struct btf_type *t, int arg,
				      enum bpf_prog_type prog_type,
				      enum bpf_attach_type attach_type)
{
	const struct btf_type *ctx_type;
	const char *tname, *ctx_tname;

	if (!btf_is_ptr(t)) {
		bpf_log(log, "arg#%d type isn't a pointer\n", arg);
		return -EINVAL;
	}
	t = btf_type_by_id(btf, t->type);

	/* KPROBE and PERF_EVENT programs allow bpf_user_pt_regs_t typedef */
	if (prog_type == BPF_PROG_TYPE_KPROBE || prog_type == BPF_PROG_TYPE_PERF_EVENT) {
		while (btf_type_is_modifier(t) && !btf_type_is_typedef(t))
			t = btf_type_by_id(btf, t->type);

		if (btf_type_is_typedef(t)) {
			tname = btf_name_by_offset(btf, t->name_off);
			if (tname && strcmp(tname, "bpf_user_pt_regs_t") == 0)
				return 0;
		}
	}

	/* all other program types don't use typedefs for context type */
	while (btf_type_is_modifier(t))
		t = btf_type_by_id(btf, t->type);

	/* `void *ctx __arg_ctx` is always valid */
	if (btf_type_is_void(t))
		return 0;

	tname = btf_name_by_offset(btf, t->name_off);
	if (str_is_empty(tname)) {
		bpf_log(log, "arg#%d type doesn't have a name\n", arg);
		return -EINVAL;
	}

	/* special cases */
	switch (prog_type) {
	case BPF_PROG_TYPE_KPROBE:
		if (__btf_type_is_struct(t) && strcmp(tname, "pt_regs") == 0)
			return 0;
		break;
	case BPF_PROG_TYPE_PERF_EVENT:
		if (__builtin_types_compatible_p(bpf_user_pt_regs_t, struct pt_regs) &&
		    __btf_type_is_struct(t) && strcmp(tname, "pt_regs") == 0)
			return 0;
		if (__builtin_types_compatible_p(bpf_user_pt_regs_t, struct user_pt_regs) &&
		    __btf_type_is_struct(t) && strcmp(tname, "user_pt_regs") == 0)
			return 0;
		if (__builtin_types_compatible_p(bpf_user_pt_regs_t, struct user_regs_struct) &&
		    __btf_type_is_struct(t) && strcmp(tname, "user_regs_struct") == 0)
			return 0;
		break;
	case BPF_PROG_TYPE_RAW_TRACEPOINT:
	case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE:
		/* allow u64* as ctx */
		if (btf_is_int(t) && t->size == 8)
			return 0;
		break;
	case BPF_PROG_TYPE_TRACING:
		switch (attach_type) {
		case BPF_TRACE_RAW_TP:
			/* tp_btf program is TRACING, so need special case here */
			if (__btf_type_is_struct(t) &&
			    strcmp(tname, "bpf_raw_tracepoint_args") == 0)
				return 0;
			/* allow u64* as ctx */
			if (btf_is_int(t) && t->size == 8)
				return 0;
			break;
		case BPF_TRACE_ITER:
			/* allow struct bpf_iter__xxx types only */
			if (__btf_type_is_struct(t) &&
			    strncmp(tname, "bpf_iter__", sizeof("bpf_iter__") - 1) == 0)
				return 0;
			break;
		case BPF_TRACE_FENTRY:
		case BPF_TRACE_FEXIT:
		case BPF_MODIFY_RETURN:
		case BPF_TRACE_FSESSION:
			/* allow u64* as ctx */
			if (btf_is_int(t) && t->size == 8)
				return 0;
			break;
		default:
			break;
		}
		break;
	case BPF_PROG_TYPE_LSM:
	case BPF_PROG_TYPE_STRUCT_OPS:
		/* allow u64* as ctx */
		if (btf_is_int(t) && t->size == 8)
			return 0;
		break;
	case BPF_PROG_TYPE_TRACEPOINT:
	case BPF_PROG_TYPE_SYSCALL:
	case BPF_PROG_TYPE_EXT:
		return 0; /* anything goes */
	default:
		break;
	}

	ctx_type = find_canonical_prog_ctx_type(prog_type);
	if (!ctx_type) {
		/* should not happen */
		bpf_log(log, "btf_vmlinux is malformed\n");
		return -EINVAL;
	}

	/* resolve typedefs and check that underlying structs are matching as well */
	while (btf_type_is_modifier(ctx_type))
		ctx_type = btf_type_by_id(btf_vmlinux, ctx_type->type);

	/* if program type doesn't have distinctly named struct type for
	 * context, then __arg_ctx argument can only be `void *`, which we
	 * already checked above
	 */
	if (!__btf_type_is_struct(ctx_type)) {
		bpf_log(log, "arg#%d should be void pointer\n", arg);
		return -EINVAL;
	}

	ctx_tname = btf_name_by_offset(btf_vmlinux, ctx_type->name_off);
	if (!__btf_type_is_struct(t) || strcmp(ctx_tname, tname) != 0) {
		bpf_log(log, "arg#%d should be `struct %s *`\n", arg, ctx_tname);
		return -EINVAL;
	}

	return 0;
}

static int btf_translate_to_vmlinux(struct bpf_verifier_log *log,
				     struct btf *btf,
				     const struct btf_type *t,
				     enum bpf_prog_type prog_type,
				     int arg)
{
	if (!btf_is_prog_ctx_type(log, btf, t, prog_type, arg))
		return -ENOENT;
	return find_kern_ctx_type_id(prog_type);
}

int get_kern_ctx_btf_id(struct bpf_verifier_log *log, enum bpf_prog_type prog_type)
{
	const struct btf_member *kctx_member;
	const struct btf_type *conv_struct;
	const struct btf_type *kctx_type;
	u32 kctx_type_id;

	conv_struct = bpf_ctx_convert.t;
	/* get member for kernel ctx type */
	kctx_member = btf_type_member(conv_struct) + bpf_ctx_convert_map[prog_type] * 2 + 1;
	kctx_type_id = kctx_member->type;
	kctx_type = btf_type_by_id(btf_vmlinux, kctx_type_id);
	if (!btf_type_is_struct(kctx_type)) {
		bpf_log(log, "kern ctx type id %u is not a struct\n", kctx_type_id);
		return -EINVAL;
	}

	return kctx_type_id;
}

BTF_ID_LIST_SINGLE(bpf_ctx_convert_btf_id, struct, bpf_ctx_convert)
struct btf *btf_parse_vmlinux(void)
{
	struct btf_verifier_env *env = NULL;
	struct bpf_verifier_log *log;
	struct btf *btf;
	int err;

	env = kzalloc_obj(*env, GFP_KERNEL | __GFP_NOWARN);
	if (!env)
		return ERR_PTR(-ENOMEM);

	log = &env->log;
	log->level = BPF_LOG_KERNEL;
	btf = btf_parse_base(env, "vmlinux", __start_BTF, __stop_BTF - __start_BTF);
	if (IS_ERR(btf))
		goto err_out;

	/* btf_parse_vmlinux() runs under bpf_verifier_lock */
	bpf_ctx_convert.t = btf_type_by_id(btf, bpf_ctx_convert_btf_id[0]);
	err = btf_alloc_id(btf);
	if (err) {
		btf_free(btf);
		btf = ERR_PTR(err);
	}
err_out:
	btf_verifier_env_free(env);
	return btf;
}

/* If .BTF_ids section was created with distilled base BTF, both base and
 * split BTF ids will need to be mapped to actual base/split ids for
 * BTF now that it has been relocated.
 */
static __u32 btf_relocate_id(const struct btf *btf, __u32 id)
{
	if (!btf->base_btf || !btf->base_id_map)
		return id;
	return btf->base_id_map[id];
}

#ifdef CONFIG_DEBUG_INFO_BTF_MODULES

static struct btf *btf_parse_module(const char *module_name, const void *data,
				    unsigned int data_size, void *base_data,
				    unsigned int base_data_size)
{
	struct btf *btf = NULL, *vmlinux_btf, *base_btf = NULL;
	struct btf_verifier_env *env = NULL;
	struct bpf_verifier_log *log;
	int err = 0;

	vmlinux_btf = bpf_get_btf_vmlinux();
	if (IS_ERR(vmlinux_btf))
		return vmlinux_btf;
	if (!vmlinux_btf)
		return ERR_PTR(-EINVAL);

	env = kzalloc_obj(*env, GFP_KERNEL | __GFP_NOWARN);
	if (!env)
		return ERR_PTR(-ENOMEM);

	log = &env->log;
	log->level = BPF_LOG_KERNEL;

	if (base_data) {
		base_btf = btf_parse_base(env, ".BTF.base", base_data, base_data_size);
		if (IS_ERR(base_btf)) {
			err = PTR_ERR(base_btf);
			goto errout;
		}
	} else {
		base_btf = vmlinux_btf;
	}

	btf = kzalloc_obj(*btf, GFP_KERNEL | __GFP_NOWARN);
	if (!btf) {
		err = -ENOMEM;
		goto errout;
	}
	env->btf = btf;

	btf->base_btf = base_btf;
	btf->start_id = base_btf->nr_types;
	btf->start_str_off = base_btf->hdr.str_len;
	btf->kernel_btf = true;
	btf->named_start_id = 0;
	strscpy(btf->name, module_name);

	btf->data = kvmemdup(data, data_size, GFP_KERNEL | __GFP_NOWARN);
	if (!btf->data) {
		err = -ENOMEM;
		goto errout;
	}
	btf->data_size = data_size;

	err = btf_parse_hdr(env);
	if (err)
		goto errout;

	btf->nohdr_data = btf->data + btf->hdr.hdr_len;

	err = btf_parse_str_sec(env);
	if (err)
		goto errout;

	err = btf_check_all_metas(env);
	if (err)
		goto errout;

	err = btf_check_type_tags(env, btf, btf_nr_types(base_btf));
	if (err)
		goto errout;

	if (base_btf != vmlinux_btf) {
		err = btf_relocate(btf, vmlinux_btf, &btf->base_id_map);
		if (err)
			goto errout;
		btf_free(base_btf);
		base_btf = vmlinux_btf;
	}

	btf_verifier_env_free(env);
	btf_check_sorted(btf);
	refcount_set(&btf->refcnt, 1);
	return btf;

errout:
	btf_verifier_env_free(env);
	if (!IS_ERR(base_btf) && base_btf != vmlinux_btf)
		btf_free(base_btf);
	if (btf) {
		kvfree(btf->data);
		kvfree(btf->types);
		kfree(btf);
	}
	return ERR_PTR(err);
}

#endif /* CONFIG_DEBUG_INFO_BTF_MODULES */

struct btf *bpf_prog_get_target_btf(const struct bpf_prog *prog)
{
	struct bpf_prog *tgt_prog = prog->aux->dst_prog;

	if (tgt_prog)
		return tgt_prog->aux->btf;
	else
		return prog->aux->attach_btf;
}

u32 btf_ctx_arg_idx(struct btf *btf, const struct btf_type *func_proto,
		    int off)
{
	const struct btf_param *args;
	const struct btf_type *t;
	u32 offset = 0, nr_args;
	int i;

	if (!func_proto)
		return off / 8;

	nr_args = btf_type_vlen(func_proto);
	args = (const struct btf_param *)(func_proto + 1);
	for (i = 0; i < nr_args; i++) {
		t = btf_type_skip_modifiers(btf, args[i].type, NULL);
		offset += btf_type_is_ptr(t) ? 8 : roundup(t->size, 8);
		if (off < offset)
			return i;
	}

	t = btf_type_skip_modifiers(btf, func_proto->type, NULL);
	offset += btf_type_is_ptr(t) ? 8 : roundup(t->size, 8);
	if (off < offset)
		return nr_args;

	return nr_args + 1;
}

static bool prog_args_trusted(const struct bpf_prog *prog)
{
	enum bpf_attach_type atype = prog->expected_attach_type;

	switch (prog->type) {
	case BPF_PROG_TYPE_TRACING:
		return atype == BPF_TRACE_RAW_TP || atype == BPF_TRACE_ITER;
	case BPF_PROG_TYPE_LSM:
		return bpf_lsm_is_trusted(prog);
	case BPF_PROG_TYPE_STRUCT_OPS:
		return true;
	default:
		return false;
	}
}

int btf_ctx_arg_offset(const struct btf *btf, const struct btf_type *func_proto,
		       u32 arg_no)
{
	const struct btf_param *args;
	const struct btf_type *t;
	int off = 0, i;
	u32 sz;

	args = btf_params(func_proto);
	for (i = 0; i < arg_no; i++) {
		t = btf_type_by_id(btf, args[i].type);
		t = btf_resolve_size(btf, t, &sz);
		if (IS_ERR(t))
			return PTR_ERR(t);
		off += roundup(sz, 8);
	}

	return off;
}

struct bpf_raw_tp_null_args {
	const char *func;
	u64 mask;
};

static const struct bpf_raw_tp_null_args raw_tp_null_args[] = {
	/* sched */
	{ "sched_pi_setprio", 0x10 },
	/* ... from sched_numa_pair_template event class */
	{ "sched_stick_numa", 0x100 },
	{ "sched_swap_numa", 0x100 },
	/* afs */
	{ "afs_make_fs_call", 0x10 },
	{ "afs_make_fs_calli", 0x10 },
	{ "afs_make_fs_call1", 0x10 },
	{ "afs_make_fs_call2", 0x10 },
	{ "afs_protocol_error", 0x1 },
	{ "afs_flock_ev", 0x10 },
	/* cachefiles */
	{ "cachefiles_lookup", 0x1 | 0x200 },
	{ "cachefiles_unlink", 0x1 },
	{ "cachefiles_rename", 0x1 },
	{ "cachefiles_prep_read", 0x1 },
	{ "cachefiles_mark_active", 0x1 },
	{ "cachefiles_mark_failed", 0x1 },
	{ "cachefiles_mark_inactive", 0x1 },
	{ "cachefiles_vfs_error", 0x1 },
	{ "cachefiles_io_error", 0x1 },
	{ "cachefiles_ondemand_open", 0x1 },
	{ "cachefiles_ondemand_copen", 0x1 },
	{ "cachefiles_ondemand_close", 0x1 },
	{ "cachefiles_ondemand_read", 0x1 },
	{ "cachefiles_ondemand_cread", 0x1 },
	{ "cachefiles_ondemand_fd_write", 0x1 },
	{ "cachefiles_ondemand_fd_release", 0x1 },
	/* ext4, from ext4__mballoc event class */
	{ "ext4_mballoc_discard", 0x10 },
	{ "ext4_mballoc_free", 0x10 },
	/* fib */
	{ "fib_table_lookup", 0x100 },
	/* filelock */
	/* ... from filelock_lock event class */
	{ "posix_lock_inode", 0x10 },
	{ "fcntl_setlk", 0x10 },
	{ "locks_remove_posix", 0x10 },
	{ "flock_lock_inode", 0x10 },
	/* ... from filelock_lease event class */
	{ "break_lease_noblock", 0x10 },
	{ "break_lease_block", 0x10 },
	{ "break_lease_unblock", 0x10 },
	{ "generic_delete_lease", 0x10 },
	{ "time_out_leases", 0x10 },
	/* host1x */
	{ "host1x_cdma_push_gather", 0x10000 },
	/* huge_memory */
	{ "mm_khugepaged_scan_pmd", 0x10 },
	{ "mm_collapse_huge_page_isolate", 0x1 },
	{ "mm_khugepaged_scan_file", 0x10 },
	{ "mm_khugepaged_collapse_file", 0x10 },
	/* kmem */
	{ "mm_page_alloc", 0x1 },
	{ "mm_page_pcpu_drain", 0x1 },
	/* .. from mm_page event class */
	{ "mm_page_alloc_zone_locked", 0x1 },
	/* netfs */
	{ "netfs_failure", 0x10 },
	/* power */
	{ "device_pm_callback_start", 0x10 },
	/* qdisc */
	{ "qdisc_dequeue", 0x1000 },
	/* rxrpc */
	{ "rxrpc_recvdata", 0x1 },
	{ "rxrpc_resend", 0x10 },
	{ "rxrpc_tq", 0x10 },
	{ "rxrpc_client", 0x1 },
	/* skb */
	{"kfree_skb", 0x1000},
	/* sunrpc */
	{ "xs_stream_read_data", 0x1 },
	/* ... from xprt_cong_event event class */
	{ "xprt_reserve_cong", 0x10 },
	{ "xprt_release_cong", 0x10 },
	{ "xprt_get_cong", 0x10 },
	{ "xprt_put_cong", 0x10 },
	/* tcp */
	{ "tcp_send_reset", 0x11 },
	{ "tcp_sendmsg_locked", 0x100 },
	/* tegra_apb_dma */
	{ "tegra_dma_tx_status", 0x100 },
	/* timer_migration */
	{ "tmigr_update_events", 0x1 },
	/* writeback, from writeback_folio_template event class */
	{ "writeback_dirty_folio", 0x10 },
	{ "folio_wait_writeback", 0x10 },
	/* rdma */
	{ "mr_integ_alloc", 0x2000 },
	/* bpf_testmod */
	{ "bpf_testmod_test_read", 0x0 },
	/* amdgpu */
	{ "amdgpu_vm_bo_map", 0x1 },
	{ "amdgpu_vm_bo_unmap", 0x1 },
	/* netfs */
	{ "netfs_folioq", 0x1 },
	/* xfs from xfs_defer_pending_class */
	{ "xfs_defer_create_intent", 0x1 },
	{ "xfs_defer_cancel_list", 0x1 },
	{ "xfs_defer_pending_finish", 0x1 },
	{ "xfs_defer_pending_abort", 0x1 },
	{ "xfs_defer_relog_intent", 0x1 },
	{ "xfs_defer_isolate_paused", 0x1 },
	{ "xfs_defer_item_pause", 0x1 },
	{ "xfs_defer_item_unpause", 0x1 },
	/* xfs from xfs_defer_pending_item_class */
	{ "xfs_defer_add_item", 0x1 },
	{ "xfs_defer_cancel_item", 0x1 },
	{ "xfs_defer_finish_item", 0x1 },
	/* xfs from xfs_icwalk_class */
	{ "xfs_ioc_free_eofblocks", 0x10 },
	{ "xfs_blockgc_free_space", 0x10 },
	/* xfs from xfs_btree_cur_class */
	{ "xfs_btree_updkeys", 0x100 },
	{ "xfs_btree_overlapped_query_range", 0x100 },
	/* xfs from xfs_imap_class*/
	{ "xfs_map_blocks_found", 0x10000 },
	{ "xfs_map_blocks_alloc", 0x10000 },
	{ "xfs_iomap_alloc", 0x1000 },
	{ "xfs_iomap_found", 0x1000 },
	/* xfs from xfs_fs_class */
	{ "xfs_inodegc_flush", 0x1 },
	{ "xfs_inodegc_push", 0x1 },
	{ "xfs_inodegc_start", 0x1 },
	{ "xfs_inodegc_stop", 0x1 },
	{ "xfs_inodegc_queue", 0x1 },
	{ "xfs_inodegc_throttle", 0x1 },
	{ "xfs_fs_sync_fs", 0x1 },
	{ "xfs_blockgc_start", 0x1 },
	{ "xfs_blockgc_stop", 0x1 },
	{ "xfs_blockgc_worker", 0x1 },
	{ "xfs_blockgc_flush_all", 0x1 },
	/* xfs_scrub */
	{ "xchk_nlinks_live_update", 0x10 },
	/* xfs_scrub from xchk_metapath_class */
	{ "xchk_metapath_lookup", 0x100 },
	/* nfsd */
	{ "nfsd_dirent", 0x1 },
	{ "nfsd_file_acquire", 0x1001 },
	{ "nfsd_file_insert_err", 0x1 },
	{ "nfsd_file_cons_err", 0x1 },
	/* nfs4 */
	{ "nfs4_setup_sequence", 0x1 },
	{ "pnfs_update_layout", 0x10000 },
	{ "nfs4_inode_callback_event", 0x200 },
	{ "nfs4_inode_stateid_callback_event", 0x200 },
	/* nfs from pnfs_layout_event */
	{ "pnfs_mds_fallback_pg_init_read", 0x10000 },
	{ "pnfs_mds_fallback_pg_init_write", 0x10000 },
	{ "pnfs_mds_fallback_pg_get_mirror_count", 0x10000 },
	{ "pnfs_mds_fallback_read_done", 0x10000 },
	{ "pnfs_mds_fallback_write_done", 0x10000 },
	{ "pnfs_mds_fallback_read_pagelist", 0x10000 },
	{ "pnfs_mds_fallback_write_pagelist", 0x10000 },
	/* coda */
	{ "coda_dec_pic_run", 0x10 },
	{ "coda_dec_pic_done", 0x10 },
	/* cfg80211 */
	{ "cfg80211_scan_done", 0x11 },
	{ "rdev_set_coalesce", 0x10 },
	{ "cfg80211_report_wowlan_wakeup", 0x100 },
	{ "cfg80211_inform_bss_frame", 0x100 },
	{ "cfg80211_michael_mic_failure", 0x10000 },
	/* cfg80211 from wiphy_work_event */
	{ "wiphy_work_queue", 0x10 },
	{ "wiphy_work_run", 0x10 },
	{ "wiphy_work_cancel", 0x10 },
	{ "wiphy_work_flush", 0x10 },
	/* hugetlbfs */
	{ "hugetlbfs_alloc_inode", 0x10 },
	/* spufs */
	{ "spufs_context", 0x10 },
	/* kvm_hv */
	{ "kvm_page_fault_enter", 0x100 },
	/* dpu */
	{ "dpu_crtc_setup_mixer", 0x100 },
	/* binder */
	{ "binder_transaction", 0x100 },
	/* bcachefs */
	{ "btree_path_free", 0x100 },
	/* hfi1_tx */
	{ "hfi1_sdma_progress", 0x1000 },
	/* iptfs */
	{ "iptfs_ingress_postq_event", 0x1000 },
	/* neigh */
	{ "neigh_update", 0x10 },
	/* snd_firewire_lib */
	{ "amdtp_packet", 0x100 },
};

bool btf_ctx_access(int off, int size, enum bpf_access_type type,
		    const struct bpf_prog *prog,
		    struct bpf_insn_access_aux *info)
{
	const struct btf_type *t = prog->aux->attach_func_proto;
	struct bpf_prog *tgt_prog = prog->aux->dst_prog;
	struct btf *btf = bpf_prog_get_target_btf(prog);
	const char *tname = prog->aux->attach_func_name;
	struct bpf_verifier_log *log = info->log;
	const struct btf_param *args;
	bool ptr_err_raw_tp = false;
	const char *tag_value;
	u32 nr_args, arg;
	int i, ret;

	if (off % 8) {
		bpf_log(log, "func '%s' offset %d is not multiple of 8\n",
			tname, off);
		return false;
	}
	arg = btf_ctx_arg_idx(btf, t, off);
	args = (const struct btf_param *)(t + 1);
	/* if (t == NULL) Fall back to default BPF prog with
	 * MAX_BPF_FUNC_REG_ARGS u64 arguments.
	 */
	nr_args = t ? btf_type_vlen(t) : MAX_BPF_FUNC_REG_ARGS;
	if (prog->aux->attach_btf_trace) {
		/* skip first 'void *__data' argument in btf_trace_##name typedef */
		args++;
		nr_args--;
	}

	if (arg > nr_args) {
		bpf_log(log, "func '%s' doesn't have %d-th argument\n",
			tname, arg + 1);
		return false;
	}

	if (arg == nr_args) {
		switch (prog->expected_attach_type) {
		case BPF_LSM_MAC:
			/* mark we are accessing the return value */
			info->is_retval = true;
			fallthrough;
		case BPF_LSM_CGROUP:
		case BPF_TRACE_FEXIT:
		case BPF_TRACE_FSESSION:
			/* When LSM programs are attached to void LSM hooks
			 * they use FEXIT trampolines and when attached to
			 * int LSM hooks, they use MODIFY_RETURN trampolines.
			 *
			 * While the LSM programs are BPF_MODIFY_RETURN-like
			 * the check:
			 *
			 *	if (ret_type != 'int')
			 *		return -EINVAL;
			 *
			 * is _not_ done here. This is still safe as LSM hooks
			 * have only void and int return types.
			 */
			if (!t)
				return true;
			t = btf_type_by_id(btf, t->type);
			break;
		case BPF_MODIFY_RETURN:
			/* For now the BPF_MODIFY_RETURN can only be attached to
			 * functions that return an int.
			 */
			if (!t)
				return false;

			t = btf_type_skip_modifiers(btf, t->type, NULL);
			if (!btf_type_is_small_int(t)) {
				bpf_log(log,
					"ret type %s not allowed for fmod_ret\n",
					btf_type_str(t));
				return false;
			}
			break;
		default:
			bpf_log(log, "func '%s' doesn't have %d-th argument\n",
				tname, arg + 1);
			return false;
		}
	} else {
		if (!t)
			/* Default prog with MAX_BPF_FUNC_REG_ARGS args */
			return true;
		t = btf_type_by_id(btf, args[arg].type);
	}

	/* skip modifiers */
	while (btf_type_is_modifier(t))
		t = btf_type_by_id(btf, t->type);
	if (btf_type_is_small_int(t) || btf_is_any_enum(t) || btf_type_is_struct(t))
		/* accessing a scalar */
		return true;
	if (!btf_type_is_ptr(t)) {
		bpf_log(log,
			"func '%s' arg%d '%s' has type %s. Only pointer access is allowed\n",
			tname, arg,
			__btf_name_by_offset(btf, t->name_off),
			btf_type_str(t));
		return false;
	}

	if (size != sizeof(u64)) {
		bpf_log(log, "func '%s' size %d must be 8\n",
			tname, size);
		return false;
	}

	/* check for PTR_TO_RDONLY_BUF_OR_NULL or PTR_TO_RDWR_BUF_OR_NULL */
	for (i = 0; i < prog->aux->ctx_arg_info_size; i++) {
		const struct bpf_ctx_arg_aux *ctx_arg_info = &prog->aux->ctx_arg_info[i];
		u32 type, flag;

		type = base_type(ctx_arg_info->reg_type);
		flag = type_flag(ctx_arg_info->reg_type);
		if (ctx_arg_info->offset == off && type == PTR_TO_BUF &&
		    (flag & PTR_MAYBE_NULL)) {
			info->reg_type = ctx_arg_info->reg_type;
			return true;
		}
	}

	/*
	 * If it's a single or multilevel pointer, except a pointer
	 * to a structure, it's the same as scalar from the verifier
	 * safety POV. Multilevel pointers to structures are treated as
	 * scalars. The verifier lacks the context to infer the size of
	 * their target memory regions. Either way, no further pointer
	 * walking is allowed.
	 */
	if (!btf_type_is_struct_ptr(btf, t))
		return true;

	/* this is a pointer to another type */
	for (i = 0; i < prog->aux->ctx_arg_info_size; i++) {
		const struct bpf_ctx_arg_aux *ctx_arg_info = &prog->aux->ctx_arg_info[i];

		if (ctx_arg_info->offset == off) {
			if (!ctx_arg_info->btf_id) {
				bpf_log(log,"invalid btf_id for context argument offset %u\n", off);
				return false;
			}

			info->reg_type = ctx_arg_info->reg_type;
			info->btf = ctx_arg_info->btf ? : btf_vmlinux;
			info->btf_id = ctx_arg_info->btf_id;
			info->ref_obj_id = ctx_arg_info->ref_obj_id;
			return true;
		}
	}

	info->reg_type = PTR_TO_BTF_ID;
	if (prog_args_trusted(prog))
		info->reg_type |= PTR_TRUSTED;

	if (btf_param_match_suffix(btf, &args[arg], "__nullable"))
		info->reg_type |= PTR_MAYBE_NULL;

	if (prog->expected_attach_type == BPF_TRACE_RAW_TP) {
		struct btf *btf = prog->aux->attach_btf;
		const struct btf_type *t;
		const char *tname;

		/* BTF lookups cannot fail, return false on error */
		t = btf_type_by_id(btf, prog->aux->attach_btf_id);
		if (!t)
			return false;
		tname = btf_name_by_offset(btf, t->name_off);
		if (!tname)
			return false;
		/* Checked by bpf_check_attach_target */
		tname += sizeof("btf_trace_") - 1;
		for (i = 0; i < ARRAY_SIZE(raw_tp_null_args); i++) {
			/* Is this a func with potential NULL args? */
			if (strcmp(tname, raw_tp_null_args[i].func))
				continue;
			if (raw_tp_null_args[i].mask & (0x1ULL << (arg * 4)))
				info->reg_type |= PTR_MAYBE_NULL;
			/* Is the current arg IS_ERR? */
			if (raw_tp_null_args[i].mask & (0x2ULL << (arg * 4)))
				ptr_err_raw_tp = true;
			break;
		}
		/* If we don't know NULL-ness specification and the tracepoint
		 * is coming from a loadable module, be conservative and mark
		 * argument as PTR_MAYBE_NULL.
		 */
		if (i == ARRAY_SIZE(raw_tp_null_args) && btf_is_module(btf))
			info->reg_type |= PTR_MAYBE_NULL;
	}

	if (tgt_prog) {
		enum bpf_prog_type tgt_type;

		if (tgt_prog->type == BPF_PROG_TYPE_EXT)
			tgt_type = tgt_prog->aux->saved_dst_prog_type;
		else
			tgt_type = tgt_prog->type;

		ret = btf_translate_to_vmlinux(log, btf, t, tgt_type, arg);
		if (ret > 0) {
			info->btf = btf_vmlinux;
			info->btf_id = ret;
			return true;
		} else {
			return false;
		}
	}

	info->btf = btf;
	info->btf_id = t->type;
	t = btf_type_by_id(btf, t->type);

	if (btf_type_is_type_tag(t) && !btf_type_kflag(t)) {
		tag_value = __btf_name_by_offset(btf, t->name_off);
		if (strcmp(tag_value, "user") == 0)
			info->reg_type |= MEM_USER;
		if (strcmp(tag_value, "percpu") == 0)
			info->reg_type |= MEM_PERCPU;
	}

	/* skip modifiers */
	while (btf_type_is_modifier(t)) {
		info->btf_id = t->type;
		t = btf_type_by_id(btf, t->type);
	}
	if (!btf_type_is_struct(t)) {
		bpf_log(log,
			"func '%s' arg%d type %s is not a struct\n",
			tname, arg, btf_type_str(t));
		return false;
	}
	bpf_log(log, "func '%s' arg%d has btf_id %d type %s '%s'\n",
		tname, arg, info->btf_id, btf_type_str(t),
		__btf_name_by_offset(btf, t->name_off));

	/* Perform all checks on the validity of type for this argument, but if
	 * we know it can be IS_ERR at runtime, scrub pointer type and mark as
	 * scalar.
	 */
	if (ptr_err_raw_tp) {
		bpf_log(log, "marking pointer arg%d as scalar as it may encode error", arg);
		info->reg_type = SCALAR_VALUE;
	}
	return true;
}
EXPORT_SYMBOL_GPL(btf_ctx_access);

enum bpf_struct_walk_result {
	/* < 0 error */
	WALK_SCALAR = 0,
	WALK_PTR,
	WALK_PTR_UNTRUSTED,
	WALK_STRUCT,
};

static int btf_struct_walk(struct bpf_verifier_log *log, const struct btf *btf,
			   const struct btf_type *t, int off, int size,
			   u32 *next_btf_id, enum bpf_type_flag *flag,
			   const char **field_name)
{
	u32 i, moff, mtrue_end, msize = 0, total_nelems = 0;
	const struct btf_type *mtype, *elem_type = NULL;
	const struct btf_member *member;
	const char *tname, *mname, *tag_value;
	u32 vlen, elem_id, mid;

again:
	if (btf_type_is_modifier(t))
		t = btf_type_skip_modifiers(btf, t->type, NULL);
	tname = __btf_name_by_offset(btf, t->name_off);
	if (!btf_type_is_struct(t)) {
		bpf_log(log, "Type '%s' is not a struct\n", tname);
		return -EINVAL;
	}

	vlen = btf_type_vlen(t);
	if (BTF_INFO_KIND(t->info) == BTF_KIND_UNION && vlen != 1 && !(*flag & PTR_UNTRUSTED))
		/*
		 * walking unions yields untrusted pointers
		 * with exception of __bpf_md_ptr and other
		 * unions with a single member
		 */
		*flag |= PTR_UNTRUSTED;

	if (off + size > t->size) {
		/* If the last element is a variable size array, we may
		 * need to relax the rule.
		 */
		struct btf_array *array_elem;

		if (vlen == 0)
			goto error;

		member = btf_type_member(t) + vlen - 1;
		mtype = btf_type_skip_modifiers(btf, member->type,
						NULL);
		if (!btf_type_is_array(mtype))
			goto error;

		array_elem = (struct btf_array *)(mtype + 1);
		if (array_elem->nelems != 0)
			goto error;

		moff = __btf_member_bit_offset(t, member) / 8;
		if (off < moff)
			goto error;

		/* allow structure and integer */
		t = btf_type_skip_modifiers(btf, array_elem->type,
					    NULL);

		if (btf_type_is_int(t))
			return WALK_SCALAR;

		if (!btf_type_is_struct(t))
			goto error;

		off = (off - moff) % t->size;
		goto again;

error:
		bpf_log(log, "access beyond struct %s at off %u size %u\n",
			tname, off, size);
		return -EACCES;
	}

	for_each_member(i, t, member) {
		/* offset of the field in bytes */
		moff = __btf_member_bit_offset(t, member) / 8;
		if (off + size <= moff)
			/* won't find anything, field is already too far */
			break;

		if (__btf_member_bitfield_size(t, member)) {
			u32 end_bit = __btf_member_bit_offset(t, member) +
				__btf_member_bitfield_size(t, member);

			/* off <= moff instead of off == moff because clang
			 * does not generate a BTF member for anonymous
			 * bitfield like the ":16" here:
			 * struct {
			 *	int :16;
			 *	int x:8;
			 * };
			 */
			if (off <= moff &&
			    BITS_ROUNDUP_BYTES(end_bit) <= off + size)
				return WALK_SCALAR;

			/* off may be accessing a following member
			 *
			 * or
			 *
			 * Doing partial access at either end of this
			 * bitfield.  Continue on this case also to
			 * treat it as not accessing this bitfield
			 * and eventually error out as field not
			 * found to keep it simple.
			 * It could be relaxed if there was a legit
			 * partial access case later.
			 */
			continue;
		}

		/* In case of "off" is pointing to holes of a struct */
		if (off < moff)
			break;

		/* type of the field */
		mid = member->type;
		mtype = btf_type_by_id(btf, member->type);
		mname = __btf_name_by_offset(btf, member->name_off);

		mtype = __btf_resolve_size(btf, mtype, &msize,
					   &elem_type, &elem_id, &total_nelems,
					   &mid);
		if (IS_ERR(mtype)) {
			bpf_log(log, "field %s doesn't have size\n", mname);
			return -EFAULT;
		}

		mtrue_end = moff + msize;
		if (off >= mtrue_end)
			/* no overlap with member, keep iterating */
			continue;

		if (btf_type_is_array(mtype)) {
			u32 elem_idx;

			/* __btf_resolve_size() above helps to
			 * linearize a multi-dimensional array.
			 *
			 * The logic here is treating an array
			 * in a struct as the following way:
			 *
			 * struct outer {
			 *	struct inner array[2][2];
			 * };
			 *
			 * looks like:
			 *
			 * struct outer {
			 *	struct inner array_elem0;
			 *	struct inner array_elem1;
			 *	struct inner array_elem2;
			 *	struct inner array_elem3;
			 * };
			 *
			 * When accessing outer->array[1][0], it moves
			 * moff to "array_elem2", set mtype to
			 * "struct inner", and msize also becomes
			 * sizeof(struct inner).  Then most of the
			 * remaining logic will fall through without
			 * caring the current member is an array or
			 * not.
			 *
			 * Unlike mtype/msize/moff, mtrue_end does not
			 * change.  The naming difference ("_true") tells
			 * that it is not always corresponding to
			 * the current mtype/msize/moff.
			 * It is the true end of the current
			 * member (i.e. array in this case).  That
			 * will allow an int array to be accessed like
			 * a scratch space,
			 * i.e. allow access beyond the size of
			 *      the array's element as long as it is
			 *      within the mtrue_end boundary.
			 */

			/* skip empty array */
			if (moff == mtrue_end)
				continue;

			msize /= total_nelems;
			elem_idx = (off - moff) / msize;
			moff += elem_idx * msize;
			mtype = elem_type;
			mid = elem_id;
		}

		/* the 'off' we're looking for is either equal to start
		 * of this field or inside of this struct
		 */
		if (btf_type_is_struct(mtype)) {
			/* our field must be inside that union or struct */
			t = mtype;

			/* return if the offset matches the member offset */
			if (off == moff) {
				*next_btf_id = mid;
				return WALK_STRUCT;
			}

			/* adjust offset we're looking for */
			off -= moff;
			goto again;
		}

		if (btf_type_is_ptr(mtype)) {
			const struct btf_type *stype, *t;
			enum bpf_type_flag tmp_flag = 0;
			u32 id;

			if (msize != size || off != moff) {
				bpf_log(log,
					"cannot access ptr member %s with moff %u in struct %s with off %u size %u\n",
					mname, moff, tname, off, size);
				return -EACCES;
			}

			/* check type tag */
			t = btf_type_by_id(btf, mtype->type);
			if (btf_type_is_type_tag(t) && !btf_type_kflag(t)) {
				tag_value = __btf_name_by_offset(btf, t->name_off);
				/* check __user tag */
				if (strcmp(tag_value, "user") == 0)
					tmp_flag = MEM_USER;
				/* check __percpu tag */
				if (strcmp(tag_value, "percpu") == 0)
					tmp_flag = MEM_PERCPU;
				/* check __rcu tag */
				if (strcmp(tag_value, "rcu") == 0)
					tmp_flag = MEM_RCU;
			}

			stype = btf_type_skip_modifiers(btf, mtype->type, &id);
			if (btf_type_is_struct(stype)) {
				*next_btf_id = id;
				*flag |= tmp_flag;
				if (field_name)
					*field_name = mname;
				return WALK_PTR;
			}

			return WALK_PTR_UNTRUSTED;
		}

		/* Allow more flexible access within an int as long as
		 * it is within mtrue_end.
		 * Since mtrue_end could be the end of an array,
		 * that also allows using an array of int as a scratch
		 * space. e.g. skb->cb[].
		 */
		if (off + size > mtrue_end && !(*flag & PTR_UNTRUSTED)) {
			bpf_log(log,
				"access beyond the end of member %s (mend:%u) in struct %s with off %u size %u\n",
				mname, mtrue_end, tname, off, size);
			return -EACCES;
		}

		return WALK_SCALAR;
	}
	bpf_log(log, "struct %s doesn't have field at offset %d\n", tname, off);
	return -EINVAL;
}

int btf_struct_access(struct bpf_verifier_log *log,
		      const struct bpf_reg_state *reg,
		      int off, int size, enum bpf_access_type atype __maybe_unused,
		      u32 *next_btf_id, enum bpf_type_flag *flag,
		      const char **field_name)
{
	const struct btf *btf = reg->btf;
	enum bpf_type_flag tmp_flag = 0;
	const struct btf_type *t;
	u32 id = reg->btf_id;
	int err;

	while (type_is_alloc(reg->type)) {
		struct btf_struct_meta *meta;
		struct btf_record *rec;
		int i;

		meta = btf_find_struct_meta(btf, id);
		if (!meta)
			break;
		rec = meta->record;
		for (i = 0; i < rec->cnt; i++) {
			struct btf_field *field = &rec->fields[i];
			u32 offset = field->offset;
			if (off < offset + field->size && offset < off + size) {
				bpf_log(log,
					"direct access to %s is disallowed\n",
					btf_field_type_name(field->type));
				return -EACCES;
			}
		}
		break;
	}

	t = btf_type_by_id(btf, id);
	do {
		err = btf_struct_walk(log, btf, t, off, size, &id, &tmp_flag, field_name);

		switch (err) {
		case WALK_PTR:
			/* For local types, the destination register cannot
			 * become a pointer again.
			 */
			if (type_is_alloc(reg->type))
				return SCALAR_VALUE;
			/* If we found the pointer or scalar on t+off,
			 * we're done.
			 */
			*next_btf_id = id;
			*flag = tmp_flag;
			return PTR_TO_BTF_ID;
		case WALK_PTR_UNTRUSTED:
			*flag = MEM_RDONLY | PTR_UNTRUSTED;
			return PTR_TO_MEM;
		case WALK_SCALAR:
			return SCALAR_VALUE;
		case WALK_STRUCT:
			/* We found nested struct, so continue the search
			 * by diving in it. At this point the offset is
			 * aligned with the new type, so set it to 0.
			 */
			t = btf_type_by_id(btf, id);
			off = 0;
			break;
		default:
			/* It's either error or unknown return value..
			 * scream and leave.
			 */
			if (WARN_ONCE(err > 0, "unknown btf_struct_walk return value"))
				return -EINVAL;
			return err;
		}
	} while (t);

	return -EINVAL;
}

/* Check that two BTF types, each specified as an BTF object + id, are exactly
 * the same. Trivial ID check is not enough due to module BTFs, because we can
 * end up with two different module BTFs, but IDs point to the common type in
 * vmlinux BTF.
 */
bool btf_types_are_same(const struct btf *btf1, u32 id1,
			const struct btf *btf2, u32 id2)
{
	if (id1 != id2)
		return false;
	if (btf1 == btf2)
		return true;
	return btf_type_by_id(btf1, id1) == btf_type_by_id(btf2, id2);
}

bool btf_struct_ids_match(struct bpf_verifier_log *log,
			  const struct btf *btf, u32 id, int off,
			  const struct btf *need_btf, u32 need_type_id,
			  bool strict)
{
	const struct btf_type *type;
	enum bpf_type_flag flag = 0;
	int err;

	/* Are we already done? */
	if (off == 0 && btf_types_are_same(btf, id, need_btf, need_type_id))
		return true;
	/* In case of strict type match, we do not walk struct, the top level
	 * type match must succeed. When strict is true, off should have already
	 * been 0.
	 */
	if (strict)
		return false;
again:
	type = btf_type_by_id(btf, id);
	if (!type)
		return false;
	err = btf_struct_walk(log, btf, type, off, 1, &id, &flag, NULL);
	if (err != WALK_STRUCT)
		return false;

	/* We found nested struct object. If it matches
	 * the requested ID, we're done. Otherwise let's
	 * continue the search with offset 0 in the new
	 * type.
	 */
	if (!btf_types_are_same(btf, id, need_btf, need_type_id)) {
		off = 0;
		goto again;
	}

	return true;
}

static int __get_type_size(struct btf *btf, u32 btf_id,
			   const struct btf_type **ret_type)
{
	const struct btf_type *t;

	*ret_type = btf_type_by_id(btf, 0);
	if (!btf_id)
		/* void */
		return 0;
	t = btf_type_by_id(btf, btf_id);
	while (t && btf_type_is_modifier(t))
		t = btf_type_by_id(btf, t->type);
	if (!t)
		return -EINVAL;
	*ret_type = t;
	if (btf_type_is_ptr(t))
		/* kernel size of pointer. Not BPF's size of pointer*/
		return sizeof(void *);
	if (btf_type_is_int(t) || btf_is_any_enum(t) || btf_type_is_struct(t))
		return t->size;
	return -EINVAL;
}

static u8 __get_type_fmodel_flags(const struct btf_type *t)
{
	u8 flags = 0;

	if (btf_type_is_struct(t))
		flags |= BTF_FMODEL_STRUCT_ARG;
	if (btf_type_is_signed_int(t))
		flags |= BTF_FMODEL_SIGNED_ARG;

	return flags;
}

int btf_distill_func_proto(struct bpf_verifier_log *log,
			   struct btf *btf,
			   const struct btf_type *func,
			   const char *tname,
			   struct btf_func_model *m)
{
	const struct btf_param *args;
	const struct btf_type *t;
	u32 i, nargs;
	int ret;

	if (!func) {
		/* BTF function prototype doesn't match the verifier types.
		 * Fall back to MAX_BPF_FUNC_REG_ARGS u64 args.
		 */
		for (i = 0; i < MAX_BPF_FUNC_REG_ARGS; i++) {
			m->arg_size[i] = 8;
			m->arg_flags[i] = 0;
		}
		m->ret_size = 8;
		m->ret_flags = 0;
		m->nr_args = MAX_BPF_FUNC_REG_ARGS;
		return 0;
	}
	args = (const struct btf_param *)(func + 1);
	nargs = btf_type_vlen(func);
	if (nargs > MAX_BPF_FUNC_ARGS) {
		bpf_log(log,
			"The function %s has %d arguments. Too many.\n",
			tname, nargs);
		return -EINVAL;
	}
	ret = __get_type_size(btf, func->type, &t);
	if (ret < 0 || btf_type_is_struct(t)) {
		bpf_log(log,
			"The function %s return type %s is unsupported.\n",
			tname, btf_type_str(t));
		return -EINVAL;
	}
	m->ret_size = ret;
	m->ret_flags = __get_type_fmodel_flags(t);

	for (i = 0; i < nargs; i++) {
		if (i == nargs - 1 && args[i].type == 0) {
			bpf_log(log,
				"The function %s with variable args is unsupported.\n",
				tname);
			return -EINVAL;
		}
		ret = __get_type_size(btf, args[i].type, &t);

		/* No support of struct argument size greater than 16 bytes */
		if (ret < 0 || ret > 16) {
			bpf_log(log,
				"The function %s arg%d type %s is unsupported.\n",
				tname, i, btf_type_str(t));
			return -EINVAL;
		}
		if (ret == 0) {
			bpf_log(log,
				"The function %s has malformed void argument.\n",
				tname);
			return -EINVAL;
		}
		m->arg_size[i] = ret;
		m->arg_flags[i] = __get_type_fmodel_flags(t);
	}
	m->nr_args = nargs;
	return 0;
}

/* Compare BTFs of two functions assuming only scalars and pointers to context.
 * t1 points to BTF_KIND_FUNC in btf1
 * t2 points to BTF_KIND_FUNC in btf2
 * Returns:
 * EINVAL - function prototype mismatch
 * EFAULT - verifier bug
 * 0 - 99% match. The last 1% is validated by the verifier.
 */
static int btf_check_func_type_match(struct bpf_verifier_log *log,
				     struct btf *btf1, const struct btf_type *t1,
				     struct btf *btf2, const struct btf_type *t2)
{
	const struct btf_param *args1, *args2;
	const char *fn1, *fn2, *s1, *s2;
	u32 nargs1, nargs2, i;

	fn1 = btf_name_by_offset(btf1, t1->name_off);
	fn2 = btf_name_by_offset(btf2, t2->name_off);

	if (btf_func_linkage(t1) != BTF_FUNC_GLOBAL) {
		bpf_log(log, "%s() is not a global function\n", fn1);
		return -EINVAL;
	}
	if (btf_func_linkage(t2) != BTF_FUNC_GLOBAL) {
		bpf_log(log, "%s() is not a global function\n", fn2);
		return -EINVAL;
	}

	t1 = btf_type_by_id(btf1, t1->type);
	if (!t1 || !btf_type_is_func_proto(t1))
		return -EFAULT;
	t2 = btf_type_by_id(btf2, t2->type);
	if (!t2 || !btf_type_is_func_proto(t2))
		return -EFAULT;

	args1 = (const struct btf_param *)(t1 + 1);
	nargs1 = btf_type_vlen(t1);
	args2 = (const struct btf_param *)(t2 + 1);
	nargs2 = btf_type_vlen(t2);

	if (nargs1 != nargs2) {
		bpf_log(log, "%s() has %d args while %s() has %d args\n",
			fn1, nargs1, fn2, nargs2);
		return -EINVAL;
	}

	t1 = btf_type_skip_modifiers(btf1, t1->type, NULL);
	t2 = btf_type_skip_modifiers(btf2, t2->type, NULL);
	if (t1->info != t2->info) {
		bpf_log(log,
			"Return type %s of %s() doesn't match type %s of %s()\n",
			btf_type_str(t1), fn1,
			btf_type_str(t2), fn2);
		return -EINVAL;
	}

	for (i = 0; i < nargs1; i++) {
		t1 = btf_type_skip_modifiers(btf1, args1[i].type, NULL);
		t2 = btf_type_skip_modifiers(btf2, args2[i].type, NULL);

		if (t1->info != t2->info) {
			bpf_log(log, "arg%d in %s() is %s while %s() has %s\n",
				i, fn1, btf_type_str(t1),
				fn2, btf_type_str(t2));
			return -EINVAL;
		}
		if (btf_type_has_size(t1) && t1->size != t2->size) {
			bpf_log(log,
				"arg%d in %s() has size %d while %s() has %d\n",
				i, fn1, t1->size,
				fn2, t2->size);
			return -EINVAL;
		}

		/* global functions are validated with scalars and pointers
		 * to context only. And only global functions can be replaced.
		 * Hence type check only those types.
		 */
		if (btf_type_is_int(t1) || btf_is_any_enum(t1))
			continue;
		if (!btf_type_is_ptr(t1)) {
			bpf_log(log,
				"arg%d in %s() has unrecognized type\n",
				i, fn1);
			return -EINVAL;
		}
		t1 = btf_type_skip_modifiers(btf1, t1->type, NULL);
		t2 = btf_type_skip_modifiers(btf2, t2->type, NULL);
		if (!btf_type_is_struct(t1)) {
			bpf_log(log,
				"arg%d in %s() is not a pointer to context\n",
				i, fn1);
			return -EINVAL;
		}
		if (!btf_type_is_struct(t2)) {
			bpf_log(log,
				"arg%d in %s() is not a pointer to context\n",
				i, fn2);
			return -EINVAL;
		}
		/* This is an optional check to make program writing easier.
		 * Compare names of structs and report an error to the user.
		 * btf_prepare_func_args() already checked that t2 struct
		 * is a context type. btf_prepare_func_args() will check
		 * later that t1 struct is a context type as well.
		 */
		s1 = btf_name_by_offset(btf1, t1->name_off);
		s2 = btf_name_by_offset(btf2, t2->name_off);
		if (strcmp(s1, s2)) {
			bpf_log(log,
				"arg%d %s(struct %s *) doesn't match %s(struct %s *)\n",
				i, fn1, s1, fn2, s2);
			return -EINVAL;
		}
	}
	return 0;
}

/* Compare BTFs of given program with BTF of target program */
int btf_check_type_match(struct bpf_verifier_log *log, const struct bpf_prog *prog,
			 struct btf *btf2, const struct btf_type *t2)
{
	struct btf *btf1 = prog->aux->btf;
	const struct btf_type *t1;
	u32 btf_id = 0;

	if (!prog->aux->func_info) {
		bpf_log(log, "Program extension requires BTF\n");
		return -EINVAL;
	}

	btf_id = prog->aux->func_info[0].type_id;
	if (!btf_id)
		return -EFAULT;

	t1 = btf_type_by_id(btf1, btf_id);
	if (!t1 || !btf_type_is_func(t1))
		return -EFAULT;

	return btf_check_func_type_match(log, btf1, t1, btf2, t2);
}

static bool btf_is_dynptr_ptr(const struct btf *btf, const struct btf_type *t)
{
	const char *name;

	t = btf_type_by_id(btf, t->type); /* skip PTR */

	while (btf_type_is_modifier(t))
		t = btf_type_by_id(btf, t->type);

	/* allow either struct or struct forward declaration */
	if (btf_type_is_struct(t) ||
	    (btf_type_is_fwd(t) && btf_type_kflag(t) == 0)) {
		name = btf_str_by_offset(btf, t->name_off);
		return name && strcmp(name, "bpf_dynptr") == 0;
	}

	return false;
}

struct bpf_cand_cache {
	const char *name;
	u32 name_len;
	u16 kind;
	u16 cnt;
	struct {
		const struct btf *btf;
		u32 id;
	} cands[];
};

static DEFINE_MUTEX(cand_cache_mutex);

static struct bpf_cand_cache *
bpf_core_find_cands(struct bpf_core_ctx *ctx, u32 local_type_id);

static int btf_get_ptr_to_btf_id(struct bpf_verifier_log *log, int arg_idx,
				 const struct btf *btf, const struct btf_type *t)
{
	struct bpf_cand_cache *cc;
	struct bpf_core_ctx ctx = {
		.btf = btf,
		.log = log,
	};
	u32 kern_type_id, type_id;
	int err = 0;

	/* skip PTR and modifiers */
	type_id = t->type;
	t = btf_type_by_id(btf, t->type);
	while (btf_type_is_modifier(t)) {
		type_id = t->type;
		t = btf_type_by_id(btf, t->type);
	}

	mutex_lock(&cand_cache_mutex);
	cc = bpf_core_find_cands(&ctx, type_id);
	if (IS_ERR(cc)) {
		err = PTR_ERR(cc);
		bpf_log(log, "arg#%d reference type('%s %s') candidate matching error: %d\n",
			arg_idx, btf_type_str(t), __btf_name_by_offset(btf, t->name_off),
			err);
		goto cand_cache_unlock;
	}
	if (cc->cnt != 1) {
		bpf_log(log, "arg#%d reference type('%s %s') %s\n",
			arg_idx, btf_type_str(t), __btf_name_by_offset(btf, t->name_off),
			cc->cnt == 0 ? "has no matches" : "is ambiguous");
		err = cc->cnt == 0 ? -ENOENT : -ESRCH;
		goto cand_cache_unlock;
	}
	if (btf_is_module(cc->cands[0].btf)) {
		bpf_log(log, "arg#%d reference type('%s %s') points to kernel module type (unsupported)\n",
			arg_idx, btf_type_str(t), __btf_name_by_offset(btf, t->name_off));
		err = -EOPNOTSUPP;
		goto cand_cache_unlock;
	}
	kern_type_id = cc->cands[0].id;

cand_cache_unlock:
	mutex_unlock(&cand_cache_mutex);
	if (err)
		return err;

	return kern_type_id;
}

enum btf_arg_tag {
	ARG_TAG_CTX	  = BIT_ULL(0),
	ARG_TAG_NONNULL   = BIT_ULL(1),
	ARG_TAG_TRUSTED   = BIT_ULL(2),
	ARG_TAG_UNTRUSTED = BIT_ULL(3),
	ARG_TAG_NULLABLE  = BIT_ULL(4),
	ARG_TAG_ARENA	  = BIT_ULL(5),
};

/* Process BTF of a function to produce high-level expectation of function
 * arguments (like ARG_PTR_TO_CTX, or ARG_PTR_TO_MEM, etc). This information
 * is cached in subprog info for reuse.
 * Returns:
 * EFAULT - there is a verifier bug. Abort verification.
 * EINVAL - cannot convert BTF.
 * 0 - Successfully processed BTF and constructed argument expectations.
 */
int btf_prepare_func_args(struct bpf_verifier_env *env, int subprog)
{
	bool is_global = subprog_aux(env, subprog)->linkage == BTF_FUNC_GLOBAL;
	struct bpf_subprog_info *sub = subprog_info(env, subprog);
	struct bpf_verifier_log *log = &env->log;
	struct bpf_prog *prog = env->prog;
	enum bpf_prog_type prog_type = prog->type;
	struct btf *btf = prog->aux->btf;
	const struct btf_param *args;
	const struct btf_type *t, *ref_t, *fn_t;
	u32 i, nargs, btf_id;
	const char *tname;

	if (sub->args_cached)
		return 0;

	if (!prog->aux->func_info) {
		verifier_bug(env, "func_info undefined");
		return -EFAULT;
	}

	btf_id = prog->aux->func_info[subprog].type_id;
	if (!btf_id) {
		if (!is_global) /* not fatal for static funcs */
			return -EINVAL;
		bpf_log(log, "Global functions need valid BTF\n");
		return -EFAULT;
	}

	fn_t = btf_type_by_id(btf, btf_id);
	if (!fn_t || !btf_type_is_func(fn_t)) {
		/* These checks were already done by the verifier while loading
		 * struct bpf_func_info
		 */
		bpf_log(log, "BTF of func#%d doesn't point to KIND_FUNC\n",
			subprog);
		return -EFAULT;
	}
	tname = btf_name_by_offset(btf, fn_t->name_off);

	if (prog->aux->func_info_aux[subprog].unreliable) {
		verifier_bug(env, "unreliable BTF for function %s()", tname);
		return -EFAULT;
	}
	if (prog_type == BPF_PROG_TYPE_EXT)
		prog_type = prog->aux->dst_prog->type;

	t = btf_type_by_id(btf, fn_t->type);
	if (!t || !btf_type_is_func_proto(t)) {
		bpf_log(log, "Invalid type of function %s()\n", tname);
		return -EFAULT;
	}
	args = (const struct btf_param *)(t + 1);
	nargs = btf_type_vlen(t);
	if (nargs > MAX_BPF_FUNC_REG_ARGS) {
		if (!is_global)
			return -EINVAL;
		bpf_log(log, "Global function %s() with %d > %d args. Buggy compiler.\n",
			tname, nargs, MAX_BPF_FUNC_REG_ARGS);
		return -EINVAL;
	}
	/* check that function is void or returns int, exception cb also requires this */
	t = btf_type_by_id(btf, t->type);
	while (btf_type_is_modifier(t))
		t = btf_type_by_id(btf, t->type);
	if (!btf_type_is_void(t) && !btf_type_is_int(t) && !btf_is_any_enum(t)) {
		if (!is_global)
			return -EINVAL;
		bpf_log(log,
			"Global function %s() return value not void or scalar. "
			"Only those are supported.\n",
			tname);
		return -EINVAL;
	}

	/* Convert BTF function arguments into verifier types.
	 * Only PTR_TO_CTX and SCALAR are supported atm.
	 */
	for (i = 0; i < nargs; i++) {
		u32 tags = 0;
		int id = btf_named_start_id(btf, false) - 1;

		/* 'arg:<tag>' decl_tag takes precedence over derivation of
		 * register type from BTF type itself
		 */
		while ((id = btf_find_next_decl_tag(btf, fn_t, i, "arg:", id)) > 0) {
			const struct btf_type *tag_t = btf_type_by_id(btf, id);
			const char *tag = __btf_name_by_offset(btf, tag_t->name_off) + 4;

			/* disallow arg tags in static subprogs */
			if (!is_global) {
				bpf_log(log, "arg#%d type tag is not supported in static functions\n", i);
				return -EOPNOTSUPP;
			}

			if (strcmp(tag, "ctx") == 0) {
				tags |= ARG_TAG_CTX;
			} else if (strcmp(tag, "trusted") == 0) {
				tags |= ARG_TAG_TRUSTED;
			} else if (strcmp(tag, "untrusted") == 0) {
				tags |= ARG_TAG_UNTRUSTED;
			} else if (strcmp(tag, "nonnull") == 0) {
				tags |= ARG_TAG_NONNULL;
			} else if (strcmp(tag, "nullable") == 0) {
				tags |= ARG_TAG_NULLABLE;
			} else if (strcmp(tag, "arena") == 0) {
				tags |= ARG_TAG_ARENA;
			} else {
				bpf_log(log, "arg#%d has unsupported set of tags\n", i);
				return -EOPNOTSUPP;
			}
		}
		if (id != -ENOENT) {
			bpf_log(log, "arg#%d type tag fetching failure: %d\n", i, id);
			return id;
		}

		t = btf_type_by_id(btf, args[i].type);
		while (btf_type_is_modifier(t))
			t = btf_type_by_id(btf, t->type);
		if (!btf_type_is_ptr(t))
			goto skip_pointer;

		if ((tags & ARG_TAG_CTX) || btf_is_prog_ctx_type(log, btf, t, prog_type, i)) {
			if (tags & ~ARG_TAG_CTX) {
				bpf_log(log, "arg#%d has invalid combination of tags\n", i);
				return -EINVAL;
			}
			if ((tags & ARG_TAG_CTX) &&
			    btf_validate_prog_ctx_type(log, btf, t, i, prog_type,
						       prog->expected_attach_type))
				return -EINVAL;
			sub->args[i].arg_type = ARG_PTR_TO_CTX;
			continue;
		}
		if (btf_is_dynptr_ptr(btf, t)) {
			if (tags) {
				bpf_log(log, "arg#%d has invalid combination of tags\n", i);
				return -EINVAL;
			}
			sub->args[i].arg_type = ARG_PTR_TO_DYNPTR | MEM_RDONLY;
			continue;
		}
		if (tags & ARG_TAG_TRUSTED) {
			int kern_type_id;

			if (tags & ARG_TAG_NONNULL) {
				bpf_log(log, "arg#%d has invalid combination of tags\n", i);
				return -EINVAL;
			}

			kern_type_id = btf_get_ptr_to_btf_id(log, i, btf, t);
			if (kern_type_id < 0)
				return kern_type_id;

			sub->args[i].arg_type = ARG_PTR_TO_BTF_ID | PTR_TRUSTED;
			if (tags & ARG_TAG_NULLABLE)
				sub->args[i].arg_type |= PTR_MAYBE_NULL;
			sub->args[i].btf_id = kern_type_id;
			continue;
		}
		if (tags & ARG_TAG_UNTRUSTED) {
			struct btf *vmlinux_btf;
			int kern_type_id;

			if (tags & ~ARG_TAG_UNTRUSTED) {
				bpf_log(log, "arg#%d untrusted cannot be combined with any other tags\n", i);
				return -EINVAL;
			}

			ref_t = btf_type_skip_modifiers(btf, t->type, NULL);
			if (btf_type_is_void(ref_t) || btf_type_is_primitive(ref_t)) {
				sub->args[i].arg_type = ARG_PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED;
				sub->args[i].mem_size = 0;
				continue;
			}

			kern_type_id = btf_get_ptr_to_btf_id(log, i, btf, t);
			if (kern_type_id < 0)
				return kern_type_id;

			vmlinux_btf = bpf_get_btf_vmlinux();
			ref_t = btf_type_by_id(vmlinux_btf, kern_type_id);
			if (!btf_type_is_struct(ref_t)) {
				tname = __btf_name_by_offset(vmlinux_btf, t->name_off);
				bpf_log(log, "arg#%d has type %s '%s', but only struct or primitive types are allowed\n",
					i, btf_type_str(ref_t), tname);
				return -EINVAL;
			}
			sub->args[i].arg_type = ARG_PTR_TO_BTF_ID | PTR_UNTRUSTED;
			sub->args[i].btf_id = kern_type_id;
			continue;
		}
		if (tags & ARG_TAG_ARENA) {
			if (tags & ~ARG_TAG_ARENA) {
				bpf_log(log, "arg#%d arena cannot be combined with any other tags\n", i);
				return -EINVAL;
			}
			sub->args[i].arg_type = ARG_PTR_TO_ARENA;
			continue;
		}
		if (is_global) { /* generic user data pointer */
			u32 mem_size;

			if (tags & ARG_TAG_NULLABLE) {
				bpf_log(log, "arg#%d has invalid combination of tags\n", i);
				return -EINVAL;
			}

			t = btf_type_skip_modifiers(btf, t->type, NULL);
			ref_t = btf_resolve_size(btf, t, &mem_size);
			if (IS_ERR(ref_t)) {
				bpf_log(log, "arg#%d reference type('%s %s') size cannot be determined: %ld\n",
					i, btf_type_str(t), btf_name_by_offset(btf, t->name_off),
					PTR_ERR(ref_t));
				return -EINVAL;
			}

			sub->args[i].arg_type = ARG_PTR_TO_MEM | PTR_MAYBE_NULL;
			if (tags & ARG_TAG_NONNULL)
				sub->args[i].arg_type &= ~PTR_MAYBE_NULL;
			sub->args[i].mem_size = mem_size;
			continue;
		}

skip_pointer:
		if (tags) {
			bpf_log(log, "arg#%d has pointer tag, but is not a pointer type\n", i);
			return -EINVAL;
		}
		if (btf_type_is_int(t) || btf_is_any_enum(t)) {
			sub->args[i].arg_type = ARG_ANYTHING;
			continue;
		}
		if (!is_global)
			return -EINVAL;
		bpf_log(log, "Arg#%d type %s in %s() is not supported yet.\n",
			i, btf_type_str(t), tname);
		return -EINVAL;
	}

	sub->arg_cnt = nargs;
	sub->args_cached = true;

	return 0;
}
#ifdef CONFIG_PROC_FS
static void bpf_btf_show_fdinfo(struct seq_file *m, struct file *filp)
{
	const struct btf *btf = filp->private_data;

	seq_printf(m, "btf_id:\t%u\n", READ_ONCE(btf->id));
}
#endif

static int btf_release(struct inode *inode, struct file *filp)
{
	btf_put(filp->private_data);
	return 0;
}

const struct file_operations btf_fops = {
#ifdef CONFIG_PROC_FS
	.show_fdinfo	= bpf_btf_show_fdinfo,
#endif
	.release	= btf_release,
};

static int __btf_new_fd(struct btf *btf)
{
	return anon_inode_getfd("btf", &btf_fops, btf, O_RDONLY | O_CLOEXEC);
}

int btf_new_fd(const union bpf_attr *attr, bpfptr_t uattr, u32 uattr_size)
{
	struct btf *btf;
	int ret;

	btf = btf_parse(attr, uattr, uattr_size);
	if (IS_ERR(btf))
		return PTR_ERR(btf);

	ret = btf_alloc_id(btf);
	if (ret) {
		btf_free(btf);
		return ret;
	}

	/*
	 * The BTF ID is published to the userspace.
	 * All BTF free must go through call_rcu() from
	 * now on (i.e. free by calling btf_put()).
	 */

	ret = __btf_new_fd(btf);
	if (ret < 0)
		btf_put(btf);

	return ret;
}

struct btf *btf_get_by_fd(int fd)
{
	struct btf *btf;
	CLASS(fd, f)(fd);

	btf = __btf_get_by_fd(f);
	if (!IS_ERR(btf))
		refcount_inc(&btf->refcnt);

	return btf;
}

int btf_get_info_by_fd(const struct btf *btf,
		       const union bpf_attr *attr,
		       union bpf_attr __user *uattr)
{
	struct bpf_btf_info __user *uinfo;
	struct bpf_btf_info info;
	u32 info_copy, btf_copy;
	void __user *ubtf;
	char __user *uname;
	u32 uinfo_len, uname_len, name_len;
	int ret = 0;

	uinfo = u64_to_user_ptr(attr->info.info);
	uinfo_len = attr->info.info_len;

	info_copy = min_t(u32, uinfo_len, sizeof(info));
	memset(&info, 0, sizeof(info));
	if (copy_from_user(&info, uinfo, info_copy))
		return -EFAULT;

	info.id = READ_ONCE(btf->id);
	ubtf = u64_to_user_ptr(info.btf);
	btf_copy = min_t(u32, btf->data_size, info.btf_size);
	if (copy_to_user(ubtf, btf->data, btf_copy))
		return -EFAULT;
	info.btf_size = btf->data_size;

	info.kernel_btf = btf->kernel_btf;

	uname = u64_to_user_ptr(info.name);
	uname_len = info.name_len;
	if (!uname ^ !uname_len)
		return -EINVAL;

	name_len = strlen(btf->name);
	info.name_len = name_len;

	if (uname) {
		if (uname_len >= name_len + 1) {
			if (copy_to_user(uname, btf->name, name_len + 1))
				return -EFAULT;
		} else {
			char zero = '\0';

			if (copy_to_user(uname, btf->name, uname_len - 1))
				return -EFAULT;
			if (put_user(zero, uname + uname_len - 1))
				return -EFAULT;
			/* let user-space know about too short buffer */
			ret = -ENOSPC;
		}
	}

	if (copy_to_user(uinfo, &info, info_copy) ||
	    put_user(info_copy, &uattr->info.info_len))
		return -EFAULT;

	return ret;
}

int btf_get_fd_by_id(u32 id)
{
	struct btf *btf;
	int fd;

	rcu_read_lock();
	btf = idr_find(&btf_idr, id);
	if (!btf || !refcount_inc_not_zero(&btf->refcnt))
		btf = ERR_PTR(-ENOENT);
	rcu_read_unlock();

	if (IS_ERR(btf))
		return PTR_ERR(btf);

	fd = __btf_new_fd(btf);
	if (fd < 0)
		btf_put(btf);

	return fd;
}

u32 btf_obj_id(const struct btf *btf)
{
	return READ_ONCE(btf->id);
}
enum {
	BTF_MODULE_F_LIVE = (1 << 0),
};

#ifdef CONFIG_DEBUG_INFO_BTF_MODULES
struct btf_module {
	struct list_head list;
	struct module *module;
	struct btf *btf;
	struct bin_attribute *sysfs_attr;
	int flags;
};

static LIST_HEAD(btf_modules);
static DEFINE_MUTEX(btf_module_mutex);

static void purge_cand_cache(struct btf *btf);

static int btf_module_notify(struct notifier_block *nb, unsigned long op,
			     void *module)
{
	struct btf_module *btf_mod, *tmp;
	struct module *mod = module;
	struct btf *btf;
	int err = 0;

	if (mod->btf_data_size == 0 ||
	    (op != MODULE_STATE_COMING && op != MODULE_STATE_LIVE &&
	     op != MODULE_STATE_GOING))
		goto out;

	switch (op) {
	case MODULE_STATE_COMING:
		btf_mod = kzalloc_obj(*btf_mod);
		if (!btf_mod) {
			err = -ENOMEM;
			goto out;
		}
		btf = btf_parse_module(mod->name, mod->btf_data, mod->btf_data_size,
				       mod->btf_base_data, mod->btf_base_data_size);
		if (IS_ERR(btf)) {
			kfree(btf_mod);
			if (!IS_ENABLED(CONFIG_MODULE_ALLOW_BTF_MISMATCH)) {
				pr_warn("failed to validate module [%s] BTF: %ld\n",
					mod->name, PTR_ERR(btf));
				err = PTR_ERR(btf);
			} else {
				pr_warn_once("Kernel module BTF mismatch detected, BTF debug info may be unavailable for some modules\n");
			}
			goto out;
		}
		err = btf_alloc_id(btf);
		if (err) {
			btf_free(btf);
			kfree(btf_mod);
			goto out;
		}

		purge_cand_cache(NULL);
		mutex_lock(&btf_module_mutex);
		btf_mod->module = module;
		btf_mod->btf = btf;
		list_add(&btf_mod->list, &btf_modules);
		mutex_unlock(&btf_module_mutex);

		if (IS_ENABLED(CONFIG_SYSFS)) {
			struct bin_attribute *attr;

			attr = kzalloc_obj(*attr);
			if (!attr)
				goto out;

			sysfs_bin_attr_init(attr);
			attr->attr.name = btf->name;
			attr->attr.mode = 0444;
			attr->size = btf->data_size;
			attr->private = btf->data;
			attr->read = sysfs_bin_attr_simple_read;

			err = sysfs_create_bin_file(btf_kobj, attr);
			if (err) {
				pr_warn("failed to register module [%s] BTF in sysfs: %d\n",
					mod->name, err);
				kfree(attr);
				err = 0;
				goto out;
			}

			btf_mod->sysfs_attr = attr;
		}

		break;
	case MODULE_STATE_LIVE:
		mutex_lock(&btf_module_mutex);
		list_for_each_entry_safe(btf_mod, tmp, &btf_modules, list) {
			if (btf_mod->module != module)
				continue;

			btf_mod->flags |= BTF_MODULE_F_LIVE;
			break;
		}
		mutex_unlock(&btf_module_mutex);
		break;
	case MODULE_STATE_GOING:
		mutex_lock(&btf_module_mutex);
		list_for_each_entry_safe(btf_mod, tmp, &btf_modules, list) {
			if (btf_mod->module != module)
				continue;

			/*
			 * For modules, we do the freeing of BTF IDR as soon as
			 * module goes away to disable BTF discovery, since the
			 * btf_try_get_module() on such BTFs will fail. This may
			 * be called again on btf_put(), but it's ok to do so.
			 */
			btf_free_id(btf_mod->btf);
			list_del(&btf_mod->list);
			if (btf_mod->sysfs_attr)
				sysfs_remove_bin_file(btf_kobj, btf_mod->sysfs_attr);
			purge_cand_cache(btf_mod->btf);
			btf_put(btf_mod->btf);
			kfree(btf_mod->sysfs_attr);
			kfree(btf_mod);
			break;
		}
		mutex_unlock(&btf_module_mutex);
		break;
	}
out:
	return notifier_from_errno(err);
}

static struct notifier_block btf_module_nb = {
	.notifier_call = btf_module_notify,
};

static int __init btf_module_init(void)
{
	register_module_notifier(&btf_module_nb);
	return 0;
}

fs_initcall(btf_module_init);
#endif /* CONFIG_DEBUG_INFO_BTF_MODULES */

struct module *btf_try_get_module(const struct btf *btf)
{
	struct module *res = NULL;
#ifdef CONFIG_DEBUG_INFO_BTF_MODULES
	struct btf_module *btf_mod, *tmp;

	mutex_lock(&btf_module_mutex);
	list_for_each_entry_safe(btf_mod, tmp, &btf_modules, list) {
		if (btf_mod->btf != btf)
			continue;

		/* We must only consider module whose __init routine has
		 * finished, hence we must check for BTF_MODULE_F_LIVE flag,
		 * which is set from the notifier callback for
		 * MODULE_STATE_LIVE.
		 */
		if ((btf_mod->flags & BTF_MODULE_F_LIVE) && try_module_get(btf_mod->module))
			res = btf_mod->module;

		break;
	}
	mutex_unlock(&btf_module_mutex);
#endif

	return res;
}

/* Returns struct btf corresponding to the struct module.
 * This function can return NULL or ERR_PTR.
 */
static struct btf *btf_get_module_btf(const struct module *module)
{
#ifdef CONFIG_DEBUG_INFO_BTF_MODULES
	struct btf_module *btf_mod, *tmp;
#endif
	struct btf *btf = NULL;

	if (!module) {
		btf = bpf_get_btf_vmlinux();
		if (!IS_ERR_OR_NULL(btf))
			btf_get(btf);
		return btf;
	}

#ifdef CONFIG_DEBUG_INFO_BTF_MODULES
	mutex_lock(&btf_module_mutex);
	list_for_each_entry_safe(btf_mod, tmp, &btf_modules, list) {
		if (btf_mod->module != module)
			continue;

		btf_get(btf_mod->btf);
		btf = btf_mod->btf;
		break;
	}
	mutex_unlock(&btf_module_mutex);
#endif

	return btf;
}

static int check_btf_kconfigs(const struct module *module, const char *feature)
{
	if (!module && IS_ENABLED(CONFIG_DEBUG_INFO_BTF)) {
		pr_err("missing vmlinux BTF, cannot register %s\n", feature);
		return -ENOENT;
	}
	if (module && IS_ENABLED(CONFIG_DEBUG_INFO_BTF_MODULES))
		pr_warn("missing module BTF, cannot register %s\n", feature);
	return 0;
}

BPF_CALL_4(bpf_btf_find_by_name_kind, char *, name, int, name_sz, u32, kind, int, flags)
{
	struct btf *btf = NULL;
	int btf_obj_fd = 0;
	long ret;

	if (flags)
		return -EINVAL;

	if (name_sz <= 1 || name[name_sz - 1])
		return -EINVAL;

	ret = bpf_find_btf_id(name, kind, &btf);
	if (ret > 0 && btf_is_module(btf)) {
		btf_obj_fd = __btf_new_fd(btf);
		if (btf_obj_fd < 0) {
			btf_put(btf);
			return btf_obj_fd;
		}
		return ret | (((u64)btf_obj_fd) << 32);
	}
	if (ret > 0)
		btf_put(btf);
	return ret;
}

const struct bpf_func_proto bpf_btf_find_by_name_kind_proto = {
	.func		= bpf_btf_find_by_name_kind,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg2_type	= ARG_CONST_SIZE,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};

BTF_ID_LIST_GLOBAL(btf_tracing_ids, MAX_BTF_TRACING_TYPE)
#define BTF_TRACING_TYPE(name, type) BTF_ID(struct, type)
BTF_TRACING_TYPE_xxx
#undef BTF_TRACING_TYPE

/* Validate well-formedness of iter argument type.
 * On success, return positive BTF ID of iter state's STRUCT type.
 * On error, negative error is returned.
 */
int btf_check_iter_arg(struct btf *btf, const struct btf_type *func, int arg_idx)
{
	const struct btf_param *arg;
	const struct btf_type *t;
	const char *name;
	int btf_id;

	if (btf_type_vlen(func) <= arg_idx)
		return -EINVAL;

	arg = &btf_params(func)[arg_idx];
	t = btf_type_skip_modifiers(btf, arg->type, NULL);
	if (!t || !btf_type_is_ptr(t))
		return -EINVAL;
	t = btf_type_skip_modifiers(btf, t->type, &btf_id);
	if (!t || !__btf_type_is_struct(t))
		return -EINVAL;

	name = btf_name_by_offset(btf, t->name_off);
	if (!name || strncmp(name, ITER_PREFIX, sizeof(ITER_PREFIX) - 1))
		return -EINVAL;

	return btf_id;
}

static int btf_check_iter_kfuncs(struct btf *btf, const char *func_name,
				 const struct btf_type *func, u32 func_flags)
{
	u32 flags = func_flags & (KF_ITER_NEW | KF_ITER_NEXT | KF_ITER_DESTROY);
	const char *sfx, *iter_name;
	const struct btf_type *t;
	char exp_name[128];
	u32 nr_args;
	int btf_id;

	/* exactly one of KF_ITER_{NEW,NEXT,DESTROY} can be set */
	if (!flags || (flags & (flags - 1)))
		return -EINVAL;

	/* any BPF iter kfunc should have `struct bpf_iter_<type> *` first arg */
	nr_args = btf_type_vlen(func);
	if (nr_args < 1)
		return -EINVAL;

	btf_id = btf_check_iter_arg(btf, func, 0);
	if (btf_id < 0)
		return btf_id;

	/* sizeof(struct bpf_iter_<type>) should be a multiple of 8 to
	 * fit nicely in stack slots
	 */
	t = btf_type_by_id(btf, btf_id);
	if (t->size == 0 || (t->size % 8))
		return -EINVAL;

	/* validate bpf_iter_<type>_{new,next,destroy}(struct bpf_iter_<type> *)
	 * naming pattern
	 */
	iter_name = btf_name_by_offset(btf, t->name_off) + sizeof(ITER_PREFIX) - 1;
	if (flags & KF_ITER_NEW)
		sfx = "new";
	else if (flags & KF_ITER_NEXT)
		sfx = "next";
	else /* (flags & KF_ITER_DESTROY) */
		sfx = "destroy";

	snprintf(exp_name, sizeof(exp_name), "bpf_iter_%s_%s", iter_name, sfx);
	if (strcmp(func_name, exp_name))
		return -EINVAL;

	/* only iter constructor should have extra arguments */
	if (!(flags & KF_ITER_NEW) && nr_args != 1)
		return -EINVAL;

	if (flags & KF_ITER_NEXT) {
		/* bpf_iter_<type>_next() should return pointer */
		t = btf_type_skip_modifiers(btf, func->type, NULL);
		if (!t || !btf_type_is_ptr(t))
			return -EINVAL;
	}

	if (flags & KF_ITER_DESTROY) {
		/* bpf_iter_<type>_destroy() should return void */
		t = btf_type_by_id(btf, func->type);
		if (!t || !btf_type_is_void(t))
			return -EINVAL;
	}

	return 0;
}

static int btf_check_kfunc_protos(struct btf *btf, u32 func_id, u32 func_flags)
{
	const struct btf_type *func;
	const char *func_name;
	int err;

	/* any kfunc should be FUNC -> FUNC_PROTO */
	func = btf_type_by_id(btf, func_id);
	if (!func || !btf_type_is_func(func))
		return -EINVAL;

	/* sanity check kfunc name */
	func_name = btf_name_by_offset(btf, func->name_off);
	if (!func_name || !func_name[0])
		return -EINVAL;

	func = btf_type_by_id(btf, func->type);
	if (!func || !btf_type_is_func_proto(func))
		return -EINVAL;

	if (func_flags & (KF_ITER_NEW | KF_ITER_NEXT | KF_ITER_DESTROY)) {
		err = btf_check_iter_kfuncs(btf, func_name, func, func_flags);
		if (err)
			return err;
	}

	return 0;
}

/* Kernel Function (kfunc) BTF ID set registration API */

static int btf_populate_kfunc_set(struct btf *btf, enum btf_kfunc_hook hook,
				  const struct btf_kfunc_id_set *kset)
{
	struct btf_kfunc_hook_filter *hook_filter;
	struct btf_id_set8 *add_set = kset->set;
	bool vmlinux_set = !btf_is_module(btf);
	bool add_filter = !!kset->filter;
	struct btf_kfunc_set_tab *tab;
	struct btf_id_set8 *set;
	u32 set_cnt, i;
	int ret;

	if (hook >= BTF_KFUNC_HOOK_MAX) {
		ret = -EINVAL;
		goto end;
	}

	if (!add_set->cnt)
		return 0;

	tab = btf->kfunc_set_tab;

	if (tab && add_filter) {
		u32 i;

		hook_filter = &tab->hook_filters[hook];
		for (i = 0; i < hook_filter->nr_filters; i++) {
			if (hook_filter->filters[i] == kset->filter) {
				add_filter = false;
				break;
			}
		}

		if (add_filter && hook_filter->nr_filters == BTF_KFUNC_FILTER_MAX_CNT) {
			ret = -E2BIG;
			goto end;
		}
	}

	if (!tab) {
		tab = kzalloc_obj(*tab, GFP_KERNEL | __GFP_NOWARN);
		if (!tab)
			return -ENOMEM;
		btf->kfunc_set_tab = tab;
	}

	set = tab->sets[hook];
	/* Warn when register_btf_kfunc_id_set is called twice for the same hook
	 * for module sets.
	 */
	if (WARN_ON_ONCE(set && !vmlinux_set)) {
		ret = -EINVAL;
		goto end;
	}

	/* In case of vmlinux sets, there may be more than one set being
	 * registered per hook. To create a unified set, we allocate a new set
	 * and concatenate all individual sets being registered. While each set
	 * is individually sorted, they may become unsorted when concatenated,
	 * hence re-sorting the final set again is required to make binary
	 * searching the set using btf_id_set8_contains function work.
	 *
	 * For module sets, we need to allocate as we may need to relocate
	 * BTF ids.
	 */
	set_cnt = set ? set->cnt : 0;

	if (set_cnt > U32_MAX - add_set->cnt) {
		ret = -EOVERFLOW;
		goto end;
	}

	if (set_cnt + add_set->cnt > BTF_KFUNC_SET_MAX_CNT) {
		ret = -E2BIG;
		goto end;
	}

	/* Grow set */
	set = krealloc(tab->sets[hook],
		       struct_size(set, pairs, set_cnt + add_set->cnt),
		       GFP_KERNEL | __GFP_NOWARN);
	if (!set) {
		ret = -ENOMEM;
		goto end;
	}

	/* For newly allocated set, initialize set->cnt to 0 */
	if (!tab->sets[hook])
		set->cnt = 0;
	tab->sets[hook] = set;

	/* Concatenate the two sets */
	memcpy(set->pairs + set->cnt, add_set->pairs, add_set->cnt * sizeof(set->pairs[0]));
	/* Now that the set is copied, update with relocated BTF ids */
	for (i = set->cnt; i < set->cnt + add_set->cnt; i++)
		set->pairs[i].id = btf_relocate_id(btf, set->pairs[i].id);

	set->cnt += add_set->cnt;

	sort(set->pairs, set->cnt, sizeof(set->pairs[0]), btf_id_cmp_func, NULL);

	if (add_filter) {
		hook_filter = &tab->hook_filters[hook];
		hook_filter->filters[hook_filter->nr_filters++] = kset->filter;
	}
	return 0;
end:
	btf_free_kfunc_set_tab(btf);
	return ret;
}

static u32 *btf_kfunc_id_set_contains(const struct btf *btf,
				      enum btf_kfunc_hook hook,
				      u32 kfunc_btf_id)
{
	struct btf_id_set8 *set;
	u32 *id;

	if (hook >= BTF_KFUNC_HOOK_MAX)
		return NULL;
	if (!btf->kfunc_set_tab)
		return NULL;
	set = btf->kfunc_set_tab->sets[hook];
	if (!set)
		return NULL;
	id = btf_id_set8_contains(set, kfunc_btf_id);
	if (!id)
		return NULL;
	/* The flags for BTF ID are located next to it */
	return id + 1;
}

static bool __btf_kfunc_is_allowed(const struct btf *btf,
				   enum btf_kfunc_hook hook,
				   u32 kfunc_btf_id,
				   const struct bpf_prog *prog)
{
	struct btf_kfunc_hook_filter *hook_filter;
	int i;

	if (hook >= BTF_KFUNC_HOOK_MAX)
		return false;
	if (!btf->kfunc_set_tab)
		return false;

	hook_filter = &btf->kfunc_set_tab->hook_filters[hook];
	for (i = 0; i < hook_filter->nr_filters; i++) {
		if (hook_filter->filters[i](prog, kfunc_btf_id))
			return false;
	}

	return true;
}

static int bpf_prog_type_to_kfunc_hook(enum bpf_prog_type prog_type)
{
	switch (prog_type) {
	case BPF_PROG_TYPE_UNSPEC:
		return BTF_KFUNC_HOOK_COMMON;
	case BPF_PROG_TYPE_XDP:
		return BTF_KFUNC_HOOK_XDP;
	case BPF_PROG_TYPE_SCHED_CLS:
		return BTF_KFUNC_HOOK_TC;
	case BPF_PROG_TYPE_STRUCT_OPS:
		return BTF_KFUNC_HOOK_STRUCT_OPS;
	case BPF_PROG_TYPE_TRACING:
	case BPF_PROG_TYPE_TRACEPOINT:
	case BPF_PROG_TYPE_RAW_TRACEPOINT:
	case BPF_PROG_TYPE_PERF_EVENT:
	case BPF_PROG_TYPE_LSM:
		return BTF_KFUNC_HOOK_TRACING;
	case BPF_PROG_TYPE_SYSCALL:
		return BTF_KFUNC_HOOK_SYSCALL;
	case BPF_PROG_TYPE_CGROUP_SKB:
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_CGROUP_DEVICE:
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
	case BPF_PROG_TYPE_CGROUP_SYSCTL:
	case BPF_PROG_TYPE_SOCK_OPS:
		return BTF_KFUNC_HOOK_CGROUP;
	case BPF_PROG_TYPE_SCHED_ACT:
		return BTF_KFUNC_HOOK_SCHED_ACT;
	case BPF_PROG_TYPE_SK_SKB:
		return BTF_KFUNC_HOOK_SK_SKB;
	case BPF_PROG_TYPE_SOCKET_FILTER:
		return BTF_KFUNC_HOOK_SOCKET_FILTER;
	case BPF_PROG_TYPE_LWT_OUT:
	case BPF_PROG_TYPE_LWT_IN:
	case BPF_PROG_TYPE_LWT_XMIT:
	case BPF_PROG_TYPE_LWT_SEG6LOCAL:
		return BTF_KFUNC_HOOK_LWT;
	case BPF_PROG_TYPE_NETFILTER:
		return BTF_KFUNC_HOOK_NETFILTER;
	case BPF_PROG_TYPE_KPROBE:
		return BTF_KFUNC_HOOK_KPROBE;
	default:
		return BTF_KFUNC_HOOK_MAX;
	}
}

bool btf_kfunc_is_allowed(const struct btf *btf,
			  u32 kfunc_btf_id,
			  const struct bpf_prog *prog)
{
	enum bpf_prog_type prog_type = resolve_prog_type(prog);
	enum btf_kfunc_hook hook;
	u32 *kfunc_flags;

	kfunc_flags = btf_kfunc_id_set_contains(btf, BTF_KFUNC_HOOK_COMMON, kfunc_btf_id);
	if (kfunc_flags && __btf_kfunc_is_allowed(btf, BTF_KFUNC_HOOK_COMMON, kfunc_btf_id, prog))
		return true;

	hook = bpf_prog_type_to_kfunc_hook(prog_type);
	kfunc_flags = btf_kfunc_id_set_contains(btf, hook, kfunc_btf_id);
	if (kfunc_flags && __btf_kfunc_is_allowed(btf, hook, kfunc_btf_id, prog))
		return true;

	return false;
}

/* Caution:
 * Reference to the module (obtained using btf_try_get_module) corresponding to
 * the struct btf *MUST* be held when calling this function from verifier
 * context. This is usually true as we stash references in prog's kfunc_btf_tab;
 * keeping the reference for the duration of the call provides the necessary
 * protection for looking up a well-formed btf->kfunc_set_tab.
 */
u32 *btf_kfunc_flags(const struct btf *btf, u32 kfunc_btf_id, const struct bpf_prog *prog)
{
	enum bpf_prog_type prog_type = resolve_prog_type(prog);
	enum btf_kfunc_hook hook;
	u32 *kfunc_flags;

	kfunc_flags = btf_kfunc_id_set_contains(btf, BTF_KFUNC_HOOK_COMMON, kfunc_btf_id);
	if (kfunc_flags)
		return kfunc_flags;

	hook = bpf_prog_type_to_kfunc_hook(prog_type);
	return btf_kfunc_id_set_contains(btf, hook, kfunc_btf_id);
}

u32 *btf_kfunc_is_modify_return(const struct btf *btf, u32 kfunc_btf_id,
				const struct bpf_prog *prog)
{
	if (!__btf_kfunc_is_allowed(btf, BTF_KFUNC_HOOK_FMODRET, kfunc_btf_id, prog))
		return NULL;

	return btf_kfunc_id_set_contains(btf, BTF_KFUNC_HOOK_FMODRET, kfunc_btf_id);
}

static int __register_btf_kfunc_id_set(enum btf_kfunc_hook hook,
				       const struct btf_kfunc_id_set *kset)
{
	struct btf *btf;
	int ret, i;

	btf = btf_get_module_btf(kset->owner);
	if (!btf)
		return check_btf_kconfigs(kset->owner, "kfunc");
	if (IS_ERR(btf))
		return PTR_ERR(btf);

	for (i = 0; i < kset->set->cnt; i++) {
		ret = btf_check_kfunc_protos(btf, btf_relocate_id(btf, kset->set->pairs[i].id),
					     kset->set->pairs[i].flags);
		if (ret)
			goto err_out;
	}

	ret = btf_populate_kfunc_set(btf, hook, kset);

err_out:
	btf_put(btf);
	return ret;
}

/* This function must be invoked only from initcalls/module init functions */
int register_btf_kfunc_id_set(enum bpf_prog_type prog_type,
			      const struct btf_kfunc_id_set *kset)
{
	enum btf_kfunc_hook hook;

	/* All kfuncs need to be tagged as such in BTF.
	 * WARN() for initcall registrations that do not check errors.
	 */
	if (!(kset->set->flags & BTF_SET8_KFUNCS)) {
		WARN_ON(!kset->owner);
		return -EINVAL;
	}

	hook = bpf_prog_type_to_kfunc_hook(prog_type);
	return __register_btf_kfunc_id_set(hook, kset);
}
EXPORT_SYMBOL_GPL(register_btf_kfunc_id_set);

/* This function must be invoked only from initcalls/module init functions */
int register_btf_fmodret_id_set(const struct btf_kfunc_id_set *kset)
{
	return __register_btf_kfunc_id_set(BTF_KFUNC_HOOK_FMODRET, kset);
}
EXPORT_SYMBOL_GPL(register_btf_fmodret_id_set);

s32 btf_find_dtor_kfunc(struct btf *btf, u32 btf_id)
{
	struct btf_id_dtor_kfunc_tab *tab = btf->dtor_kfunc_tab;
	struct btf_id_dtor_kfunc *dtor;

	if (!tab)
		return -ENOENT;
	/* Even though the size of tab->dtors[0] is > sizeof(u32), we only need
	 * to compare the first u32 with btf_id, so we can reuse btf_id_cmp_func.
	 */
	BUILD_BUG_ON(offsetof(struct btf_id_dtor_kfunc, btf_id) != 0);
	dtor = bsearch(&btf_id, tab->dtors, tab->cnt, sizeof(tab->dtors[0]), btf_id_cmp_func);
	if (!dtor)
		return -ENOENT;
	return dtor->kfunc_btf_id;
}

static int btf_check_dtor_kfuncs(struct btf *btf, const struct btf_id_dtor_kfunc *dtors, u32 cnt)
{
	const struct btf_type *dtor_func, *dtor_func_proto, *t;
	const struct btf_param *args;
	s32 dtor_btf_id;
	u32 nr_args, i;

	for (i = 0; i < cnt; i++) {
		dtor_btf_id = btf_relocate_id(btf, dtors[i].kfunc_btf_id);

		dtor_func = btf_type_by_id(btf, dtor_btf_id);
		if (!dtor_func || !btf_type_is_func(dtor_func))
			return -EINVAL;

		dtor_func_proto = btf_type_by_id(btf, dtor_func->type);
		if (!dtor_func_proto || !btf_type_is_func_proto(dtor_func_proto))
			return -EINVAL;

		/* Make sure the prototype of the destructor kfunc is 'void func(type *)' */
		t = btf_type_by_id(btf, dtor_func_proto->type);
		if (!t || !btf_type_is_void(t))
			return -EINVAL;

		nr_args = btf_type_vlen(dtor_func_proto);
		if (nr_args != 1)
			return -EINVAL;
		args = btf_params(dtor_func_proto);
		t = btf_type_by_id(btf, args[0].type);
		/* Allow any pointer type, as width on targets Linux supports
		 * will be same for all pointer types (i.e. sizeof(void *))
		 */
		if (!t || !btf_type_is_ptr(t))
			return -EINVAL;

		if (IS_ENABLED(CONFIG_CFI)) {
			/* Ensure the destructor kfunc type matches btf_dtor_kfunc_t */
			t = btf_type_by_id(btf, t->type);
			if (!btf_type_is_void(t))
				return -EINVAL;
		}
	}
	return 0;
}

/* This function must be invoked only from initcalls/module init functions */
int register_btf_id_dtor_kfuncs(const struct btf_id_dtor_kfunc *dtors, u32 add_cnt,
				struct module *owner)
{
	struct btf_id_dtor_kfunc_tab *tab;
	struct btf *btf;
	u32 tab_cnt, i;
	int ret;

	btf = btf_get_module_btf(owner);
	if (!btf)
		return check_btf_kconfigs(owner, "dtor kfuncs");
	if (IS_ERR(btf))
		return PTR_ERR(btf);

	if (add_cnt >= BTF_DTOR_KFUNC_MAX_CNT) {
		pr_err("cannot register more than %d kfunc destructors\n", BTF_DTOR_KFUNC_MAX_CNT);
		ret = -E2BIG;
		goto end;
	}

	/* Ensure that the prototype of dtor kfuncs being registered is sane */
	ret = btf_check_dtor_kfuncs(btf, dtors, add_cnt);
	if (ret < 0)
		goto end;

	tab = btf->dtor_kfunc_tab;
	/* Only one call allowed for modules */
	if (WARN_ON_ONCE(tab && btf_is_module(btf))) {
		ret = -EINVAL;
		goto end;
	}

	tab_cnt = tab ? tab->cnt : 0;
	if (tab_cnt > U32_MAX - add_cnt) {
		ret = -EOVERFLOW;
		goto end;
	}
	if (tab_cnt + add_cnt >= BTF_DTOR_KFUNC_MAX_CNT) {
		pr_err("cannot register more than %d kfunc destructors\n", BTF_DTOR_KFUNC_MAX_CNT);
		ret = -E2BIG;
		goto end;
	}

	tab = krealloc(btf->dtor_kfunc_tab,
		       struct_size(tab, dtors, tab_cnt + add_cnt),
		       GFP_KERNEL | __GFP_NOWARN);
	if (!tab) {
		ret = -ENOMEM;
		goto end;
	}

	if (!btf->dtor_kfunc_tab)
		tab->cnt = 0;
	btf->dtor_kfunc_tab = tab;

	memcpy(tab->dtors + tab->cnt, dtors, add_cnt * sizeof(tab->dtors[0]));

	/* remap BTF ids based on BTF relocation (if any) */
	for (i = tab_cnt; i < tab_cnt + add_cnt; i++) {
		tab->dtors[i].btf_id = btf_relocate_id(btf, tab->dtors[i].btf_id);
		tab->dtors[i].kfunc_btf_id = btf_relocate_id(btf, tab->dtors[i].kfunc_btf_id);
	}

	tab->cnt += add_cnt;

	sort(tab->dtors, tab->cnt, sizeof(tab->dtors[0]), btf_id_cmp_func, NULL);

end:
	if (ret)
		btf_free_dtor_kfunc_tab(btf);
	btf_put(btf);
	return ret;
}
EXPORT_SYMBOL_GPL(register_btf_id_dtor_kfuncs);

#define MAX_TYPES_ARE_COMPAT_DEPTH 2

/* Check local and target types for compatibility. This check is used for
 * type-based CO-RE relocations and follow slightly different rules than
 * field-based relocations. This function assumes that root types were already
 * checked for name match. Beyond that initial root-level name check, names
 * are completely ignored. Compatibility rules are as follows:
 *   - any two STRUCTs/UNIONs/FWDs/ENUMs/INTs/ENUM64s are considered compatible, but
 *     kind should match for local and target types (i.e., STRUCT is not
 *     compatible with UNION);
 *   - for ENUMs/ENUM64s, the size is ignored;
 *   - for INT, size and signedness are ignored;
 *   - for ARRAY, dimensionality is ignored, element types are checked for
 *     compatibility recursively;
 *   - CONST/VOLATILE/RESTRICT modifiers are ignored;
 *   - TYPEDEFs/PTRs are compatible if types they pointing to are compatible;
 *   - FUNC_PROTOs are compatible if they have compatible signature: same
 *     number of input args and compatible return and argument types.
 * These rules are not set in stone and probably will be adjusted as we get
 * more experience with using BPF CO-RE relocations.
 */
int bpf_core_types_are_compat(const struct btf *local_btf, __u32 local_id,
			      const struct btf *targ_btf, __u32 targ_id)
{
	return __bpf_core_types_are_compat(local_btf, local_id, targ_btf, targ_id,
					   MAX_TYPES_ARE_COMPAT_DEPTH);
}

#define MAX_TYPES_MATCH_DEPTH 2

int bpf_core_types_match(const struct btf *local_btf, u32 local_id,
			 const struct btf *targ_btf, u32 targ_id)
{
	return __bpf_core_types_match(local_btf, local_id, targ_btf, targ_id, false,
				      MAX_TYPES_MATCH_DEPTH);
}

static bool bpf_core_is_flavor_sep(const char *s)
{
	/* check X___Y name pattern, where X and Y are not underscores */
	return s[0] != '_' &&				      /* X */
	       s[1] == '_' && s[2] == '_' && s[3] == '_' &&   /* ___ */
	       s[4] != '_';				      /* Y */
}

size_t bpf_core_essential_name_len(const char *name)
{
	size_t n = strlen(name);
	int i;

	for (i = n - 5; i >= 0; i--) {
		if (bpf_core_is_flavor_sep(name + i))
			return i + 1;
	}
	return n;
}

static void bpf_free_cands(struct bpf_cand_cache *cands)
{
	if (!cands->cnt)
		/* empty candidate array was allocated on stack */
		return;
	kfree(cands);
}

static void bpf_free_cands_from_cache(struct bpf_cand_cache *cands)
{
	kfree(cands->name);
	kfree(cands);
}

#define VMLINUX_CAND_CACHE_SIZE 31
static struct bpf_cand_cache *vmlinux_cand_cache[VMLINUX_CAND_CACHE_SIZE];

#define MODULE_CAND_CACHE_SIZE 31
static struct bpf_cand_cache *module_cand_cache[MODULE_CAND_CACHE_SIZE];

static void __print_cand_cache(struct bpf_verifier_log *log,
			       struct bpf_cand_cache **cache,
			       int cache_size)
{
	struct bpf_cand_cache *cc;
	int i, j;

	for (i = 0; i < cache_size; i++) {
		cc = cache[i];
		if (!cc)
			continue;
		bpf_log(log, "[%d]%s(", i, cc->name);
		for (j = 0; j < cc->cnt; j++) {
			bpf_log(log, "%d", cc->cands[j].id);
			if (j < cc->cnt - 1)
				bpf_log(log, " ");
		}
		bpf_log(log, "), ");
	}
}

static void print_cand_cache(struct bpf_verifier_log *log)
{
	mutex_lock(&cand_cache_mutex);
	bpf_log(log, "vmlinux_cand_cache:");
	__print_cand_cache(log, vmlinux_cand_cache, VMLINUX_CAND_CACHE_SIZE);
	bpf_log(log, "\nmodule_cand_cache:");
	__print_cand_cache(log, module_cand_cache, MODULE_CAND_CACHE_SIZE);
	bpf_log(log, "\n");
	mutex_unlock(&cand_cache_mutex);
}

static u32 hash_cands(struct bpf_cand_cache *cands)
{
	return jhash(cands->name, cands->name_len, 0);
}

static struct bpf_cand_cache *check_cand_cache(struct bpf_cand_cache *cands,
					       struct bpf_cand_cache **cache,
					       int cache_size)
{
	struct bpf_cand_cache *cc = cache[hash_cands(cands) % cache_size];

	if (cc && cc->name_len == cands->name_len &&
	    !strncmp(cc->name, cands->name, cands->name_len))
		return cc;
	return NULL;
}

static size_t sizeof_cands(int cnt)
{
	return offsetof(struct bpf_cand_cache, cands[cnt]);
}

static struct bpf_cand_cache *populate_cand_cache(struct bpf_cand_cache *cands,
						  struct bpf_cand_cache **cache,
						  int cache_size)
{
	struct bpf_cand_cache **cc = &cache[hash_cands(cands) % cache_size], *new_cands;

	if (*cc) {
		bpf_free_cands_from_cache(*cc);
		*cc = NULL;
	}
	new_cands = kmemdup(cands, sizeof_cands(cands->cnt), GFP_KERNEL_ACCOUNT);
	if (!new_cands) {
		bpf_free_cands(cands);
		return ERR_PTR(-ENOMEM);
	}
	/* strdup the name, since it will stay in cache.
	 * the cands->name points to strings in prog's BTF and the prog can be unloaded.
	 */
	new_cands->name = kmemdup_nul(cands->name, cands->name_len, GFP_KERNEL_ACCOUNT);
	bpf_free_cands(cands);
	if (!new_cands->name) {
		kfree(new_cands);
		return ERR_PTR(-ENOMEM);
	}
	*cc = new_cands;
	return new_cands;
}

#ifdef CONFIG_DEBUG_INFO_BTF_MODULES
static void __purge_cand_cache(struct btf *btf, struct bpf_cand_cache **cache,
			       int cache_size)
{
	struct bpf_cand_cache *cc;
	int i, j;

	for (i = 0; i < cache_size; i++) {
		cc = cache[i];
		if (!cc)
			continue;
		if (!btf) {
			/* when new module is loaded purge all of module_cand_cache,
			 * since new module might have candidates with the name
			 * that matches cached cands.
			 */
			bpf_free_cands_from_cache(cc);
			cache[i] = NULL;
			continue;
		}
		/* when module is unloaded purge cache entries
		 * that match module's btf
		 */
		for (j = 0; j < cc->cnt; j++)
			if (cc->cands[j].btf == btf) {
				bpf_free_cands_from_cache(cc);
				cache[i] = NULL;
				break;
			}
	}

}

static void purge_cand_cache(struct btf *btf)
{
	mutex_lock(&cand_cache_mutex);
	__purge_cand_cache(btf, module_cand_cache, MODULE_CAND_CACHE_SIZE);
	mutex_unlock(&cand_cache_mutex);
}
#endif

static struct bpf_cand_cache *
bpf_core_add_cands(struct bpf_cand_cache *cands, const struct btf *targ_btf,
		   int targ_start_id)
{
	struct bpf_cand_cache *new_cands;
	const struct btf_type *t;
	const char *targ_name;
	size_t targ_essent_len;
	int n, i;

	n = btf_nr_types(targ_btf);
	for (i = targ_start_id; i < n; i++) {
		t = btf_type_by_id(targ_btf, i);
		if (btf_kind(t) != cands->kind)
			continue;

		targ_name = btf_name_by_offset(targ_btf, t->name_off);
		if (!targ_name)
			continue;

		/* the resched point is before strncmp to make sure that search
		 * for non-existing name will have a chance to schedule().
		 */
		cond_resched();

		if (strncmp(cands->name, targ_name, cands->name_len) != 0)
			continue;

		targ_essent_len = bpf_core_essential_name_len(targ_name);
		if (targ_essent_len != cands->name_len)
			continue;

		/* most of the time there is only one candidate for a given kind+name pair */
		new_cands = kmalloc(sizeof_cands(cands->cnt + 1), GFP_KERNEL_ACCOUNT);
		if (!new_cands) {
			bpf_free_cands(cands);
			return ERR_PTR(-ENOMEM);
		}

		memcpy(new_cands, cands, sizeof_cands(cands->cnt));
		bpf_free_cands(cands);
		cands = new_cands;
		cands->cands[cands->cnt].btf = targ_btf;
		cands->cands[cands->cnt].id = i;
		cands->cnt++;
	}
	return cands;
}

static struct bpf_cand_cache *
bpf_core_find_cands(struct bpf_core_ctx *ctx, u32 local_type_id)
{
	struct bpf_cand_cache *cands, *cc, local_cand = {};
	const struct btf *local_btf = ctx->btf;
	const struct btf_type *local_type;
	const struct btf *main_btf;
	size_t local_essent_len;
	struct btf *mod_btf;
	const char *name;
	int id;

	main_btf = bpf_get_btf_vmlinux();
	if (IS_ERR(main_btf))
		return ERR_CAST(main_btf);
	if (!main_btf)
		return ERR_PTR(-EINVAL);

	local_type = btf_type_by_id(local_btf, local_type_id);
	if (!local_type)
		return ERR_PTR(-EINVAL);

	name = btf_name_by_offset(local_btf, local_type->name_off);
	if (str_is_empty(name))
		return ERR_PTR(-EINVAL);
	local_essent_len = bpf_core_essential_name_len(name);

	cands = &local_cand;
	cands->name = name;
	cands->kind = btf_kind(local_type);
	cands->name_len = local_essent_len;

	cc = check_cand_cache(cands, vmlinux_cand_cache, VMLINUX_CAND_CACHE_SIZE);
	/* cands is a pointer to stack here */
	if (cc) {
		if (cc->cnt)
			return cc;
		goto check_modules;
	}

	/* Attempt to find target candidates in vmlinux BTF first */
	cands = bpf_core_add_cands(cands, main_btf, btf_named_start_id(main_btf, true));
	if (IS_ERR(cands))
		return ERR_CAST(cands);

	/* cands is a pointer to kmalloced memory here if cands->cnt > 0 */

	/* populate cache even when cands->cnt == 0 */
	cc = populate_cand_cache(cands, vmlinux_cand_cache, VMLINUX_CAND_CACHE_SIZE);
	if (IS_ERR(cc))
		return ERR_CAST(cc);

	/* if vmlinux BTF has any candidate, don't go for module BTFs */
	if (cc->cnt)
		return cc;

check_modules:
	/* cands is a pointer to stack here and cands->cnt == 0 */
	cc = check_cand_cache(cands, module_cand_cache, MODULE_CAND_CACHE_SIZE);
	if (cc)
		/* if cache has it return it even if cc->cnt == 0 */
		return cc;

	/* If candidate is not found in vmlinux's BTF then search in module's BTFs */
	spin_lock_bh(&btf_idr_lock);
	idr_for_each_entry(&btf_idr, mod_btf, id) {
		if (!btf_is_module(mod_btf))
			continue;
		/* linear search could be slow hence unlock/lock
		 * the IDR to avoiding holding it for too long
		 */
		btf_get(mod_btf);
		spin_unlock_bh(&btf_idr_lock);
		cands = bpf_core_add_cands(cands, mod_btf, btf_named_start_id(mod_btf, true));
		btf_put(mod_btf);
		if (IS_ERR(cands))
			return ERR_CAST(cands);
		spin_lock_bh(&btf_idr_lock);
	}
	spin_unlock_bh(&btf_idr_lock);
	/* cands is a pointer to kmalloced memory here if cands->cnt > 0
	 * or pointer to stack if cands->cnd == 0.
	 * Copy it into the cache even when cands->cnt == 0 and
	 * return the result.
	 */
	return populate_cand_cache(cands, module_cand_cache, MODULE_CAND_CACHE_SIZE);
}

int bpf_core_apply(struct bpf_core_ctx *ctx, const struct bpf_core_relo *relo,
		   int relo_idx, void *insn)
{
	bool need_cands = relo->kind != BPF_CORE_TYPE_ID_LOCAL;
	struct bpf_core_cand_list cands = {};
	struct bpf_core_relo_res targ_res;
	struct bpf_core_spec *specs;
	const struct btf_type *type;
	int err;

	/* ~4k of temp memory necessary to convert LLVM spec like "0:1:0:5"
	 * into arrays of btf_ids of struct fields and array indices.
	 */
	specs = kzalloc_objs(*specs, 3, GFP_KERNEL_ACCOUNT);
	if (!specs)
		return -ENOMEM;

	type = btf_type_by_id(ctx->btf, relo->type_id);
	if (!type) {
		bpf_log(ctx->log, "relo #%u: bad type id %u\n",
			relo_idx, relo->type_id);
		kfree(specs);
		return -EINVAL;
	}

	if (need_cands) {
		struct bpf_cand_cache *cc;
		int i;

		mutex_lock(&cand_cache_mutex);
		cc = bpf_core_find_cands(ctx, relo->type_id);
		if (IS_ERR(cc)) {
			bpf_log(ctx->log, "target candidate search failed for %d\n",
				relo->type_id);
			err = PTR_ERR(cc);
			goto out;
		}
		if (cc->cnt) {
			cands.cands = kzalloc_objs(*cands.cands, cc->cnt,
						   GFP_KERNEL_ACCOUNT);
			if (!cands.cands) {
				err = -ENOMEM;
				goto out;
			}
		}
		for (i = 0; i < cc->cnt; i++) {
			bpf_log(ctx->log,
				"CO-RE relocating %s %s: found target candidate [%d]\n",
				btf_kind_str[cc->kind], cc->name, cc->cands[i].id);
			cands.cands[i].btf = cc->cands[i].btf;
			cands.cands[i].id = cc->cands[i].id;
		}
		cands.len = cc->cnt;
		/* cand_cache_mutex needs to span the cache lookup and
		 * copy of btf pointer into bpf_core_cand_list,
		 * since module can be unloaded while bpf_core_calc_relo_insn
		 * is working with module's btf.
		 */
	}

	err = bpf_core_calc_relo_insn((void *)ctx->log, relo, relo_idx, ctx->btf, &cands, specs,
				      &targ_res);
	if (err)
		goto out;

	err = bpf_core_patch_insn((void *)ctx->log, insn, relo->insn_off / 8, relo, relo_idx,
				  &targ_res);

out:
	kfree(specs);
	if (need_cands) {
		kfree(cands.cands);
		mutex_unlock(&cand_cache_mutex);
		if (ctx->log->level & BPF_LOG_LEVEL2)
			print_cand_cache(ctx->log);
	}
	return err;
}

bool btf_nested_type_is_trusted(struct bpf_verifier_log *log,
				const struct bpf_reg_state *reg,
				const char *field_name, u32 btf_id, const char *suffix)
{
	struct btf *btf = reg->btf;
	const struct btf_type *walk_type, *safe_type;
	const char *tname;
	char safe_tname[64];
	long ret, safe_id;
	const struct btf_member *member;
	u32 i;

	walk_type = btf_type_by_id(btf, reg->btf_id);
	if (!walk_type)
		return false;

	tname = btf_name_by_offset(btf, walk_type->name_off);

	ret = snprintf(safe_tname, sizeof(safe_tname), "%s%s", tname, suffix);
	if (ret >= sizeof(safe_tname))
		return false;

	safe_id = btf_find_by_name_kind(btf, safe_tname, BTF_INFO_KIND(walk_type->info));
	if (safe_id < 0)
		return false;

	safe_type = btf_type_by_id(btf, safe_id);
	if (!safe_type)
		return false;

	for_each_member(i, safe_type, member) {
		const char *m_name = __btf_name_by_offset(btf, member->name_off);
		const struct btf_type *mtype = btf_type_by_id(btf, member->type);
		u32 id;

		if (!btf_type_is_ptr(mtype))
			continue;

		btf_type_skip_modifiers(btf, mtype->type, &id);
		/* If we match on both type and name, the field is considered trusted. */
		if (btf_id == id && !strcmp(field_name, m_name))
			return true;
	}

	return false;
}

bool btf_type_ids_nocast_alias(struct bpf_verifier_log *log,
			       const struct btf *reg_btf, u32 reg_id,
			       const struct btf *arg_btf, u32 arg_id)
{
	const char *reg_name, *arg_name, *search_needle;
	const struct btf_type *reg_type, *arg_type;
	int reg_len, arg_len, cmp_len;
	size_t pattern_len = sizeof(NOCAST_ALIAS_SUFFIX) - sizeof(char);

	reg_type = btf_type_by_id(reg_btf, reg_id);
	if (!reg_type)
		return false;

	arg_type = btf_type_by_id(arg_btf, arg_id);
	if (!arg_type)
		return false;

	reg_name = btf_name_by_offset(reg_btf, reg_type->name_off);
	arg_name = btf_name_by_offset(arg_btf, arg_type->name_off);

	reg_len = strlen(reg_name);
	arg_len = strlen(arg_name);

	/* Exactly one of the two type names may be suffixed with ___init, so
	 * if the strings are the same size, they can't possibly be no-cast
	 * aliases of one another. If you have two of the same type names, e.g.
	 * they're both nf_conn___init, it would be improper to return true
	 * because they are _not_ no-cast aliases, they are the same type.
	 */
	if (reg_len == arg_len)
		return false;

	/* Either of the two names must be the other name, suffixed with ___init. */
	if ((reg_len != arg_len + pattern_len) &&
	    (arg_len != reg_len + pattern_len))
		return false;

	if (reg_len < arg_len) {
		search_needle = strstr(arg_name, NOCAST_ALIAS_SUFFIX);
		cmp_len = reg_len;
	} else {
		search_needle = strstr(reg_name, NOCAST_ALIAS_SUFFIX);
		cmp_len = arg_len;
	}

	if (!search_needle)
		return false;

	/* ___init suffix must come at the end of the name */
	if (*(search_needle + pattern_len) != '\0')
		return false;

	return !strncmp(reg_name, arg_name, cmp_len);
}

#ifdef CONFIG_BPF_JIT
static int
btf_add_struct_ops(struct btf *btf, struct bpf_struct_ops *st_ops,
		   struct bpf_verifier_log *log)
{
	struct btf_struct_ops_tab *tab, *new_tab;
	int i, err;

	tab = btf->struct_ops_tab;
	if (!tab) {
		tab = kzalloc_flex(*tab, ops, 4);
		if (!tab)
			return -ENOMEM;
		tab->capacity = 4;
		btf->struct_ops_tab = tab;
	}

	for (i = 0; i < tab->cnt; i++)
		if (tab->ops[i].st_ops == st_ops)
			return -EEXIST;

	if (tab->cnt == tab->capacity) {
		new_tab = krealloc(tab,
				   struct_size(tab, ops, tab->capacity * 2),
				   GFP_KERNEL);
		if (!new_tab)
			return -ENOMEM;
		tab = new_tab;
		tab->capacity *= 2;
		btf->struct_ops_tab = tab;
	}

	tab->ops[btf->struct_ops_tab->cnt].st_ops = st_ops;

	err = bpf_struct_ops_desc_init(&tab->ops[btf->struct_ops_tab->cnt], btf, log);
	if (err)
		return err;

	btf->struct_ops_tab->cnt++;

	return 0;
}

const struct bpf_struct_ops_desc *
bpf_struct_ops_find_value(struct btf *btf, u32 value_id)
{
	const struct bpf_struct_ops_desc *st_ops_list;
	unsigned int i;
	u32 cnt;

	if (!value_id)
		return NULL;
	if (!btf->struct_ops_tab)
		return NULL;

	cnt = btf->struct_ops_tab->cnt;
	st_ops_list = btf->struct_ops_tab->ops;
	for (i = 0; i < cnt; i++) {
		if (st_ops_list[i].value_id == value_id)
			return &st_ops_list[i];
	}

	return NULL;
}

const struct bpf_struct_ops_desc *
bpf_struct_ops_find(struct btf *btf, u32 type_id)
{
	const struct bpf_struct_ops_desc *st_ops_list;
	unsigned int i;
	u32 cnt;

	if (!type_id)
		return NULL;
	if (!btf->struct_ops_tab)
		return NULL;

	cnt = btf->struct_ops_tab->cnt;
	st_ops_list = btf->struct_ops_tab->ops;
	for (i = 0; i < cnt; i++) {
		if (st_ops_list[i].type_id == type_id)
			return &st_ops_list[i];
	}

	return NULL;
}

int __register_bpf_struct_ops(struct bpf_struct_ops *st_ops)
{
	struct bpf_verifier_log *log;
	struct btf *btf;
	int err = 0;

	btf = btf_get_module_btf(st_ops->owner);
	if (!btf)
		return check_btf_kconfigs(st_ops->owner, "struct_ops");
	if (IS_ERR(btf))
		return PTR_ERR(btf);

	log = kzalloc_obj(*log, GFP_KERNEL | __GFP_NOWARN);
	if (!log) {
		err = -ENOMEM;
		goto errout;
	}

	log->level = BPF_LOG_KERNEL;

	err = btf_add_struct_ops(btf, st_ops, log);

errout:
	kfree(log);
	btf_put(btf);

	return err;
}
EXPORT_SYMBOL_GPL(__register_bpf_struct_ops);
#endif
