// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025, Oracle and/or its affiliates. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/ptrace.h>
#include <linux/kernel.h>

/* s8 will be marked as poison while it's a reg of riscv */
#if defined(__riscv)
#define rv_s8 s8
#endif

#include "bpf.h"
#include "btf.h"
#include "libbpf.h"
#include "libbpf_common.h"
#include "libbpf_internal.h"

/* Location implementation is very similar to usdt.c; key difference
 * is the data specifying how to retrieve parameters for a target is
 * in BTF.
 */

/* should match exactly enum __bpf_loc_arg_type from loc.bpf.h */
enum loc_arg_type {
	BPF_LOC_ARG_UNAVAILABLE,
	BPF_LOC_ARG_CONST,
	BPF_LOC_ARG_REG,
	BPF_LOC_ARG_REG_DEREF,
	BPF_LOC_ARG_REG_MULTI,
};

/* should match exactly struct __bpf_loc_arg_spec from loc.bpf.h */
struct loc_arg_spec {
	/* u64 scalar interpreted depending on arg_type, see below */
	__u64 val_off;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	enum loc_arg_type arg_type: 8;
	/* reserved for future use, keeps reg_off offset stable */
	__u32 __reserved: 24;
#else
	__u32 __reserved: 24;
	enum loc_arg_type arg_type: 8;
#endif
	/* offset of referenced register within struct pt_regs */
	union {
		short reg_off;
		short reg_offs[2];
	};
	/* whether arg should be interpreted as signed value */
	bool arg_signed;
	/* number of bits that need to be cleared and, optionally,
	 * sign-extended to cast arguments that are 1, 2, or 4 bytes
	 * long into final 8-byte u64/s64 value returned to user
	 */
	char arg_bitshift;
};

#define LOC_MAX_ARG_CNT 12
struct loc_spec {
	struct loc_arg_spec args[LOC_MAX_ARG_CNT];
	__u64 loc_cookie;
	short arg_cnt;
};

struct loc_target {
	long abs_ip;
	struct loc_spec spec;
};

struct loc_manager {
	struct bpf_map *specs_map;
	struct bpf_map *ip_to_spec_id_map;
	int *free_spec_ids;
	size_t free_spec_cnt;
	size_t next_free_spec_id;
	struct loc_target *targets;
	size_t target_cnt;
	bool has_bpf_cookie;
};

static int get_base_addr(const char *mod, __u64 *base_addr)
{
	bool is_vmlinux = strcmp(mod, "vmlinux") == 0;
	const char *file = is_vmlinux ? "/proc/kallsyms" : "/proc/modules";
	char name[PATH_MAX], type;
	int err = -ENOENT;
	FILE *f = NULL;
	long addr;

	*base_addr = 0;

	f = fopen(file, "r");
	if (!f) {
		pr_warn("loc: cannot open '%s' (err %s)\n", file, errstr(-errno));
		return -errno;
	}
	if (is_vmlinux) {
		while (fscanf(f, "%lx %c %499s%*[^\n]\n", &addr, &type, name) == 3) {
			if (strcmp(name, "_text") != 0)
				continue;
			*base_addr = addr;
			err = 0;
			break;
		}
	} else {
		while (fscanf(f, "%s %*s %*s %*s %*s 0x%lx\n", name, &addr) == 5) {
			if (strcmp(name, mod) != 0)
				continue;
			*base_addr = addr;
			err = 0;
			break;
		}
	}
	fclose(f);
	if (err)
		pr_warn("loc: could not find base addr for '%s'\n", mod);
	return err;
}

void loc_manager_free(struct loc_manager *man)
{
	if (IS_ERR_OR_NULL(man))
		return;

	free(man->free_spec_ids);
	free(man);
}

struct loc_manager *loc_manager_new(struct bpf_object *obj)
{
	struct loc_manager *man = NULL;
	struct bpf_map *specs_map, *ip_to_spec_id_map;

	specs_map = bpf_object__find_map_by_name(obj, "__bpf_loc_specs");
	ip_to_spec_id_map = bpf_object__find_map_by_name(obj, "__bpf_loc_ip_to_spec_id");
	if (!specs_map || !ip_to_spec_id_map) {
		pr_warn("loc: failed to find location support BPF maps, did you forget to include bpf/loc.bpf.h?\n");
		return ERR_PTR(-ESRCH);
	}

	man = calloc(1, sizeof(*man));
	if (!man)
		return ERR_PTR(-ENOMEM);
	man->specs_map = specs_map;
	man->ip_to_spec_id_map = ip_to_spec_id_map;

	/* Detect if BPF cookie is supported for kprobes.
	 * We don't need IP-to-ID mapping if we can use BPF cookies.
	 * Added in: 7adfc6c9b315 ("bpf: Add bpf_get_attach_cookie() BPF helper to access bpf_cookie value")
	 */
	man->has_bpf_cookie = kernel_supports(obj, FEAT_BPF_COOKIE);

	return man;
}

struct bpf_link_loc {
	struct bpf_link link;

	struct loc_manager *loc_man;

	size_t spec_cnt;
	int *spec_ids;

	size_t kprobe_cnt;
	struct {
		long abs_ip;
		struct bpf_link *link;
	} *kprobes;
};

static int bpf_link_loc_detach(struct bpf_link *link)
{
	struct bpf_link_loc *loc_link = container_of(link, struct bpf_link_loc, link);
	struct loc_manager *man = loc_link->loc_man;
	int i;

	for (i = 0; i < loc_link->kprobe_cnt; i++) {
		/* detach underlying kprobe link */
		bpf_link__destroy(loc_link->kprobes[i].link);
		/* there is no need to update specs map because it will be
		 * unconditionally overwritten on subsequent loc attaches,
		 * but if BPF cookies are not used we need to remove entry
		 * from ip_to_spec_id map, otherwise we'll run into false
		 * conflicting IP errors
		 */
		if (!man->has_bpf_cookie) {
			/* not much we can do about errors here */
			(void)bpf_map_delete_elem(bpf_map__fd(man->ip_to_spec_id_map),
						  &loc_link->kprobes[i].abs_ip);
		}
	}

	/* try to return the list of previously used spec IDs to loc_manager
	 * for future reuse for subsequent loc attaches
	 */
	if (!man->free_spec_ids) {
		/* if there were no free spec IDs yet, just transfer our IDs */
		man->free_spec_ids = loc_link->spec_ids;
		man->free_spec_cnt = loc_link->spec_cnt;
		loc_link->spec_ids = NULL;
	} else {
		/* otherwise concat IDs */
		size_t new_cnt = man->free_spec_cnt + loc_link->spec_cnt;
		int *new_free_ids;

		new_free_ids = libbpf_reallocarray(man->free_spec_ids, new_cnt,
						   sizeof(*new_free_ids));
		/* If we couldn't resize free_spec_ids, we'll just leak
		 * a bunch of free IDs; this is very unlikely to happen and if
		 * system is so exhausted on memory, it's the least of user's
		 * concerns, probably.
		 * So just do our best here to return those IDs to usdt_manager.
		 * Another edge case when we can legitimately get NULL is when
		 * new_cnt is zero, which can happen in some edge cases, so we
		 * need to be careful about that.
		 */
		if (new_free_ids || new_cnt == 0) {
			memcpy(new_free_ids + man->free_spec_cnt, loc_link->spec_ids,
			       loc_link->spec_cnt * sizeof(*loc_link->spec_ids));
			man->free_spec_ids = new_free_ids;
			man->free_spec_cnt = new_cnt;
		}
	}

	return 0;
}

static void bpf_link_loc_dealloc(struct bpf_link *link)
{
	struct bpf_link_loc *loc_link = container_of(link, struct bpf_link_loc, link);

	free(loc_link->spec_ids);
	free(loc_link->kprobes);
	free(loc_link);
}

static int allocate_spec_id(struct loc_manager *man, struct bpf_link_loc *link,
			    struct loc_target *target, int *spec_id, bool *is_new)
{
	void *new_ids;

	new_ids = libbpf_reallocarray(link->spec_ids, link->spec_cnt + 1, sizeof(*link->spec_ids));
	if (!new_ids)
		return -ENOMEM;
	link->spec_ids = new_ids;

	/* get next free spec ID, giving preference to free list, if not empty */
	if (man->free_spec_cnt) {
		*spec_id = man->free_spec_ids[man->free_spec_cnt - 1];
		man->free_spec_cnt--;
	} else {
		/* don't allocate spec ID bigger than what fits in specs map */
		if (man->next_free_spec_id >= bpf_map__max_entries(man->specs_map))
			return -E2BIG;

		*spec_id = man->next_free_spec_id;
		man->next_free_spec_id++;
	}

	/* remember new spec ID in the link for later return back to free list on detach */
	link->spec_ids[link->spec_cnt] = *spec_id;
	link->spec_cnt++;
	*is_new = true;
	return 0;
}

static int collect_loc_targets(struct loc_manager *man, const char *mod, const char *name,
			       __u64 loc_cookie, struct loc_target **out_targets,
			       size_t *out_target_cnt);

struct bpf_link *loc_manager_attach_kloc(struct loc_manager *man, const struct bpf_program *prog,
					 const char *loc_mod, const char *loc_name,
					 __u64 loc_cookie)
{
	int i, err, spec_map_fd, ip_map_fd;

	LIBBPF_OPTS(bpf_kprobe_opts, opts);
	struct bpf_link_loc *link = NULL;
	struct loc_target *targets = NULL;
	__u64 *cookies = NULL;
	size_t target_cnt = 0;

	spec_map_fd = bpf_map__fd(man->specs_map);
	ip_map_fd = bpf_map__fd(man->ip_to_spec_id_map);

	err = collect_loc_targets(man, loc_mod, loc_name, loc_cookie, &targets, &target_cnt);
	if (err <= 0) {
		err = (err == 0) ? -ENOENT : err;
		goto err_out;
	}
	err = 0;

	link = calloc(1, sizeof(*link));
	if (!link) {
		err = -ENOMEM;
		goto err_out;
	}

	link->loc_man = man;
	link->link.detach = &bpf_link_loc_detach;
	link->link.dealloc = &bpf_link_loc_dealloc;

	link->kprobes = calloc(target_cnt, sizeof(*link->kprobes));
	if (!link->kprobes) {
		err = -ENOMEM;
		goto err_out;
	}

	for (i = 0; i < target_cnt; i++) {
		struct loc_target *target = &targets[i];
		struct bpf_link *kprobe_link;
		bool is_new;
		int spec_id;

		/* Spec ID can be either reused or newly allocated. */
		err = allocate_spec_id(man, link, target, &spec_id, &is_new);
		if (err)
			goto err_out;

		if (is_new && bpf_map_update_elem(spec_map_fd, &spec_id, &target->spec, BPF_ANY)) {
			err = -errno;
			pr_warn("loc: failed to set loc spec #%d for '%s:%s' in : %s\n",
				spec_id, loc_mod, loc_name, errstr(err));
			goto err_out;
		}
		if (!man->has_bpf_cookie &&
		    bpf_map_update_elem(ip_map_fd, &target->abs_ip, &spec_id, BPF_NOEXIST)) {
			err = -errno;
			if (err == -EEXIST) {
				pr_warn("loc: IP collision detected for spec #%d for '%s:%s''\n",
					spec_id, loc_mod, loc_name);
			} else {
				pr_warn("loc: failed to map IP 0x%lx to spec #%d for '%s:%s': %s\n",
					target->abs_ip, spec_id, loc_mod, loc_name,
					errstr(err));
			}
			goto err_out;
		}


		opts.bpf_cookie = man->has_bpf_cookie ? spec_id : 0;
		opts.offset = target->abs_ip;
		kprobe_link = bpf_program__attach_kprobe_opts(prog, NULL, &opts);
		err = libbpf_get_error(kprobe_link);
		if (err) {
			pr_warn("loc: failed to attach kprobe #%d for '%s:%s': %s\n",
				i, loc_mod, loc_name, errstr(err));
				goto err_out;
		}

		link->kprobes[i].link = kprobe_link;
		link->kprobes[i].abs_ip = target->abs_ip;
		link->kprobe_cnt++;
	}

	return &link->link;

err_out:
	pr_warn("loc: failed to attach to all loc targets for '%s:%s': %d\n",
		loc_mod, loc_name, err);
	free(cookies);

	if (link)
		bpf_link__destroy(&link->link);
	free(targets);
	return libbpf_err_ptr(err);
}

/* Architecture-specific logic for parsing location info */

#if defined(__x86_64__) || defined(__i386__)

static int calc_pt_regs_off(uint16_t num)
{
	size_t reg_map[] = {
#ifdef __x86_64__
#define reg_off(reg64, reg32) offsetof(struct pt_regs, reg64)
#else
#define reg_off(reg64, reg32) offsetof(struct pt_regs, reg32)
#endif
		reg_off(rax, eax),
		reg_off(rdx, edx),
		reg_off(rcx, ecx),
		reg_off(rbx, ebx),
		reg_off(rsi, esi),
		reg_off(rdi, edi),
		reg_off(rbp, ebp),
		reg_off(rsp, esp),
		offsetof(struct pt_regs, r8),
		offsetof(struct pt_regs, r9),
		offsetof(struct pt_regs, r10),
		offsetof(struct pt_regs, r11),
		offsetof(struct pt_regs, r12),
		offsetof(struct pt_regs, r13),
		offsetof(struct pt_regs, r14),
		offsetof(struct pt_regs, r15),
		-ENOENT,	
		-ENOENT,
		-ENOENT,
		-ENOENT,
		-ENOENT,
		-ENOENT,
		-ENOENT,
		-ENOENT,
		-ENOENT,
		-ENOENT,
		-ENOENT,
		-ENOENT,
		-ENOENT,
		-ENOENT,
		-ENOENT,
		-ENOENT,
		-ENOENT,
		reg_off(rbp, ebp)
	};

	if (num > ARRAY_SIZE(reg_map) || reg_map[num] == -ENOENT) {
		pr_warn("loc: unsupported register '%d'\n", num);
		return -ENOENT;
	}
	return reg_map[num];
}

#elif defined(__aarch64__)

static int calc_pt_regs_off(int num)
{
	if (num >= 0 && num < 31)
		return offsetof(struct user_pt_regs, regs[reg_num]);
	else if (num == 33)
		return offsetof(struct user_pt_regs, sp);
	pr_warn("loc: unsupported register '%d'\n", num);
	return -ENOENT;
}

#else
static int calc_pt_regs_off(int num)
{
	pr_warn("loc: unsupported platform (register '%d')\n", num);
	return -ENOENT;
}
#endif

static int parse_loc_arg(const struct btf_type *t, __u64 base_addr, short arg_num, struct loc_arg_spec *arg)
{
	const struct btf_loc_param *lp = t ? btf_loc_param(t) : NULL;
	int reg_off, arg_sz;
	bool is_const;

	if (!t) {
		arg->arg_type = BPF_LOC_ARG_UNAVAILABLE;
		return 0;
	}
	is_const = btf_kflag(t);
	arg_sz = BTF_TYPE_LOC_PARAM_SIZE(t);
	if (arg_sz < 0) {
		arg->arg_signed = true;
		arg_sz = -arg_sz;
	}
	switch (arg_sz) {
	case 1: case 2: case 4: case 8:
		arg->arg_bitshift = 64 - arg_sz * 8;
		break;
	default:
		pr_warn("loc: unsupported arg #%d size: %d\n",
			arg_num, arg_sz);
		return -EINVAL;
	}

	if (is_const) {
		arg->arg_type = BPF_LOC_ARG_CONST;
		arg->val_off = lp->val_lo32 | ((__u64)lp->val_hi32 << 32);
		if (arg_sz == 8)
			arg->val_off += base_addr;
	} else {
		reg_off = calc_pt_regs_off(lp->reg);
		if (reg_off < 0)
			return reg_off;
		if (arg->arg_type == BPF_LOC_ARG_REG_MULTI) {
			arg->reg_offs[1] = reg_off;
		} else {
			if (lp->flags & BTF_LOC_FLAG_CONTINUE)
				arg->arg_type = BPF_LOC_ARG_REG_MULTI;
			else
				arg->arg_type = BPF_LOC_ARG_REG;
			arg->reg_off = reg_off;
		}
		arg->val_off = 0;
		if (lp->flags & BTF_LOC_FLAG_REG_DEREF) {
			arg->arg_type = BPF_LOC_ARG_REG_DEREF;
			arg->val_off = lp->offset;
		}
	}
	if (lp->flags & BTF_LOC_FLAG_CONTINUE)
		return 1;
	return 0;
}

static int parse_loc_spec(struct btf *btf, __u64 base_addr, const char *name,
			  __u32 func_proto, __u32 loc_proto, __u32 offset,
			  __u64 loc_cookie, struct loc_spec *spec)
{
	struct loc_arg_spec *arg;
	const struct btf_param *p;
	const struct btf_type *t;
	int ret, i;
	__u32 *l;

	pr_debug("loc: parsing spec for '%s': func_proto_id %u loc_proto_id %u abs_ip 0x%llx\n",
		 name, func_proto, loc_proto, base_addr + offset);
	spec->loc_cookie = loc_cookie;

	t = btf__type_by_id(btf, func_proto);
	if (!t) {
		pr_warn("loc: unknown func proto %u for '%s'\n", func_proto, name);
		return -EINVAL;
	}
	spec->arg_cnt = btf_vlen(t);
	if (spec->arg_cnt >= LOC_MAX_ARG_CNT) {
		pr_warn("loc: too many loc arguments (> %d) for '%s'\n",
			LOC_MAX_ARG_CNT, name);
		return -E2BIG;
	}
	p = btf_params(t);

	t = btf__type_by_id(btf, loc_proto);
	if (!t) {
		pr_warn("loc: unknown loc proto %u for '%s'\n", func_proto, name);
		return -EINVAL;
	}
	l = btf_loc_proto_params(t);

	for (i = 0 ; i < spec->arg_cnt; i++, l++, p++) {
		__u64 addr = 0;

		arg = &spec->args[i];
		if (*l == 0) {
			t = NULL;
		} else {
			__u32 id;

			/* use func proto to determine if the value
			 * is an address; if so we need to add base addr
			 * to value.
			 */
			for (id = p->type;
			     (t = btf__type_by_id(btf, id)) != NULL;
			     id = t->type) {
				if (!btf_is_mod(t) && !btf_is_typedef(t))
					break;
			}
			if (t && btf_is_ptr(t))
				addr = base_addr;

			t = btf__type_by_id(btf, *l);
			if (!t) {
				pr_warn("loc: unknown type id %u for '%s'\n",
					*l, name);
				return -EINVAL;
			}
		}
		ret = parse_loc_arg(t, addr, i, arg);
		if (ret < 0)
			return ret;
		/* multi-reg location param? */
		if (ret > 0) {
			l++;
			t = btf__type_by_id(btf, *l);

			ret = parse_loc_arg(t, addr, i, arg);
		}
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int collect_loc_targets(struct loc_manager *man, const char *mod, const char *name,
			       __u64 loc_cookie, struct loc_target **out_targets,
			       size_t *out_target_cnt)
{
	struct loc_target *tmp, *targets = NULL;
	struct btf *base_btf, *btf = NULL;
	__u32 start_id, type_cnt;
	size_t target_cnt = 0;
	__u64 base_addr = 0;
	int err = 0;
	__u32 i, j;

	base_btf = btf__load_vmlinux_btf();
	if (!IS_ERR(base_btf) && strcmp(mod, "vmlinux") != 0)
		base_btf = btf__load_module_btf(mod, base_btf);
	if (IS_ERR(base_btf))
		return PTR_ERR(base_btf);
	btf = btf__load_btf_extra(mod, base_btf);
	if (IS_ERR(btf)) {
		btf__free(base_btf);
		return PTR_ERR(btf);
	}

	start_id = base_btf ? btf__type_cnt(base_btf) : 1;
	type_cnt = btf__type_cnt(btf);

	err = get_base_addr(mod, &base_addr);
	if (err)
		goto err_out;

	for (i = start_id; i < type_cnt; i++) {
		struct loc_target *target;
		const struct btf_type *t;
		const struct btf_loc *l;
		const char *locname;
		int vlen;

		t = btf__type_by_id(btf, i);
		if (!btf_is_locsec(t))
			continue;
		vlen = btf_vlen(t);
		l = btf_locsec_locs(t);

		for (j = 0; j < vlen; j++, l++) {
			locname = btf__name_by_offset(btf, l->name_off);
			if (!locname || strcmp(name, locname) != 0)
				continue;
			tmp = libbpf_reallocarray(targets, target_cnt + 1, sizeof(*targets));
			if (!tmp) {
				err = -ENOMEM;
				goto err_out;
			}
			targets = tmp;
			target = &targets[target_cnt];
			memset(target, 0, sizeof(*target));
			target->abs_ip = base_addr + l->offset;
			err = parse_loc_spec(btf, base_addr, locname,
					     l->func_proto, l->loc_proto, l->offset,
					     loc_cookie, &target->spec);
			if (err)
				goto err_out;
			target_cnt++;

		}
	}
	*out_targets = targets;
	*out_target_cnt = target_cnt;
	return target_cnt;
err_out:
	free(targets);
	return err;
}
