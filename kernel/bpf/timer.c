#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/err.h>
#include <linux/idr.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/filter.h>
#include <uapi/linux/btf.h>

struct bpf_timer_list {
	struct timer_list timer;
	struct bpf_prog *prog;
	u64 expires;
	s32 id;
	struct rcu_head rcu;
};

struct bpf_timer_map {
	struct bpf_map map;
	struct idr timer_idr;
	spinlock_t idr_lock;
};

static int timer_map_alloc_check(union bpf_attr *attr)
{
	if (attr->max_entries == 0 || attr->max_entries > INT_MAX ||
	    attr->key_size != 4 || attr->value_size != 8)
		return -EINVAL;

	if (attr->map_flags & BPF_F_MMAPABLE)
		return -EINVAL;

	return 0;
}

static struct bpf_map *timer_map_alloc(union bpf_attr *attr)
{
	struct bpf_timer_map *tmap;

	tmap = kzalloc(sizeof(*tmap), GFP_USER | __GFP_ACCOUNT);
	if (!tmap)
		return ERR_PTR(-ENOMEM);

	bpf_map_init_from_attr(&tmap->map, attr);
	spin_lock_init(&tmap->idr_lock);
	idr_init(&tmap->timer_idr);
	return &tmap->map;
}

static int bpf_timer_delete(int id, void *ptr, void *data)
{
	struct bpf_timer_list *t = ptr;

	del_timer_sync(&t->timer);
	kfree_rcu(t, rcu);
	return 0;
}

static void timer_map_free(struct bpf_map *map)
{
	struct bpf_timer_map *tmap;

	tmap = container_of(map, struct bpf_timer_map, map);
	idr_for_each(&tmap->timer_idr, bpf_timer_delete, NULL);

	rcu_barrier();
	idr_destroy(&tmap->timer_idr);
}

static void *timer_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_timer_map *tmap;
	s32 timer_id = *(s32 *)key;
	struct bpf_timer_list *t;
	void *ret = NULL;

	tmap = container_of(map, struct bpf_timer_map, map);

	rcu_read_lock();
	t = idr_find(&tmap->timer_idr, timer_id);
	if (t) {
		t->expires = t->timer.expires;
		ret = &t->expires;
	}
	rcu_read_unlock();
	return ret;
}

static int timer_map_update_elem(struct bpf_map *map, void *key, void *value,
				 u64 flags)
{
	u64 expires = *(u64 *)value;
	s32 timer_id = *(s32 *)key;
	struct bpf_timer_map *tmap;
	struct bpf_timer_list *t;
	int ret = 0;

	tmap = container_of(map, struct bpf_timer_map, map);

	rcu_read_lock();
	t = idr_find(&tmap->timer_idr, timer_id);
	if (!t)
		ret = -ENOENT;
	else
		mod_timer(&t->timer, (unsigned long)expires);
	rcu_read_unlock();
	return ret;
}

static int timer_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_timer_map *tmap;
	s32 timer_id = *(s32 *)key;
	struct bpf_timer_list *t;
	unsigned long flags;

	tmap = container_of(map, struct bpf_timer_map, map);
	spin_lock_irqsave(&tmap->idr_lock, flags);
	t = idr_remove(&tmap->timer_idr, timer_id);
	spin_unlock_irqrestore(&tmap->idr_lock, flags);
	if (!t)
		return -ENOENT;
	del_timer_sync(&t->timer);
	bpf_prog_put(t->prog);
	kfree_rcu(t, rcu);
	return 0;
}

static int timer_map_get_next_key(struct bpf_map *map, void *key,
				    void *next_key)
{
	struct bpf_timer_map *tmap;
	s32 next_id = *(s32 *)key;
	int ret = 0;

	tmap = container_of(map, struct bpf_timer_map, map);
	rcu_read_lock();
	if (!idr_get_next(&tmap->timer_idr, &next_id))
		ret = -ENOENT;
	rcu_read_unlock();
	*(s32 *)next_key = next_id;
	return ret;
}

static int timer_map_mmap(struct bpf_map *map, struct vm_area_struct *vma)
{
	return -ENOTSUPP;
}

static int timer_map_btf_id;
const struct bpf_map_ops timer_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = timer_map_alloc_check,
	.map_alloc = timer_map_alloc,
	.map_free = timer_map_free,
	.map_mmap = timer_map_mmap,
	.map_lookup_elem = timer_map_lookup_elem,
	.map_update_elem = timer_map_update_elem,
	.map_delete_elem = timer_map_delete_elem,
	.map_get_next_key = timer_map_get_next_key,
	.map_btf_name = "bpf_timer_map",
	.map_btf_id = &timer_map_btf_id,
};

static void bpf_timer_callback(struct timer_list *t)
{
	struct bpf_timer_list *bt = from_timer(bt, t, timer);
	u32 ret;

	rcu_read_lock();
	ret = BPF_PROG_RUN(bt->prog, NULL);
	rcu_read_unlock();

	if (ret)
		mod_timer(&bt->timer, bt->timer.expires + ret);
}

int bpf_timer_create(union bpf_attr *attr)
{
	unsigned int flags, timer_flags = 0;
	struct bpf_timer_map *tmap;
	struct bpf_timer_list *t;
	unsigned long irq_flags;
	struct bpf_prog *prog;
	struct bpf_map *map;
	int ret = 0;

	flags = attr->timer_create.flags;
	if (flags & ~(BTF_TIMER_F_DEFERRABLE | BTF_TIMER_F_PINNED))
		return -EINVAL;

	prog = bpf_prog_get(attr->timer_create.prog_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);
	if (prog->type != BPF_PROG_TYPE_TIMER) {
		ret = -EINVAL;
		goto out_prog_put;
	}

	map = bpf_map_get(attr->timer_create.map_fd);
	if (IS_ERR(map)) {
		ret = PTR_ERR(map);
		goto out_prog_put;
	}
	if (map->map_type != BPF_MAP_TYPE_TIMER) {
		ret = -EINVAL;
		goto out_map_put;
	}

	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (!t) {
		ret = -ENOMEM;
		goto out_map_put;
	}

	if (flags & BTF_TIMER_F_DEFERRABLE)
		timer_flags |= TIMER_DEFERRABLE;
	if (flags & BTF_TIMER_F_PINNED)
		timer_flags |= TIMER_PINNED;
	timer_setup(&t->timer, bpf_timer_callback, timer_flags);
	t->prog = prog;

	tmap = container_of(map, struct bpf_timer_map, map);
	spin_lock_irqsave(&tmap->idr_lock, irq_flags);
	ret = idr_alloc_cyclic(&tmap->timer_idr, t, 0, INT_MAX, GFP_ATOMIC);
	spin_unlock_irqrestore(&tmap->idr_lock, irq_flags);
	if (ret < 0)
		kfree(t);
	else
		t->id = ret;

out_map_put:
	bpf_map_put(map);
out_prog_put:
	if (ret)
		bpf_prog_put(prog);
	return ret;
}
