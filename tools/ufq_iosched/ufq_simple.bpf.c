// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 KylinSoft Corporation.
 * Copyright (c) 2026 Kaitao Cheng <chengkaitao@kylinos.cn>
 */
#include <ufq/common.bpf.h>

char _license[] SEC("license") = "GPL";

#define UFQ_DISK_SUM		20
#define BLK_MQ_INSERT_AT_HEAD	0x01
#define REQ_OP_MASK		((1 << 8) - 1)
#define SECTOR_SHIFT		9
#define UFQ_LOOP_MAX		100

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, UFQ_SIMP_STAT_MAX);
} stats SEC(".maps");

enum ufq_simp_data_dir {
	UFQ_SIMP_READ,
	UFQ_SIMP_WRITE,
	UFQ_SIMP_DIR_COUNT
};

struct queue_list_node {
	struct bpf_list_node node;
	struct request __kptr * req;
};

struct sort_tree_node {
	struct bpf_refcount ref;
	struct bpf_rb_node rb_node;
	u64 key;
	struct request __kptr * req;
};

struct ufq_simple_data {
	struct bpf_spin_lock lock;
	struct bpf_rb_root sort_tree_read __contains(sort_tree_node, rb_node);
	struct bpf_rb_root sort_tree_write __contains(sort_tree_node, rb_node);
	struct bpf_list_head dispatch __contains(queue_list_node, node);
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, UFQ_DISK_SUM);
	__type(key, s32);
	__type(value, struct ufq_simple_data);
} ufq_map SEC(".maps");

static void stat_add(u32 idx, u32 val)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);

	if (cnt_p)
		(*cnt_p) += val;
}

static void stat_sub(u32 idx, u32 val)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);

	if (cnt_p)
		(*cnt_p) -= val;
}

static bool sort_tree_less(struct bpf_rb_node *a, const struct bpf_rb_node *b)
{
	struct sort_tree_node *node_a, *node_b;

	node_a = container_of(a, struct sort_tree_node, rb_node);
	node_b = container_of(b, struct sort_tree_node, rb_node);

	return node_a->key < node_b->key;
}

static struct ufq_simple_data *dd_init_sched(struct request_queue *q)
{
	struct ufq_simple_data ufq_sd = {}, *ufq_sp;
	int ret, id = q->id;

	bpf_printk("ufq_simple init sched!");
	ret = bpf_map_update_elem(&ufq_map, &id, &ufq_sd, BPF_NOEXIST);
	if (ret && ret != -EEXIST) {
		bpf_printk("ufq_simple/init_sched: update ufq_map err %d", ret);
		return NULL;
	}

	ufq_sp = bpf_map_lookup_elem(&ufq_map, &id);
	if (!ufq_sp) {
		bpf_printk("ufq_simple/init_sched: lookup queue id %d in ufq_map failed", id);
		return NULL;
	}

	return ufq_sp;
}

int BPF_STRUCT_OPS(ufq_simple_init_sched, struct request_queue *q)
{
	if (dd_init_sched(q))
		return 0;
	else
		return -EPERM;
}

int BPF_STRUCT_OPS(ufq_simple_exit_sched, struct request_queue *q)
{
	int id = q->id;

	bpf_printk("ufq_simple exit sched!");
	bpf_map_delete_elem(&ufq_map, &id);
	return 0;
}

int BPF_STRUCT_OPS(ufq_simple_insert_req, struct request_queue *q,
		   struct request *rq, blk_insert_t flags,
		   struct list_head *freeq)
{
	struct ufq_simple_data *ufq_sd;
	struct queue_list_node *qnode;
	struct sort_tree_node *snode;
	int id = q->id, ret = 0;
	struct request *acquired, *old;
	enum ufq_simp_data_dir dir = ((rq->cmd_flags & REQ_OP_MASK) & 1) ?
				   UFQ_SIMP_WRITE : UFQ_SIMP_READ;

	ufq_sd = bpf_map_lookup_elem(&ufq_map, &id);
	if (!ufq_sd) {
		ufq_sd = dd_init_sched(q);
		if (!ufq_sd) {
			bpf_printk("ufq_simple/insert_req: dd_init_sched failed");
			return -EPERM;
		}
	}

	if (flags & BLK_MQ_INSERT_AT_HEAD) {
		/* create queue_list_node */
		qnode = bpf_obj_new(typeof(*qnode));
		if (!qnode) {
			bpf_printk("ufq_simple/insert_req: qnode alloc failed");
			return -ENOMEM;
		}

		acquired = bpf_request_acquire(rq);
		if (!acquired) {
			bpf_obj_drop(qnode);
			bpf_printk("ufq_simple/head-insert_req: request_acquire failed");
			return -EPERM;
		}

		/* Set request for queue_list_node */
		old = bpf_kptr_xchg(&qnode->req, acquired);
		if (old)
			bpf_request_release(old);

		/* Add queue_list_node to dispatch list */
		bpf_spin_lock(&ufq_sd->lock);
		ret = bpf_list_push_back(&ufq_sd->dispatch, &qnode->node);
		bpf_spin_unlock(&ufq_sd->lock);
	} else {
		/* create sort_tree_node */
		snode = bpf_obj_new(typeof(*snode));
		if (!snode) {
			bpf_printk("ufq_simple/insert_req: sort_tree_node alloc failed");
			return -ENOMEM;
		}

		/* Use request's starting sector as sort key */
		snode->key = rq->__sector;

		/*
		 * Acquire request reference again for sort_tree_node (each node
		 * needs independent reference)
		 */
		acquired = bpf_request_acquire(rq);
		if (!acquired) {
			bpf_obj_drop(snode);
			bpf_printk("ufq_simple/insert_req: bpf_request_acquire failed");
			return -EPERM;
		}

		/* Set request for sort_tree_node */
		old = bpf_kptr_xchg(&snode->req, acquired);
		if (old)
			bpf_request_release(old);

		/* Add sort_tree_node to red-black tree */
		bpf_spin_lock(&ufq_sd->lock);
		if (dir == UFQ_SIMP_READ)
			bpf_rbtree_add(&ufq_sd->sort_tree_read, &snode->rb_node, sort_tree_less);
		else
			bpf_rbtree_add(&ufq_sd->sort_tree_write, &snode->rb_node, sort_tree_less);
		bpf_spin_unlock(&ufq_sd->lock);
	}

	if (!ret) {
		stat_add(UFQ_SIMP_INSERT_CNT, 1);
		stat_add(UFQ_SIMP_INSERT_SIZE, rq->__data_len);
	}
	return ret;
}

struct request *BPF_STRUCT_OPS(ufq_simple_dispatch_req, struct request_queue *q)
{
	struct request *rq = NULL;
	struct bpf_list_node *list_node;
	struct bpf_rb_node *rb_node = NULL;
	struct queue_list_node *qnode;
	struct sort_tree_node *snode;
	struct ufq_simple_data *ufq_sd;
	int id = q->id;

	ufq_sd = bpf_map_lookup_elem(&ufq_map, &id);
	if (!ufq_sd) {
		bpf_printk("ufq_simple/dispatch_req: ufq_map lookup %d failed", id);
		return NULL;
	}

	bpf_spin_lock(&ufq_sd->lock);
	list_node = bpf_list_pop_front(&ufq_sd->dispatch);

	if (list_node) {
		qnode = container_of(list_node, struct queue_list_node, node);
		rq = bpf_kptr_xchg(&qnode->req, NULL);
		bpf_spin_unlock(&ufq_sd->lock);
		bpf_obj_drop(qnode);
	} else {
		rb_node = bpf_rbtree_first(&ufq_sd->sort_tree_read);
		if (rb_node) {
			rb_node = bpf_rbtree_remove(&ufq_sd->sort_tree_read, rb_node);
		} else {
			rb_node = bpf_rbtree_first(&ufq_sd->sort_tree_write);
			if (rb_node)
				rb_node = bpf_rbtree_remove(&ufq_sd->sort_tree_write, rb_node);
		}

		if (!rb_node) {
			bpf_spin_unlock(&ufq_sd->lock);
			goto out;
		}

		snode = container_of(rb_node, struct sort_tree_node, rb_node);

		/* Get request from sort_tree_node (this will be returned) */
		rq = bpf_kptr_xchg(&snode->req, NULL);
		bpf_spin_unlock(&ufq_sd->lock);
		bpf_obj_drop(snode);
	}
	if (!rq)
		bpf_printk("ufq_simple/dispatch_req: no request to dispatch");

out:
	if (rq) {
		stat_add(UFQ_SIMP_DISPATCH_CNT, 1);
		stat_add(UFQ_SIMP_DISPATCH_SIZE, rq->__data_len);
	}

	return rq;
}

bool BPF_STRUCT_OPS(ufq_simple_has_req, struct request_queue *q, int rqs_count)
{
	struct ufq_simple_data *ufq_sd;
	bool has;
	int id = q->id;

	ufq_sd = bpf_map_lookup_elem(&ufq_map, &id);
	if (!ufq_sd) {
		bpf_printk("ufq_simple/has_req: ufq_map lookup %d failed", id);
		return false;
	}

	bpf_spin_lock(&ufq_sd->lock);
	has = !bpf_list_empty(&ufq_sd->dispatch) ||
	      bpf_rbtree_root(&ufq_sd->sort_tree_read) ||
	      bpf_rbtree_root(&ufq_sd->sort_tree_write);
	bpf_spin_unlock(&ufq_sd->lock);

	return has;
}

void BPF_STRUCT_OPS(ufq_simple_finish_req, struct request *rq)
{
	if (rq) {
		stat_add(UFQ_SIMP_FINISH_CNT, 1);
		stat_add(UFQ_SIMP_FINISH_SIZE, (u64)rq->stats_sectors << SECTOR_SHIFT);
	}
}

struct request *BPF_STRUCT_OPS(ufq_simple_merge_req, struct request_queue *q,
				struct request *rq, int *type)
{
	struct sort_tree_node *snode = NULL;
	sector_t rq_start, rq_end, other_start, other_end;
	enum elv_merge mt = ELEVATOR_NO_MERGE;
	struct bpf_rb_node *rb_node = NULL;
	struct blk_mq_ctx *targ_mq_ctx;
	struct blk_mq_hw_ctx *targ_mq_hctx;
	struct ufq_simple_data *ufq_sd;
	struct request *targ = NULL;
	enum ufq_simp_data_dir dir;
	struct bpf_rb_root *tree;
	int id = q->id;
	int count = 0;

	*type = ELEVATOR_NO_MERGE;
	dir = ((rq->cmd_flags & REQ_OP_MASK) & 1) ? UFQ_SIMP_WRITE : UFQ_SIMP_READ;
	ufq_sd = bpf_map_lookup_elem(&ufq_map, &id);
	if (!ufq_sd)
		return NULL;

	/* Calculate current request position and end */
	rq_start = rq->__sector;
	rq_end = rq_start + (rq->__data_len >> SECTOR_SHIFT);

	if (dir == UFQ_SIMP_READ)
		tree = &ufq_sd->sort_tree_read;
	else
		tree = &ufq_sd->sort_tree_write;

	bpf_spin_lock(&ufq_sd->lock);
	rb_node = bpf_rbtree_root(tree);
	if (!rb_node) {
		bpf_spin_unlock(&ufq_sd->lock);
		return NULL;
	}

	while (mt == ELEVATOR_NO_MERGE && rb_node && count < UFQ_LOOP_MAX) {
		count++;
		snode = container_of(rb_node, struct sort_tree_node, rb_node);
		targ = bpf_kptr_xchg(&snode->req, NULL);
		if (!targ)
			break;

		other_start = targ->__sector;
		other_end = other_start + (targ->__data_len >> SECTOR_SHIFT);
		targ_mq_ctx = targ->mq_ctx;
		targ_mq_hctx = targ->mq_hctx;

		targ = bpf_kptr_xchg(&snode->req, targ);
		if (targ) {
			bpf_spin_unlock(&ufq_sd->lock);
			bpf_request_release(targ);
			return NULL;
		}

		if (rq_start > other_end)
			rb_node = bpf_rbtree_right(tree, rb_node);
		else if (rq_end < other_start)
			rb_node = bpf_rbtree_left(tree, rb_node);
		else if (rq_end == other_start)
			mt = ELEVATOR_FRONT_MERGE;
		else if (other_end == rq_start)
			mt = ELEVATOR_BACK_MERGE;
		else
			break;

		if (mt) {
			if (rq->mq_ctx != targ_mq_ctx || rq->mq_hctx != targ_mq_hctx) {
				mt = ELEVATOR_NO_MERGE;
				break;
			}

			rb_node = bpf_rbtree_remove(tree, rb_node);
			if (rb_node) {
				snode = container_of(rb_node,
					struct sort_tree_node, rb_node);
				targ = bpf_kptr_xchg(&snode->req, NULL);
				bpf_spin_unlock(&ufq_sd->lock);
				if (targ) {
					*type = mt;
					stat_add(UFQ_SIMP_RQMERGE_CNT, 1);
					stat_add(UFQ_SIMP_RQMERGE_SIZE, targ->__data_len);
					stat_sub(UFQ_SIMP_INSERT_CNT, 1);
					stat_sub(UFQ_SIMP_INSERT_SIZE, targ->__data_len);
				}

				bpf_obj_drop(snode);
			} else {
				bpf_spin_unlock(&ufq_sd->lock);
				*type = ELEVATOR_NO_MERGE;
			}
			return targ;
		}
	}
	bpf_spin_unlock(&ufq_sd->lock);

	return NULL;
}

static struct request *merge_bio_left_unlock(struct ufq_simple_data *ufq_sd,
					     struct bpf_rb_root *tree,
					     struct sort_tree_node *snode,
					     struct request *cand)
{
	sector_t cand_start, left_start, left_end;
	struct request *free = NULL;
	struct request *left_rq = NULL;
	struct sort_tree_node *left_node = NULL;
	struct bpf_rb_node *tmp, *removed = NULL;

	cand_start = cand->__sector;
	tmp = bpf_rbtree_left(tree, &snode->rb_node);
	if (!tmp)
		goto end;

	left_node = container_of(tmp, struct sort_tree_node, rb_node);
	if (!left_node)
		goto end;

	left_rq = bpf_kptr_xchg(&left_node->req, NULL);
	if (!left_rq)
		goto end;

	left_start = left_rq->__sector;
	left_end = left_start + (left_rq->__data_len >> SECTOR_SHIFT);

	if (left_end == cand_start)
		free = bpf_request_try_merge(left_rq, cand);

	if (free == cand) {
		removed = bpf_rbtree_remove(tree, &snode->rb_node);
		left_rq = bpf_kptr_xchg(&left_node->req, left_rq);
		bpf_spin_unlock(&ufq_sd->lock);
		if (removed) {
			struct sort_tree_node *drop = container_of(removed,
					struct sort_tree_node, rb_node);
			bpf_obj_drop(drop);
		}
		stat_add(UFQ_SIMP_RQMERGE_CNT, 1);
		stat_add(UFQ_SIMP_RQMERGE_SIZE, free->__data_len);

		if (left_rq)
			bpf_request_release(left_rq);

		return free;
	}

	left_rq = bpf_kptr_xchg(&left_node->req, left_rq);

end:
	cand = bpf_kptr_xchg(&snode->req, cand);
	bpf_spin_unlock(&ufq_sd->lock);
	if (left_rq)
		bpf_request_release(left_rq);

	if (cand)
		bpf_request_release(cand);

	return NULL;
}

static struct request *merge_bio_right_unlock(struct ufq_simple_data *ufq_sd,
					      struct bpf_rb_root *tree,
					      struct sort_tree_node *snode,
					      struct request *cand)
{
	sector_t cand_end, right_start;
	struct request *free = NULL;
	struct request *right_rq = NULL;
	struct sort_tree_node *right_node = NULL;
	struct bpf_rb_node *right_rb, *removed = NULL;

	cand_end = cand->__sector + (cand->__data_len >> SECTOR_SHIFT);

	right_rb = bpf_rbtree_right(tree, &snode->rb_node);
	if (!right_rb)
		goto end;

	right_node = container_of(right_rb, struct sort_tree_node, rb_node);
	if (!right_node)
		goto end;

	right_rq = bpf_kptr_xchg(&right_node->req, NULL);
	if (!right_rq)
		goto end;

	right_start = right_rq->__sector;
	if (cand_end == right_start)
		free = bpf_request_try_merge(cand, right_rq);

	if (free == right_rq) {
		removed = bpf_rbtree_remove(tree, right_rb);
		cand = bpf_kptr_xchg(&snode->req, cand);
		bpf_spin_unlock(&ufq_sd->lock);
		if (removed) {
			struct sort_tree_node *drop = container_of(removed,
					struct sort_tree_node, rb_node);
			bpf_obj_drop(drop);
		}
		stat_add(UFQ_SIMP_RQMERGE_CNT, 1);
		stat_add(UFQ_SIMP_RQMERGE_SIZE, free->__data_len);

		if (cand)
			bpf_request_release(cand);

		return free;
	}

	right_rq = bpf_kptr_xchg(&right_node->req, right_rq);

end:
	cand = bpf_kptr_xchg(&snode->req, cand);
	bpf_spin_unlock(&ufq_sd->lock);
	if (right_rq)
		bpf_request_release(right_rq);

	if (cand)
		bpf_request_release(cand);

	return NULL;
}

struct request *BPF_STRUCT_OPS(ufq_simple_merge_bio,
			       struct request_queue *q, struct bio *bio,
			       unsigned int nr_segs, bool *merged)
{
	sector_t start, end, cand_start, cand_end;
	struct request *cand = NULL, *old, *free = NULL;
	struct sort_tree_node *snode = NULL;
	struct bpf_rb_node *rb_node = NULL;
	struct ufq_simple_data *ufq_sd;
	enum ufq_simp_data_dir dir;
	int id = q->id, count = 0;
	struct bpf_rb_root *tree;

	if (!merged)
		return NULL;
	start = bio->bi_iter.bi_sector;
	end = start + (bio->bi_iter.bi_size >> SECTOR_SHIFT);
	dir = ((bio->bi_opf & REQ_OP_MASK) & 1) ? UFQ_SIMP_WRITE : UFQ_SIMP_READ;
	ufq_sd = bpf_map_lookup_elem(&ufq_map, &id);
	if (!ufq_sd)
		return NULL;

	bpf_spin_lock(&ufq_sd->lock);
	if (dir == UFQ_SIMP_READ)
		tree = &ufq_sd->sort_tree_read;
	else
		tree = &ufq_sd->sort_tree_write;

	rb_node = bpf_rbtree_root(tree);
	while (rb_node && count < UFQ_LOOP_MAX) {
		count++;
		snode = container_of(rb_node, struct sort_tree_node, rb_node);
		cand = bpf_kptr_xchg(&snode->req, NULL);
		if (!cand)
			break;

		cand_start = cand->__sector;
		cand_end = cand_start + (cand->__data_len >> SECTOR_SHIFT);

		if (end < cand_start) {
			rb_node = bpf_rbtree_left(tree, rb_node);
		} else if (start > cand_end) {
			rb_node = bpf_rbtree_right(tree, rb_node);
		} else if (cand_start == end) {
			if (bpf_request_bio_try_merge(cand, bio, nr_segs)) {
				*merged = true;
				free = merge_bio_left_unlock(ufq_sd, tree, snode, cand);
				stat_add(UFQ_SIMP_BIOMERGE_CNT, 1);
				stat_add(UFQ_SIMP_BIOMERGE_SIZE, bio->bi_iter.bi_size);
				return free;
			}
			rb_node = NULL;
		} else if (cand_end == start) {
			if (bpf_request_bio_try_merge(cand, bio, nr_segs)) {
				*merged = true;
				free = merge_bio_right_unlock(ufq_sd, tree, snode, cand);
				stat_add(UFQ_SIMP_BIOMERGE_CNT, 1);
				stat_add(UFQ_SIMP_BIOMERGE_SIZE, bio->bi_iter.bi_size);
				return free;
			}
			rb_node = NULL;
		} else {
			rb_node = NULL;
		}

		old = bpf_kptr_xchg(&snode->req, cand);
		if (old) {
			bpf_spin_unlock(&ufq_sd->lock);
			bpf_request_release(old);
			return NULL;
		}
	}

	bpf_spin_unlock(&ufq_sd->lock);
	return NULL;
}

UFQ_OPS_DEFINE(ufq_simple_ops,
	.init_sched		= (void *)ufq_simple_init_sched,
	.exit_sched		= (void *)ufq_simple_exit_sched,
	.insert_req		= (void *)ufq_simple_insert_req,
	.dispatch_req		= (void *)ufq_simple_dispatch_req,
	.has_req		= (void *)ufq_simple_has_req,
	.finish_req		= (void *)ufq_simple_finish_req,
	.merge_req		= (void *)ufq_simple_merge_req,
	.merge_bio		= (void *)ufq_simple_merge_bio,
	.name			= "ufq_simple");
