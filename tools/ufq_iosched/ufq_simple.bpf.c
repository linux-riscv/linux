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
	struct bpf_list_node list_node;
	u64 key;
	struct request __kptr * req;
};

struct ufq_simple_data {
	struct bpf_spin_lock lock;
	struct bpf_rb_root sort_tree_read __contains(sort_tree_node, rb_node);
	struct bpf_rb_root sort_tree_write __contains(sort_tree_node, rb_node);
	struct bpf_list_head dispatch __contains(queue_list_node, node);
	struct bpf_list_head fifo_list __contains(sort_tree_node, list_node);
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
	if (ret) {
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
	struct sort_tree_node *snode, *lnode;
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

		/* Add sort_tree_node to red-black tree and list_node to fifo_list */
		bpf_spin_lock(&ufq_sd->lock);
		if (dir == UFQ_SIMP_READ)
			bpf_rbtree_add(&ufq_sd->sort_tree_read, &snode->rb_node, sort_tree_less);
		else
			bpf_rbtree_add(&ufq_sd->sort_tree_write, &snode->rb_node, sort_tree_less);

		/* Acquire reference count since the node is also added to fifo_list */
		lnode = bpf_refcount_acquire(snode);
		if (!lnode) {
			struct bpf_rb_root *tree = (dir == UFQ_SIMP_READ) ?
				&ufq_sd->sort_tree_read : &ufq_sd->sort_tree_write;
			struct bpf_rb_node *rb_node;

			rb_node = bpf_rbtree_remove(tree, &snode->rb_node);
			bpf_spin_unlock(&ufq_sd->lock);
			if (rb_node)
				bpf_obj_drop(container_of(rb_node, struct sort_tree_node, rb_node));
			bpf_printk("ufq_simple/insert_req: bpf_refcount_acquire failed");
			return -EPERM;
		}

		ret = bpf_list_push_back(&ufq_sd->fifo_list, &lnode->list_node);
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
	struct sort_tree_node *snode, *lnode;
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

		/* Remove list_node from fifo_list (must be done while holding lock) */
		list_node = bpf_list_del(&ufq_sd->fifo_list, &snode->list_node);
		bpf_spin_unlock(&ufq_sd->lock);

		if (list_node) {
			lnode = container_of(list_node, struct sort_tree_node, list_node);
			bpf_obj_drop(lnode);
		}
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
		stat_add(UFQ_SIMP_FINISH_SIZE, rq->__data_len);
		bpf_request_put(rq);
	}
}

struct request *BPF_STRUCT_OPS(ufq_simple_next_req, struct request_queue *q,
			       struct request *rq)
{
	return NULL;
}

struct request *BPF_STRUCT_OPS(ufq_simple_former_req, struct request_queue *q,
			       struct request *rq)
{
	return NULL;
}

struct request *BPF_STRUCT_OPS(ufq_simple_merge_req, struct request_queue *q,
				struct request *rq, int *type)
{
	struct sort_tree_node *snode = NULL, *lnode = NULL;
	sector_t rq_start, rq_end, other_start, other_end;
	enum elv_merge mt = ELEVATOR_NO_MERGE;
	struct bpf_list_node *list_node = NULL;
	struct bpf_rb_node *rb_node = NULL;
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

	while (mt == ELEVATOR_NO_MERGE && rb_node && count < 100) {
		count++;
		snode = container_of(rb_node, struct sort_tree_node, rb_node);
		targ = bpf_kptr_xchg(&snode->req, NULL);
		if (!targ)
			break;

		other_start = targ->__sector;
		other_end = other_start + (targ->__data_len >> SECTOR_SHIFT);

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
			rb_node = bpf_rbtree_remove(tree, rb_node);
			if (rb_node) {
				snode = container_of(rb_node,
					struct sort_tree_node, rb_node);
				targ = bpf_kptr_xchg(&snode->req, NULL);

				list_node = bpf_list_del(&ufq_sd->fifo_list,
							 &snode->list_node);
				bpf_spin_unlock(&ufq_sd->lock);
				if (targ) {
					*type = mt;
					stat_add(UFQ_SIMP_MERGE_CNT, 1);
					stat_add(UFQ_SIMP_MERGE_SIZE, targ->__data_len);
					stat_sub(UFQ_SIMP_INSERT_CNT, 1);
					stat_sub(UFQ_SIMP_INSERT_SIZE, targ->__data_len);
				}

				if (list_node) {
					lnode = container_of(list_node,
						struct sort_tree_node, list_node);
					bpf_obj_drop(lnode);
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

UFQ_OPS_DEFINE(ufq_simple_ops,
	.init_sched		= (void *)ufq_simple_init_sched,
	.exit_sched		= (void *)ufq_simple_exit_sched,
	.insert_req		= (void *)ufq_simple_insert_req,
	.dispatch_req		= (void *)ufq_simple_dispatch_req,
	.has_req		= (void *)ufq_simple_has_req,
	.finish_req		= (void *)ufq_simple_finish_req,
	.next_req		= (void *)ufq_simple_next_req,
	.former_req		= (void *)ufq_simple_former_req,
	.merge_req		= (void *)ufq_simple_merge_req,
	.name			= "ufq_simple");
