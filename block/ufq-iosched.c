// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 KylinSoft Corporation.
 * Copyright (c) 2026 Kaitao Cheng <chengkaitao@kylinos.cn>
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/compiler.h>
#include <linux/sbitmap.h>

#include <trace/events/block.h>

#include "elevator.h"
#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-sched.h"
#include "blk-mq-debugfs.h"
#include "ufq-iosched.h"

/* For testing and debugging */
struct ufq_ops_stats {
	atomic_t dispatch_ok_count;
	atomic64_t dispatch_ok_sectors;
	atomic_t dispatch_null_count;
	atomic_t insert_ok_count;
	atomic64_t insert_ok_sectors;
	atomic_t insert_err_count;
	atomic_t merge_ok_count;
	atomic64_t merge_ok_sectors;
	atomic_t finish_ok_count;
	atomic64_t finish_ok_sectors;
};

struct ufq_data {
	struct request_queue *q;
	u32 async_depth;
	atomic_t rqs_count;
	struct ufq_ops_stats ops_stats;
};

enum ufq_priv_state {
	UFQ_PRIV_NOT_IN_SCHED = 0,
	UFQ_PRIV_IN_BPF = 1,
	UFQ_PRIV_IN_UFQ = 2,
	UFQ_PRIV_IN_SCHED = 3,
};

static void ufq_request_merged(struct request_queue *q, struct request *req,
			       enum elv_merge type)
{
	if (ufq_ops.req_merged)
		ufq_ops.req_merged(q, req, (int)type);
}

static struct request *ufq_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct ufq_data *ufq = hctx->queue->elevator->elevator_data;
	struct blk_mq_ctx *ctx;
	struct request *rq = NULL;
	unsigned short idx;

	if (ufq_ops.dispatch_req) {
		rq = ufq_ops.dispatch_req(hctx->queue);
		if (!rq) {
			atomic_inc(&ufq->ops_stats.dispatch_null_count);
			return NULL;
		}
		atomic_inc(&ufq->ops_stats.dispatch_ok_count);
		atomic64_add(blk_rq_sectors(rq), &ufq->ops_stats.dispatch_ok_sectors);

		ctx = rq->mq_ctx;
		spin_lock(&ctx->lock);
		list_del_init(&rq->queuelist);
		rq->rq_flags |= RQF_STARTED;
		if (hctx->queue->last_merge == rq)
			hctx->queue->last_merge = NULL;
		if (list_empty(&ctx->rq_lists[rq->mq_hctx->type]))
			sbitmap_clear_bit(&rq->mq_hctx->ctx_map,
					  ctx->index_hw[rq->mq_hctx->type]);
		spin_unlock(&ctx->lock);
		rq->elv.priv[0] = (void *)((uintptr_t)rq->elv.priv[0]
				  & ~UFQ_PRIV_IN_UFQ);
	} else {
		ctx = READ_ONCE(hctx->dispatch_from);
		rq = blk_mq_dequeue_from_ctx(hctx, ctx);
		if (rq) {
			idx = rq->mq_ctx->index_hw[hctx->type];
			if (++idx == hctx->nr_ctx)
				idx = 0;
			WRITE_ONCE(hctx->dispatch_from, hctx->ctxs[idx]);
		}
	}

	if (rq)
		atomic_dec(&ufq->rqs_count);
	return rq;
}

/*
 * Called by __blk_mq_alloc_request(). The shallow_depth value set by this
 * function is used by __blk_mq_get_tag().
 */
static void ufq_limit_depth(blk_opf_t opf, struct blk_mq_alloc_data *data)
{
	struct ufq_data *ufq = data->q->elevator->elevator_data;

	/* Do not throttle synchronous reads. */
	if (op_is_sync(opf) && !op_is_write(opf))
		return;

	/*
	 * Throttle asynchronous requests and writes such that these requests
	 * do not block the allocation of synchronous requests.
	 */
	data->shallow_depth = ufq->async_depth;
}

static void ufq_depth_updated(struct request_queue *q)
{
	struct ufq_data *ufq = q->elevator->elevator_data;

	ufq->async_depth = q->nr_requests;
	q->async_depth = q->nr_requests;
	blk_mq_set_min_shallow_depth(q, 1);
}

static int ufq_init_sched(struct request_queue *q, struct elevator_queue *eq)
{
	struct ufq_data *ufq;

	ufq = kzalloc_node(sizeof(*ufq), GFP_KERNEL, q->node);
	if (!ufq)
		return -ENOMEM;

	eq->elevator_data = ufq;
	ufq->q = q;

	blk_queue_flag_set(QUEUE_FLAG_SQ_SCHED, q);
	q->elevator = eq;

	q->async_depth = q->nr_requests;
	ufq->async_depth = q->nr_requests;

	if (ufq_ops.init_sched)
		ufq_ops.init_sched(q);

	ufq_depth_updated(q);
	return 0;
}

static void ufq_exit_sched(struct elevator_queue *e)
{
	struct ufq_data *ufq = e->elevator_data;

	if (ufq_ops.exit_sched)
		ufq_ops.exit_sched(ufq->q);

	WARN_ON_ONCE(atomic_read(&ufq->rqs_count));

	kfree(ufq);
}

static void ufq_merged_request(struct request_queue *q, struct request *rq,
		enum elv_merge type)
{
	struct elevator_queue *e = q->elevator;

	if (e->type->ops.request_merged)
		e->type->ops.request_merged(q, rq, type);

	q->last_merge = rq;
}

static bool ufq_sched_try_merge(struct request_queue *q, struct bio *bio,
		unsigned int nr_segs, struct request **merged_request)
{
	enum elv_merge type = ELEVATOR_NO_MERGE;
	struct request *rq = NULL, *last;
	bool ret;


	/*
	 * Levels of merges:
	 *	nomerges:  No merges at all attempted
	 *	noxmerges: Only simple one-hit cache try
	 *	merges:    All merge tries attempted
	 */
	if (blk_queue_nomerges(q) || !bio_mergeable(bio))
		return false;

	last = q->last_merge;
	if (last) {
		spin_lock(&last->mq_ctx->lock);
		if (last == q->last_merge && elv_bio_merge_ok(last, bio)) {
			type = blk_try_merge(last, bio);
			if (type != ELEVATOR_NO_MERGE) {
				rq = last;
				goto merge;
			}
		}
		spin_unlock(&last->mq_ctx->lock);
	}

	if (blk_queue_noxmerges(q))
		return false;

	if (ufq_ops.find_req_from_sector) {
		rq = ufq_ops.find_req_from_sector(q, bio->bi_iter.bi_sector,
						    bio_end_sector(bio));
		if (rq && elv_bio_merge_ok(rq, bio))
			type = blk_try_merge(rq, bio);
		else
			return false;
	}

	if (!rq || type == ELEVATOR_NO_MERGE)
		return false;

	spin_lock(&rq->mq_ctx->lock);
merge:
	ret = blk_mq_sched_merge_fn(q, bio, nr_segs, merged_request, rq,
				    type, ufq_merged_request);
	spin_unlock(&rq->mq_ctx->lock);

	return ret;
}

/*
 * Attempt to merge a bio into an existing request. This function is called
 * before @bio is associated with a request.
 */
static bool ufq_bio_merge(struct request_queue *q, struct bio *bio,
		unsigned int nr_segs)
{
	struct ufq_data *ufq = q->elevator->elevator_data;
	struct request *free = NULL;
	bool ret;

	ret = ufq_sched_try_merge(q, bio, nr_segs, &free);

	if (free) {
		blk_mq_free_request(free);
		atomic_dec(&ufq->rqs_count);
	}

	return ret;
}

static enum elv_merge ufq_try_insert_merge(struct request_queue *q,
					   struct request **new)
{
	struct request *target = NULL, *free = NULL, *last, *rq = *new;
	struct ufq_data *ufq = q->elevator->elevator_data;
	enum elv_merge type = ELEVATOR_NO_MERGE;
	int merge_type = ELEVATOR_NO_MERGE;

	if (!rq_mergeable(rq))
		return ELEVATOR_NO_MERGE;

	if (blk_queue_nomerges(q))
		return ELEVATOR_NO_MERGE;

	last = q->last_merge;
	if (last) {
		spin_lock(&last->mq_ctx->lock);
		if (last == q->last_merge && bpf_attempt_merge(q, last, rq)) {
			spin_unlock(&last->mq_ctx->lock);
			type = ELEVATOR_BACK_MERGE;
			free = rq;
			*new = NULL;
			goto end;
		}
		spin_unlock(&last->mq_ctx->lock);
	}

	if (blk_queue_noxmerges(q))
		return ELEVATOR_NO_MERGE;

	if (ufq_ops.merge_req) {
		target = ufq_ops.merge_req(q, rq, &merge_type);
		type = (enum elv_merge)merge_type;
	}

	if (type == ELEVATOR_NO_MERGE || !target) {
		return ELEVATOR_NO_MERGE;
	} else if (type == ELEVATOR_FRONT_MERGE) {
		spin_lock(&target->mq_ctx->lock);
		free = bpf_attempt_merge(q, rq, target);
		if (!free) {
			spin_unlock(&target->mq_ctx->lock);
			pr_err("ufq-iosched: front merge failed\n");
			return ELEVATOR_NO_MERGE;
		}
		rq->elv.priv[0] = (void *)((uintptr_t)rq->elv.priv[0]
				  | UFQ_PRIV_IN_UFQ);
		list_replace_init(&target->queuelist, &rq->queuelist);
		rq->fifo_time = target->fifo_time;
		q->last_merge = rq;
	} else if (type == ELEVATOR_BACK_MERGE) {
		spin_lock(&target->mq_ctx->lock);
		free = bpf_attempt_merge(q, target, rq);
		if (!free) {
			spin_unlock(&target->mq_ctx->lock);
			pr_err("ufq-iosched: back merge failed\n");
			return ELEVATOR_NO_MERGE;
		}
		*new = target;
		q->last_merge = target;
	}

	spin_unlock(&target->mq_ctx->lock);
end:
	atomic_inc(&ufq->ops_stats.merge_ok_count);
	atomic64_add(blk_rq_sectors(free), &ufq->ops_stats.merge_ok_sectors);
	blk_mq_free_request(free);
	return type;
}

static void ufq_insert_requests(struct blk_mq_hw_ctx *hctx,
			       struct list_head *list,
			       blk_insert_t flags)
{
	struct request_queue *q = hctx->queue;
	struct ufq_data *ufq = q->elevator->elevator_data;
	struct blk_mq_ctx *ctx;
	enum elv_merge type;
	int bit, ret = 0;

	while (!list_empty(list)) {
		struct request *rq;

		rq = list_first_entry(list, struct request, queuelist);
		list_del_init(&rq->queuelist);

		type = ufq_try_insert_merge(q, &rq);
		if (type == ELEVATOR_NO_MERGE) {
			rq->fifo_time = jiffies;
			ctx = rq->mq_ctx;
			rq->elv.priv[0] = (void *)((uintptr_t)rq->elv.priv[0]
					  | UFQ_PRIV_IN_UFQ);
			spin_lock(&ctx->lock);
			if (flags & BLK_MQ_INSERT_AT_HEAD)
				list_add(&rq->queuelist, &ctx->rq_lists[hctx->type]);
			else
				list_add_tail(&rq->queuelist,
					&ctx->rq_lists[hctx->type]);

			bit = ctx->index_hw[hctx->type];
			if (!sbitmap_test_bit(&hctx->ctx_map, bit))
				sbitmap_set_bit(&hctx->ctx_map, bit);
			q->last_merge = rq;
			spin_unlock(&ctx->lock);
			atomic_inc(&ufq->rqs_count);
		}

		if (rq && ufq_ops.insert_req) {
			rq->elv.priv[0] = (void *)((uintptr_t)rq->elv.priv[0]
				  | UFQ_PRIV_IN_BPF);
			ret = ufq_ops.insert_req(q, rq, flags);
			if (ret) {
				atomic_inc(&ufq->ops_stats.insert_err_count);
				pr_err("ufq-iosched: bpf insert_req error (%d)\n", ret);
			} else {
				atomic_inc(&ufq->ops_stats.insert_ok_count);
				atomic64_add(blk_rq_sectors(rq), &ufq->ops_stats.insert_ok_sectors);
			}
		}
	}
}

static void ufq_prepare_request(struct request *rq)
{
	rq->elv.priv[0] = (void *)(uintptr_t)UFQ_PRIV_NOT_IN_SCHED;
}

static void ufq_finish_request(struct request *rq)
{
	struct ufq_data *ufq = rq->q->elevator->elevator_data;

	/*
	 * The block layer core may call ufq_finish_request() without having
	 * called ufq_insert_requests(). Skip requests that bypassed I/O
	 * scheduling.
	 */
	if (!((uintptr_t)rq->elv.priv[0] & UFQ_PRIV_IN_BPF))
		return;

	if (ufq_ops.finish_req)
		ufq_ops.finish_req(rq);

	atomic_inc(&ufq->ops_stats.finish_ok_count);
	atomic64_add(blk_rq_stats_sectors(rq), &ufq->ops_stats.finish_ok_sectors);
}

static struct request *ufq_find_next_request(struct request_queue *q, struct request *rq)
{
	if (ufq_ops.next_req)
		return ufq_ops.next_req(q, rq);

	return NULL;
}

static struct request *ufq_find_former_request(struct request_queue *q, struct request *rq)
{
	if (ufq_ops.former_req)
		return ufq_ops.former_req(q, rq);

	return NULL;
}

static bool ufq_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct ufq_data *ufq = hctx->queue->elevator->elevator_data;
	int rqs_count = atomic_read(&ufq->rqs_count);

	WARN_ON_ONCE(rqs_count < 0);
	if (ufq_ops.has_req)
		return ufq_ops.has_req(hctx->queue, rqs_count);

	return rqs_count > 0;
}

#ifdef CONFIG_BLK_DEBUG_FS
static int ufq_ops_stats_show(void *data, struct seq_file *m)
{
	struct request_queue *q = data;
	struct ufq_data *ufq = q->elevator->elevator_data;
	struct ufq_ops_stats *s = &ufq->ops_stats;

	/* for debug */
	seq_printf(m, "dispatch_ok_count %d\n",
		   atomic_read(&s->dispatch_ok_count));
	seq_printf(m, "dispatch_ok_sectors %lld\n",
		   (long long)atomic64_read(&s->dispatch_ok_sectors));
	seq_printf(m, "dispatch_null_count %d\n",
		   atomic_read(&s->dispatch_null_count));
	seq_printf(m, "insert_ok_count %d\n",
		   atomic_read(&s->insert_ok_count));
	seq_printf(m, "insert_ok_sectors %lld\n",
		   (long long)atomic64_read(&s->insert_ok_sectors));
	seq_printf(m, "insert_err_count %d\n",
		   atomic_read(&s->insert_err_count));
	seq_printf(m, "merge_ok_count %d\n",
		   atomic_read(&s->merge_ok_count));
	seq_printf(m, "merge_ok_sectors %lld\n",
		   (long long)atomic64_read(&s->merge_ok_sectors));
	seq_printf(m, "finish_ok_count %d\n",
		   atomic_read(&s->finish_ok_count));
	seq_printf(m, "finish_ok_sectors %lld\n",
		   (long long)atomic64_read(&s->finish_ok_sectors));
	return 0;
}

static const struct blk_mq_debugfs_attr ufq_iosched_debugfs_attrs[] = {
	{"ops_stats", 0400, ufq_ops_stats_show},
	{},
};
#endif

static struct elevator_type ufq_iosched_mq = {
	.ops = {
		.depth_updated		= ufq_depth_updated,
		.limit_depth		= ufq_limit_depth,
		.insert_requests	= ufq_insert_requests,
		.dispatch_request	= ufq_dispatch_request,
		.prepare_request	= ufq_prepare_request,
		.finish_request		= ufq_finish_request,
		.next_request		= ufq_find_next_request,
		.former_request		= ufq_find_former_request,
		.bio_merge		= ufq_bio_merge,
		.request_merged		= ufq_request_merged,
		.has_work		= ufq_has_work,
		.init_sched		= ufq_init_sched,
		.exit_sched		= ufq_exit_sched,
	},

#ifdef CONFIG_BLK_DEBUG_FS
	.queue_debugfs_attrs = ufq_iosched_debugfs_attrs,
#endif
	.elevator_name = "ufq",
	.elevator_alias = "ufq_iosched",
	.elevator_owner = THIS_MODULE,
};
MODULE_ALIAS("ufq-iosched");

static int __init ufq_init(void)
{
	int ret;

	ret = elv_register(&ufq_iosched_mq);
	if (ret)
		return ret;

	ret = bpf_ufq_kfunc_init();
	if (ret) {
		pr_err("ufq-iosched: Failed to register kfunc sets (%d)\n", ret);
		elv_unregister(&ufq_iosched_mq);
		return ret;
	}

	ret = bpf_ufq_ops_init();
	if (ret) {
		pr_err("ufq-iosched: Failed to register struct_ops (%d)\n", ret);
		elv_unregister(&ufq_iosched_mq);
		return ret;
	}

	return 0;
}

static void __exit ufq_exit(void)
{
	elv_unregister(&ufq_iosched_mq);
}

module_init(ufq_init);
module_exit(ufq_exit);

MODULE_AUTHOR("Kaitao Cheng <chengkaitao@kylinos.cn>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("User-programmable Flexible Queueing");
