/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 KylinSoft Corporation.
 * Copyright (c) 2026 Kaitao Cheng <chengkaitao@kylinos.cn>
 */
#ifndef _BLOCK_UFQ_IOSCHED_H
#define _BLOCK_UFQ_IOSCHED_H

#include "elevator.h"
#include "blk-mq.h"

#ifndef BPF_IOSCHED_NAME_MAX
#define BPF_IOSCHED_NAME_MAX	16
#endif

struct ufq_iosched_ops {
	int (*init_sched)(struct request_queue *q);
	int (*insert_req)(struct request_queue *q, struct request *rq,
			blk_insert_t flags);
	int (*exit_sched)(struct request_queue *q);
	bool (*has_req)(struct request_queue *q, int rqs_count);
	void (*req_merged)(struct request_queue *q, struct request *rq, int type);
	void (*finish_req)(struct request *rq);
	struct request *(*merge_req)(struct request_queue *q, struct request *rq,
			int *type);
	struct request *(*find_req_from_sector)(struct request_queue *q,
			sector_t start, sector_t end);
	struct request *(*former_req)(struct request_queue *q, struct request *rq);
	struct request *(*next_req)(struct request_queue *q, struct request *rq);
	struct request *(*dispatch_req)(struct request_queue *q);
	char name[BPF_IOSCHED_NAME_MAX];
};
extern struct ufq_iosched_ops ufq_ops;

int bpf_ufq_ops_init(void);
int bpf_ufq_kfunc_init(void);

#endif /* _BLOCK_UFQ_IOSCHED_H */
