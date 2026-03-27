// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 KylinSoft Corporation.
 * Copyright (c) 2026 Kaitao Cheng <chengkaitao@kylinos.cn>
 */
#include <linux/init.h>
#include <linux/types.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/string.h>
#include "ufq-iosched.h"

struct ufq_iosched_ops ufq_ops;

static const struct bpf_func_proto *
bpf_ufq_get_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id, prog);
}

static bool bpf_ufq_is_valid_access(int off, int size,
				    enum bpf_access_type type,
				    const struct bpf_prog *prog,
				    struct bpf_insn_access_aux *info)
{
	if (type != BPF_READ)
		return false;
	if (off < 0 || off >= sizeof(__u64) * MAX_BPF_FUNC_ARGS)
		return false;
	if (off % size != 0)
		return false;

	/*
	 * merge_req's third argument is int *type.  btf_ctx_access() treats
	 * pointers that are not "pointer to struct" as scalars (no reg_type),
	 * so loading the pointer from ctx leaves a SCALAR and *type stores
	 * fail verification.  Model it as a read/write buffer of merge_type.
	 */
	if (off == 16 && size == sizeof(__u64) &&
	    prog->aux->attach_func_name &&
	    !strcmp(prog->aux->attach_func_name, "merge_req")) {
		if (!btf_ctx_access(off, size, type, prog, info))
			return false;
		info->reg_type = PTR_TO_BUF;
		return true;
	}

	return btf_ctx_access(off, size, type, prog, info);
}

static const struct bpf_verifier_ops bpf_ufq_verifier_ops = {
	.get_func_proto = bpf_ufq_get_func_proto,
	.is_valid_access = bpf_ufq_is_valid_access,
};

static int bpf_ufq_init_member(const struct btf_type *t,
			       const struct btf_member *member,
			       void *kdata, const void *udata)
{
	const struct ufq_iosched_ops *uops = udata;
	struct ufq_iosched_ops *ops = kdata;
	u32 moff = __btf_member_bit_offset(t, member) / 8;
	int ret;

	switch (moff) {
	case offsetof(struct ufq_iosched_ops, name):
		ret = bpf_obj_name_cpy(ops->name, uops->name,
				       sizeof(ops->name));
		if (ret < 0)
			return ret;
		if (ret == 0)
			return -EINVAL;
		return 1;
	/* other var adding .... */
	}

	return 0;
}

static int bpf_ufq_check_member(const struct btf_type *t,
				const struct btf_member *member,
				const struct bpf_prog *prog)
{
	return 0;
}

static int bpf_ufq_enable(struct ufq_iosched_ops *ops)
{
	ufq_ops = *ops;
	return 0;
}

static void bpf_ufq_disable(struct ufq_iosched_ops *ops)
{
	memset(&ufq_ops, 0, sizeof(ufq_ops));
}

static int bpf_ufq_reg(void *kdata, struct bpf_link *link)
{
	return bpf_ufq_enable(kdata);
}

static void bpf_ufq_unreg(void *kdata, struct bpf_link *link)
{
	bpf_ufq_disable(kdata);
}

static int bpf_ufq_init(struct btf *btf)
{
	return 0;
}

static int bpf_ufq_update(void *kdata, void *old_kdata, struct bpf_link *link)
{
	/*
	 * UFQ does not support live-updating an already-attached BPF scheduler:
	 * partial failure during callback setup (e.g. init_sched) would be hard
	 * to reason about, and update can race with unregister/teardown.
	 */
	return -EOPNOTSUPP;
}

static int bpf_ufq_validate(void *kdata)
{
	return 0;
}

static int init_sched_stub(struct request_queue *q)
{
	return -EPERM;
}

static int exit_sched_stub(struct request_queue *q)
{
	return -EPERM;
}

static int insert_req_stub(struct request_queue *q, struct request *rq,
			   blk_insert_t flags)
{
	return 0;
}

static struct request *dispatch_req_stub(struct request_queue *q)
{
	return NULL;
}

static bool has_req_stub(struct request_queue *q, int rqs_count)
{
	return rqs_count > 0;
}

static void finish_req_stub(struct request *rq)
{
}

static struct request *former_req_stub(struct request_queue *q, struct request *rq)
{
	return NULL;
}

static struct request *next_req_stub(struct request_queue *q, struct request *rq)
{
	return NULL;
}

static struct request *merge_req_stub(struct request_queue *q, struct request *rq,
				      int *type)
{
	*type = ELEVATOR_NO_MERGE;
	return NULL;
}

static void req_merged_stub(struct request_queue *q, struct request *rq,
			    int type)
{
}

static struct ufq_iosched_ops __bpf_ops_ufq_ops = {
	.init_sched	= init_sched_stub,
	.exit_sched	= exit_sched_stub,
	.insert_req	= insert_req_stub,
	.dispatch_req	= dispatch_req_stub,
	.has_req	= has_req_stub,
	.former_req	= former_req_stub,
	.next_req	= next_req_stub,
	.merge_req	= merge_req_stub,
	.req_merged	= req_merged_stub,
	.finish_req	= finish_req_stub,
};

static struct bpf_struct_ops bpf_iosched_ufq_ops = {
	.verifier_ops = &bpf_ufq_verifier_ops,
	.reg = bpf_ufq_reg,
	.unreg = bpf_ufq_unreg,
	.check_member = bpf_ufq_check_member,
	.init_member = bpf_ufq_init_member,
	.init = bpf_ufq_init,
	.update = bpf_ufq_update,
	.validate = bpf_ufq_validate,
	.name = "ufq_iosched_ops",
	.owner = THIS_MODULE,
	.cfi_stubs = &__bpf_ops_ufq_ops
};

int bpf_ufq_ops_init(void)
{
	return register_bpf_struct_ops(&bpf_iosched_ufq_ops, ufq_iosched_ops);
}

