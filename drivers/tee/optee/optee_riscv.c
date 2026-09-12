// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * This file implements the ABI used when communicating with secure world
 * OP-TEE OS over the RPMI TEE service group (RPMI spec section 4.16). It is
 * the RISC-V analog of ffa_abi.c: OP-TEE and Linux are peer endpoints of the
 * RPMI framework (OpenSBI), and shared memory follows the FF-A memory-donation
 * model through the RPMI memory parcel services.
 *
 * This file is structured exactly like ffa_abi.c:
 * 1. Maintain a hash table for lookup of a memory parcel id
 * 2. Convert between struct tee_param and struct optee_msg_param
 * 3. Low level support functions to register shared memory in secure world
 * 4. Dynamic shared memory pool based on alloc_pages()
 * 5. Do a normal scheduled call into secure world
 * 6. Driver initialization
 *
 * Every FF-A memory operation has a direct RPMI TEE service group analog:
 *   FFA_MEM_SHARE     -> MEM_PARCEL_CREATE  (0x09), issued by the REE
 *   FFA_MEM_RECLAIM   -> MEM_PARCEL_RECLAIM (0x0c), issued by the REE
 *   direct message    -> TEE_CALL           (0x13), the call doorbell
 * and the FF-A g_handle is replaced by a memory parcel id folded together
 * with a caller-supplied nonce.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/mailbox_client.h>
#include <linux/mailbox/riscv-rpmi-message.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/rhashtable.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/string.h>
#include <linux/tee_core.h>
#include <linux/types.h>

#include "optee_private.h"
#include "optee_riscv.h"
#include "optee_rpc_cmd.h"

/*
 * Low level RPMI TEE service group transport over the SBI MPXY mailbox.
 *
 * The RPMI TEE service group is reached through the SBI MPXY mailbox. Each
 * hart owns a dedicated MPXY channel so that a call issued on a given hart is
 * serviced by the OP-TEE context bound to it; optee_riscv_send() therefore
 * selects the channel of the running hart. All RPMI messages are exchanged
 * synchronously with rpmi_mbox_send_message().
 */

static int optee_riscv_send(struct optee *optee, struct rpmi_mbox_message *msg)
{
	int cpu, ret;

	cpu = get_cpu();
	if (cpu >= optee->riscv.nr_chan || !optee->riscv.chan[cpu]) {
		put_cpu();
		return -ENODEV;
	}
	ret = rpmi_mbox_send_message(optee->riscv.chan[cpu], msg);
	put_cpu();

	return ret;
}

/*
 * optee_riscv_tee_call() - issue a TEE_CALL (RPMI service 0x13)
 * @optee:	main service struct
 * @in:		the command words carried in SERVICE_DATA, the RISC-V analog
 *		of struct ffa_send_direct_data's data0-data4 (w3-w7)
 * @out:	the response words returned in SERVICE_RSP, the RISC-V analog
 *		of the same data0-data4 set on the return path
 *
 * TEE_CALL is the RISC-V analog of the FF-A direct message: it is the single
 * doorbell used both for the blocking (fast) calls of section 6 and for the
 * yielding call of section 5. The struct optee_msg_arg itself is never
 * carried here, only its parcel handle and offset, exactly as FF-A carries
 * only w4-w6.
 *
 * Returns 0 on success or <0 on failure.
 */
static int optee_riscv_tee_call(struct optee *optee,
				const u64 in[RPMI_TEE_OPTEE_CALL_REGS],
				u64 out[RPMI_TEE_OPTEE_RESP_REGS])
{
	static const u8 optee_uuid[RPMI_TEE_UUID_LEN] = RPMI_TEE_OPTEE_UUID;
	struct rpmi_tee_call_req tx = {
		.sender_id = cpu_to_le32(RPMI_TEE_ENDPOINT_REE),
		.target_id = cpu_to_le32(RPMI_TEE_ENDPOINT_OPTEE),
		.service_data_len =
			cpu_to_le32(RPMI_TEE_OPTEE_CALL_REGS *
				    sizeof(rpmi_xlen_t)),
	};
	struct rpmi_tee_call_resp rx = { };
	struct rpmi_mbox_message msg;
	unsigned int i;
	int ret;

	memcpy(tx.service, optee_uuid, sizeof(tx.service));
	for (i = 0; i < RPMI_TEE_OPTEE_CALL_REGS; i++)
		tx.reg[i] = cpu_to_rpmi_xlen(in[i]);

	rpmi_mbox_init_send_with_response(&msg, RPMI_TEE_SRV_CALL,
					  &tx, sizeof(tx), &rx, sizeof(rx));
	ret = optee_riscv_send(optee, &msg);
	if (ret)
		return ret;
	if (rx.status)
		return rpmi_to_linux_error(le32_to_cpu(rx.status));

	for (i = 0; i < RPMI_TEE_OPTEE_RESP_REGS; i++)
		out[i] = rpmi_xlen_to_cpu(rx.reg[i]);

	return 0;
}

/*
 * 1. Maintain a hash table for lookup of a memory parcel id
 *
 * The RPMI framework assigns a memory parcel id for each piece of shared
 * memory. Together with a caller-supplied nonce it forms the wire identity
 * used when communicating with secure world, playing the exact role of the
 * FF-A global memory handle.
 *
 * Main functions are optee_shm_add_riscv_handle() and
 * optee_shm_rem_riscv_handle().
 */
struct shm_rhash {
	struct tee_shm *shm;
	u64 global_id;
	struct rhash_head linkage;
};

static void rh_free_fn(void *ptr, void *arg)
{
	kfree(ptr);
}

static const struct rhashtable_params shm_rhash_params = {
	.head_offset = offsetof(struct shm_rhash, linkage),
	.key_len     = sizeof(u64),
	.key_offset  = offsetof(struct shm_rhash, global_id),
	.automatic_shrinking = true,
};

static struct tee_shm *optee_shm_from_riscv_handle(struct optee *optee,
						   u64 global_id)
{
	struct tee_shm *shm = NULL;
	struct shm_rhash *r;

	mutex_lock(&optee->riscv.mutex);
	r = rhashtable_lookup_fast(&optee->riscv.global_ids, &global_id,
				   shm_rhash_params);
	if (r)
		shm = r->shm;
	mutex_unlock(&optee->riscv.mutex);

	return shm;
}

static int optee_shm_add_riscv_handle(struct optee *optee, struct tee_shm *shm,
				      u64 global_id)
{
	struct shm_rhash *r;
	int rc;

	r = kmalloc_obj(*r);
	if (!r)
		return -ENOMEM;
	r->shm = shm;
	r->global_id = global_id;

	mutex_lock(&optee->riscv.mutex);
	rc = rhashtable_lookup_insert_fast(&optee->riscv.global_ids,
					   &r->linkage, shm_rhash_params);
	mutex_unlock(&optee->riscv.mutex);

	if (rc)
		kfree(r);

	return rc;
}

static int optee_shm_rem_riscv_handle(struct optee *optee, u64 global_id)
{
	struct shm_rhash *r;
	int rc = -ENOENT;

	mutex_lock(&optee->riscv.mutex);
	r = rhashtable_lookup_fast(&optee->riscv.global_ids, &global_id,
				   shm_rhash_params);
	if (r)
		rc = rhashtable_remove_fast(&optee->riscv.global_ids,
					    &r->linkage, shm_rhash_params);
	mutex_unlock(&optee->riscv.mutex);

	if (!rc)
		kfree(r);

	return rc;
}

/*
 * 2. Convert between struct tee_param and struct optee_msg_param
 *
 * optee_riscv_from_msg_param() and optee_riscv_to_msg_param() are the main
 * functions. They are identical to their FF-A counterparts: the memref
 * carries only the parcel handle (stored in fmem.global_id, the same slot
 * FF-A uses for its g_handle), an offset and a size, never a page list.
 */

static void from_msg_param_riscv_mem(struct optee *optee, struct tee_param *p,
				     u32 attr, const struct optee_msg_param *mp)
{
	struct tee_shm *shm = NULL;
	u64 offs_high = 0;
	u64 offs_low = 0;

	p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT +
		  attr - OPTEE_MSG_ATTR_TYPE_FMEM_INPUT;
	p->u.memref.size = mp->u.fmem.size;

	if (mp->u.fmem.global_id != OPTEE_MSG_FMEM_INVALID_GLOBAL_ID)
		shm = optee_shm_from_riscv_handle(optee, mp->u.fmem.global_id);
	p->u.memref.shm = shm;

	if (shm) {
		offs_low = mp->u.fmem.offs_low;
		offs_high = mp->u.fmem.offs_high;
	}
	p->u.memref.shm_offs = offs_low | offs_high << 32;
}

/**
 * optee_riscv_from_msg_param() - convert from OPTEE_MSG parameters to
 *				  struct tee_param
 * @optee:	main service struct
 * @params:	subsystem internal parameter representation
 * @num_params:	number of elements in the parameter arrays
 * @msg_params:	OPTEE_MSG parameters
 *
 * Returns 0 on success or <0 on failure
 */
static int optee_riscv_from_msg_param(struct optee *optee,
				      struct tee_param *params,
				      size_t num_params,
				      const struct optee_msg_param *msg_params)
{
	size_t n;

	for (n = 0; n < num_params; n++) {
		struct tee_param *p = params + n;
		const struct optee_msg_param *mp = msg_params + n;
		u32 attr = mp->attr & OPTEE_MSG_ATTR_TYPE_MASK;

		switch (attr) {
		case OPTEE_MSG_ATTR_TYPE_NONE:
			p->attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
			memset(&p->u, 0, sizeof(p->u));
			break;
		case OPTEE_MSG_ATTR_TYPE_VALUE_INPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_INOUT:
			optee_from_msg_param_value(p, attr, mp);
			break;
		case OPTEE_MSG_ATTR_TYPE_FMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_FMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_FMEM_INOUT:
			from_msg_param_riscv_mem(optee, p, attr, mp);
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

static int to_msg_param_riscv_mem(struct optee_msg_param *mp,
				  const struct tee_param *p)
{
	struct tee_shm *shm = p->u.memref.shm;

	mp->attr = OPTEE_MSG_ATTR_TYPE_FMEM_INPUT + p->attr -
		   TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT;

	if (shm) {
		u64 shm_offs = p->u.memref.shm_offs;

		mp->u.fmem.internal_offs = shm->offset;

		mp->u.fmem.offs_low = shm_offs;
		mp->u.fmem.offs_high = shm_offs >> 32;
		/* Check that the entire offset could be stored. */
		if (mp->u.fmem.offs_high != shm_offs >> 32)
			return -EINVAL;

		mp->u.fmem.global_id = shm->sec_world_id;
	} else {
		memset(&mp->u, 0, sizeof(mp->u));
		mp->u.fmem.global_id = OPTEE_MSG_FMEM_INVALID_GLOBAL_ID;
	}
	mp->u.fmem.size = p->u.memref.size;

	return 0;
}

/**
 * optee_riscv_to_msg_param() - convert from struct tee_params to OPTEE_MSG
 *				parameters
 * @optee:	main service struct
 * @msg_params:	OPTEE_MSG parameters
 * @num_params:	number of elements in the parameter arrays
 * @params:	subsystem internal parameter representation
 *
 * Returns 0 on success or <0 on failure
 */
static int optee_riscv_to_msg_param(struct optee *optee,
				    struct optee_msg_param *msg_params,
				    size_t num_params,
				    const struct tee_param *params)
{
	size_t n;

	for (n = 0; n < num_params; n++) {
		const struct tee_param *p = params + n;
		struct optee_msg_param *mp = msg_params + n;

		switch (p->attr) {
		case TEE_IOCTL_PARAM_ATTR_TYPE_NONE:
			mp->attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
			memset(&mp->u, 0, sizeof(mp->u));
			break;
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT:
			optee_to_msg_param_value(mp, p);
			break;
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
			if (to_msg_param_riscv_mem(mp, p))
				return -EINVAL;
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}

/*
 * 3. Low level support functions to register shared memory in secure world
 *
 * Functions to register and unregister shared memory both for normal
 * clients and for tee-supplicant. Registration creates an RPMI memory
 * parcel (MEM_PARCEL_CREATE), which is the analog of FFA_MEM_SHARE;
 * unregistration reclaims it (MEM_PARCEL_RECLAIM), the analog of
 * FFA_MEM_RECLAIM, after a synchronous handshake with OP-TEE.
 */

/*
 * Coalesce a page array into RPMI block-list entries (Table 198). Each entry
 * spans a run of physically contiguous pages, up to RPMI_TEE_PARCEL_BLOCK_MAX_
 * PAGES. When @block_high / @block_low are NULL only the entry count is
 * computed, so the caller can size the request buffer first.
 */
static u32 optee_riscv_build_blocks(struct page **pages, size_t num_pages,
				    __le32 *block_high, __le32 *block_low)
{
	u32 nblocks = 0;
	size_t i = 0;

	while (i < num_pages) {
		u64 pfn = page_to_pfn(pages[i]);
		u32 run = 1;

		while (i + run < num_pages &&
		       run < RPMI_TEE_PARCEL_BLOCK_MAX_PAGES &&
		       page_to_pfn(pages[i + run]) == pfn + run)
			run++;

		if (block_high && block_low) {
			block_high[nblocks] = rpmi_tee_block_high(pfn);
			block_low[nblocks] = rpmi_tee_block_low(pfn, run);
		}
		nblocks++;
		i += run;
	}

	return nblocks;
}

/*
 * Issue MEM_PARCEL_CREATE (RPMI service 0x09) for @pages with the REE as the
 * creator and OP-TEE as the sole read/write receiver. Returns the framework
 * assigned parcel id (>= 0) or a negative errno.
 */
static int optee_riscv_parcel_create(struct optee *optee, struct page **pages,
				     size_t num_pages, u32 nonce)
{
	struct rpmi_tee_mem_parcel_create_req *req;
	struct rpmi_tee_mem_parcel_create_resp rx = { };
	struct rpmi_mbox_message msg;
	__le32 *block_high, *block_low;
	size_t req_len;
	u32 block_cnt;
	__le32 *data;
	int ret;

	block_cnt = optee_riscv_build_blocks(pages, num_pages, NULL, NULL);

	/*
	 * Layout of the trailing data[] array (Table 200): one receiver_id and
	 * one access word (receiver_cnt == 1), then block_high[block_cnt] and
	 * block_low[block_cnt].
	 */
	req_len = struct_size(req, data, 2 + 2 * block_cnt);
	if (optee->riscv.max_msg_data_size &&
	    req_len > optee->riscv.max_msg_data_size)
		return -E2BIG;

	req = kzalloc(req_len, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	req->creator_id = cpu_to_le32(RPMI_TEE_ENDPOINT_REE);
	req->creator_access = cpu_to_le32(RPMI_TEE_PARCEL_ACCESS_R |
					  RPMI_TEE_PARCEL_ACCESS_W);
	req->receiver_cnt = cpu_to_le32(1);
	req->flags = 0;
	req->nonce = cpu_to_le32(nonce);
	req->block_cnt = cpu_to_le32(block_cnt);

	data = req->data;
	data[0] = cpu_to_le32(RPMI_TEE_ENDPOINT_OPTEE);
	data[1] = cpu_to_le32(RPMI_TEE_PARCEL_ACCESS_R |
			      RPMI_TEE_PARCEL_ACCESS_W);
	block_high = &data[2];
	block_low = &data[2 + block_cnt];
	optee_riscv_build_blocks(pages, num_pages, block_high, block_low);

	rpmi_mbox_init_send_with_response(&msg, RPMI_TEE_SRV_MEM_PARCEL_CREATE,
					  req, req_len, &rx, sizeof(rx));
	ret = optee_riscv_send(optee, &msg);
	kfree(req);
	if (ret)
		return ret;
	if (rx.status)
		return rpmi_to_linux_error(le32_to_cpu(rx.status));

	return le32_to_cpu(rx.mem_parcel_id);
}

/*
 * Issue MEM_PARCEL_RECLAIM (RPMI service 0x0c). OpenSBI fails the reclaim
 * while any receiver still holds the parcel, so this is only called after the
 * OPTEE_ABI_UNREGISTER_SHM handshake below has confirmed OP-TEE released it.
 */
static int optee_riscv_parcel_reclaim(struct optee *optee, u32 parcel_id)
{
	struct rpmi_tee_mem_parcel_reclaim_req tx = {
		.mem_parcel_id = cpu_to_le32(parcel_id),
	};
	struct rpmi_tee_mem_parcel_reclaim_resp rx = { };
	struct rpmi_mbox_message msg;
	int ret;

	rpmi_mbox_init_send_with_response(&msg, RPMI_TEE_SRV_MEM_PARCEL_RECLAIM,
					  &tx, sizeof(tx), &rx, sizeof(rx));
	ret = optee_riscv_send(optee, &msg);
	if (ret)
		return ret;
	if (rx.status)
		return rpmi_to_linux_error(le32_to_cpu(rx.status));

	return 0;
}

static int optee_riscv_shm_register(struct tee_context *ctx,
				    struct tee_shm *shm, struct page **pages,
				    size_t num_pages, unsigned long start)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	u64 global_id;
	u32 nonce;
	int rc;

	rc = optee_check_mem_type(start, num_pages);
	if (rc)
		return rc;

	/*
	 * MEM_PARCEL_CREATE returns only a parcel id; the nonce is
	 * caller-supplied. Fold them into the FF-A style 64-bit handle:
	 * parcel id in the low word, nonce in the high word.
	 */
	nonce = (u32)atomic_inc_return(&optee->riscv.next_nonce);
	rc = optee_riscv_parcel_create(optee, pages, num_pages, nonce);
	if (rc < 0)
		return rc;
	global_id = (u32)rc | ((u64)nonce << 32);

	rc = optee_shm_add_riscv_handle(optee, shm, global_id);
	if (rc) {
		optee_riscv_parcel_reclaim(optee, (u32)global_id);
		return rc;
	}

	shm->sec_world_id = global_id;

	return 0;
}

static int optee_riscv_shm_unregister(struct tee_context *ctx,
				      struct tee_shm *shm)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	u64 global_id = shm->sec_world_id;
	u64 in[RPMI_TEE_OPTEE_CALL_REGS] = {
		OPTEE_ABI_UNREGISTER_SHM,
		(u32)global_id,
		global_id >> 32,
		0,
	};
	u64 out[RPMI_TEE_OPTEE_RESP_REGS] = { };
	int rc;

	optee_shm_rem_riscv_handle(optee, global_id);
	shm->sec_world_id = 0;

	/*
	 * Synchronous teardown handshake, the analog of the FF-A
	 * OPTEE_FFA_UNREGISTER_SHM blocking call: OP-TEE releases the parcel on
	 * its own TEE channel before we reclaim it. Only reclaim once OP-TEE
	 * has acknowledged, so we never race the release.
	 */
	rc = optee_riscv_tee_call(optee, in, out);
	if (rc)
		pr_err("Unregister SHM id 0x%llx rc %d\n", global_id, rc);

	rc = optee_riscv_parcel_reclaim(optee, (u32)global_id);
	if (rc)
		pr_err("parcel_reclaim: 0x%llx %d\n", global_id, rc);

	return rc;
}

static int optee_riscv_shm_unregister_supp(struct tee_context *ctx,
					   struct tee_shm *shm)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	u64 global_id = shm->sec_world_id;
	int rc;

	/*
	 * We're skipping the OPTEE_ABI_UNREGISTER_SHM handshake since this is
	 * OP-TEE freeing via RPC, so it has already retired this parcel.
	 */
	optee_shm_rem_riscv_handle(optee, global_id);
	shm->sec_world_id = 0;

	rc = optee_riscv_parcel_reclaim(optee, (u32)global_id);
	if (rc)
		pr_err("parcel_reclaim: 0x%llx %d\n", global_id, rc);

	return rc;
}

/*
 * 4. Dynamic shared memory pool based on alloc_pages()
 *
 * Implements an OP-TEE specific shared memory pool.
 * The main function is optee_riscv_shm_pool_alloc_pages().
 */

static int pool_riscv_op_alloc(struct tee_shm_pool *pool,
			       struct tee_shm *shm, size_t size, size_t align)
{
	return tee_dyn_shm_alloc_helper(shm, size, align,
					optee_riscv_shm_register);
}

static void pool_riscv_op_free(struct tee_shm_pool *pool, struct tee_shm *shm)
{
	tee_dyn_shm_free_helper(shm, optee_riscv_shm_unregister);
}

static void pool_riscv_op_destroy_pool(struct tee_shm_pool *pool)
{
	kfree(pool);
}

static const struct tee_shm_pool_ops pool_riscv_ops = {
	.alloc = pool_riscv_op_alloc,
	.free = pool_riscv_op_free,
	.destroy_pool = pool_riscv_op_destroy_pool,
};

/**
 * optee_riscv_shm_pool_alloc_pages() - create page-based allocator pool
 *
 * This pool is used with OP-TEE over the RPMI TEE service group. In this case
 * command buffers and such are allocated from kernel's own memory.
 */
static struct tee_shm_pool *optee_riscv_shm_pool_alloc_pages(void)
{
	struct tee_shm_pool *pool = kzalloc_obj(*pool);

	if (!pool)
		return ERR_PTR(-ENOMEM);

	pool->ops = &pool_riscv_ops;

	return pool;
}

/*
 * 5. Do a normal scheduled call into secure world
 *
 * The function optee_riscv_do_call_with_arg() performs a normal scheduled
 * call into secure world. During this call secure world may request help
 * from normal world using RPCs, Remote Procedure Calls. This includes
 * delivery of non-secure interrupts to for instance allow rescheduling of
 * the current task.
 */

static void handle_riscv_rpc_func_cmd_shm_alloc(struct tee_context *ctx,
						struct optee *optee,
						struct optee_msg_arg *arg)
{
	struct tee_shm *shm;

	if (arg->num_params != 1 ||
	    arg->params[0].attr != OPTEE_MSG_ATTR_TYPE_VALUE_INPUT) {
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	switch (arg->params[0].u.value.a) {
	case OPTEE_RPC_SHM_TYPE_APPL:
		shm = optee_rpc_cmd_alloc_suppl(ctx, arg->params[0].u.value.b);
		break;
	case OPTEE_RPC_SHM_TYPE_KERNEL:
		shm = tee_shm_alloc_priv_buf(optee->ctx,
					     arg->params[0].u.value.b);
		break;
	default:
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		return;
	}

	if (IS_ERR(shm)) {
		arg->ret = TEEC_ERROR_OUT_OF_MEMORY;
		return;
	}

	arg->params[0] = (struct optee_msg_param){
		.attr = OPTEE_MSG_ATTR_TYPE_FMEM_OUTPUT,
		.u.fmem.size = tee_shm_get_size(shm),
		.u.fmem.global_id = shm->sec_world_id,
		.u.fmem.internal_offs = shm->offset,
	};

	arg->ret = TEEC_SUCCESS;
}

static void handle_riscv_rpc_func_cmd_shm_free(struct tee_context *ctx,
					       struct optee *optee,
					       struct optee_msg_arg *arg)
{
	struct tee_shm *shm;

	if (arg->num_params != 1 ||
	    arg->params[0].attr != OPTEE_MSG_ATTR_TYPE_VALUE_INPUT)
		goto err_bad_param;

	shm = optee_shm_from_riscv_handle(optee, arg->params[0].u.value.b);
	if (!shm)
		goto err_bad_param;
	switch (arg->params[0].u.value.a) {
	case OPTEE_RPC_SHM_TYPE_APPL:
		optee_rpc_cmd_free_suppl(ctx, shm);
		break;
	case OPTEE_RPC_SHM_TYPE_KERNEL:
		tee_shm_free(shm);
		break;
	default:
		goto err_bad_param;
	}
	arg->ret = TEEC_SUCCESS;
	return;

err_bad_param:
	arg->ret = TEEC_ERROR_BAD_PARAMETERS;
}

static void handle_riscv_rpc_func_cmd(struct tee_context *ctx,
				      struct optee *optee,
				      struct optee_msg_arg *arg)
{
	arg->ret_origin = TEEC_ORIGIN_COMMS;
	switch (arg->cmd) {
	case OPTEE_RPC_CMD_SHM_ALLOC:
		handle_riscv_rpc_func_cmd_shm_alloc(ctx, optee, arg);
		break;
	case OPTEE_RPC_CMD_SHM_FREE:
		handle_riscv_rpc_func_cmd_shm_free(ctx, optee, arg);
		break;
	default:
		optee_rpc_cmd(ctx, optee, arg);
	}
}

static void optee_handle_riscv_rpc(struct tee_context *ctx,
				   struct optee *optee, u32 cmd,
				   struct optee_msg_arg *arg)
{
	switch (cmd) {
	case OPTEE_ABI_YIELDING_CALL_RETURN_RPC_CMD:
		handle_riscv_rpc_func_cmd(ctx, optee, arg);
		break;
	case OPTEE_ABI_YIELDING_CALL_RETURN_INTERRUPT:
		/* Interrupt delivered by now */
		break;
	default:
		pr_warn("Unknown RPC func 0x%x\n", cmd);
		break;
	}
}

static int optee_riscv_yielding_call(struct tee_context *ctx,
				     u64 in[RPMI_TEE_OPTEE_CALL_REGS],
				     struct optee_msg_arg *rpc_arg,
				     bool system_thread)
{
	struct optee *optee = tee_get_drvdata(ctx->teedev);
	struct optee_call_waiter w;
	u64 out[RPMI_TEE_OPTEE_RESP_REGS] = { };
	int rc;

	/* Initialize waiter */
	optee_cq_wait_init(&optee->call_queue, &w, system_thread);
	while (true) {
		rc = optee_riscv_tee_call(optee, in, out);
		if (rc)
			goto done;

		switch ((int)out[0]) {
		case TEEC_SUCCESS:
			break;
		case TEEC_ERROR_BUSY:
			if (in[0] == OPTEE_ABI_YIELDING_CALL_RESUME) {
				rc = -EIO;
				goto done;
			}

			/*
			 * Out of threads in secure world, wait for a thread
			 * to become available.
			 */
			optee_cq_wait_for_completion(&optee->call_queue, &w);
			continue;
		default:
			rc = -EIO;
			goto done;
		}

		if (out[1] == OPTEE_ABI_YIELDING_CALL_RETURN_DONE)
			goto done;

		/*
		 * OP-TEE has returned with an RPC request.
		 *
		 * Note that out[4] (returned in reg[4]) is already filled in
		 * by optee_riscv_tee_call() returning above.
		 */
		cond_resched();
		optee_handle_riscv_rpc(ctx, optee, out[1], rpc_arg);
		in[0] = OPTEE_ABI_YIELDING_CALL_RESUME;
		in[1] = 0;
		in[2] = 0;
		in[3] = 0;
		in[4] = out[4];		/* resume info */
	}
done:
	/*
	 * We're done with our thread in secure world, if there are any
	 * thread waiters wake up one.
	 */
	optee_cq_wait_final(&optee->call_queue, &w);

	return rc;
}

/**
 * optee_riscv_do_call_with_arg() - enter OP-TEE in secure world
 * @ctx:	calling context
 * @shm:	shared memory holding the message to pass to secure world
 * @offs:	offset of the message in @shm
 * @system_thread: true if caller requests TEE system thread support
 *
 * Does a TEE_CALL to OP-TEE in secure world and handles the resulting
 * Remote Procedure Calls (RPC) from OP-TEE. The struct optee_msg_arg is
 * passed by its parcel handle plus @offs, exactly as FF-A passes it by
 * shared memory handle.
 *
 * Returns return code from OP-TEE, 0 is OK
 */
static int optee_riscv_do_call_with_arg(struct tee_context *ctx,
					struct tee_shm *shm, u_int offs,
					bool system_thread)
{
	u64 in[RPMI_TEE_OPTEE_CALL_REGS] = {
		OPTEE_ABI_YIELDING_CALL_WITH_ARG,
		(u32)shm->sec_world_id,
		shm->sec_world_id >> 32,
		offs,
	};
	struct optee_msg_arg *arg;
	unsigned int rpc_arg_offs;
	struct optee_msg_arg *rpc_arg;

	/*
	 * The shared memory object has to start on a page when passed as
	 * an argument struct. This is also what the shm pool allocator
	 * returns, but check this before calling secure world to catch
	 * eventual errors early in case something changes.
	 */
	if (shm->offset)
		return -EINVAL;

	arg = tee_shm_get_va(shm, offs);
	if (IS_ERR(arg))
		return PTR_ERR(arg);

	rpc_arg_offs = OPTEE_MSG_GET_ARG_SIZE(arg->num_params);
	rpc_arg = tee_shm_get_va(shm, offs + rpc_arg_offs);
	if (IS_ERR(rpc_arg))
		return PTR_ERR(rpc_arg);

	return optee_riscv_yielding_call(ctx, in, rpc_arg, system_thread);
}

/*
 * 6. Driver initialization
 *
 * During driver initialization the OP-TEE Trusted OS is probed over TEE_CALL
 * to find out which features it supports so the driver can be initialized
 * with a matching configuration. These blocking calls mirror the FF-A
 * OPTEE_FFA_GET_API_VERSION / GET_OS_VERSION / EXCHANGE_CAPABILITIES probes.
 */

static bool optee_riscv_api_is_compatible(struct optee *optee)
{
	u64 in[RPMI_TEE_OPTEE_CALL_REGS] = { OPTEE_ABI_GET_API_VERSION };
	u64 out[RPMI_TEE_OPTEE_RESP_REGS] = { };
	int rc;

	rc = optee_riscv_tee_call(optee, in, out);
	if (rc) {
		pr_err("Unexpected error %d\n", rc);
		return false;
	}
	if (out[0] != OPTEE_ABI_VERSION_MAJOR ||
	    out[1] < OPTEE_ABI_VERSION_MINOR) {
		pr_err("Incompatible OP-TEE API version %llu.%llu\n",
		       out[0], out[1]);
		return false;
	}

	return true;
}

static bool optee_riscv_get_os_revision(struct optee *optee)
{
	u64 in[RPMI_TEE_OPTEE_CALL_REGS] = { OPTEE_ABI_GET_OS_VERSION };
	u64 out[RPMI_TEE_OPTEE_RESP_REGS] = { };
	int rc;

	rc = optee_riscv_tee_call(optee, in, out);
	if (rc) {
		pr_err("Unexpected error %d\n", rc);
		return false;
	}

	optee->revision.os_major = out[0];
	optee->revision.os_minor = out[1];
	optee->revision.os_build_id = out[2];

	if (out[2])
		pr_info("revision %llu.%llu (%08llx)\n", out[0], out[1],
			out[2]);
	else
		pr_info("revision %llu.%llu\n", out[0], out[1]);

	return true;
}

static bool optee_riscv_exchange_caps(struct optee *optee, u32 *sec_caps,
				      unsigned int *rpc_param_count,
				      unsigned int *max_notif_value)
{
	u64 in[RPMI_TEE_OPTEE_CALL_REGS] = { OPTEE_ABI_EXCHANGE_CAPABILITIES };
	u64 out[RPMI_TEE_OPTEE_RESP_REGS] = { };
	int rc;

	rc = optee_riscv_tee_call(optee, in, out);
	if (rc) {
		pr_err("Unexpected error %d\n", rc);
		return false;
	}
	if (out[0]) {
		pr_err("Unexpected exchange error %llu\n", out[0]);
		return false;
	}

	*rpc_param_count = (u8)out[1];
	*sec_caps = out[2];
	if (out[3])
		*max_notif_value = out[3];
	else
		*max_notif_value = OPTEE_DEFAULT_MAX_NOTIF_VALUE;

	return true;
}

static void optee_riscv_get_version(struct tee_device *teedev,
				    struct tee_ioctl_version_data *vers)
{
	struct tee_ioctl_version_data v = {
		.impl_id = TEE_IMPL_ID_OPTEE,
		.impl_caps = TEE_OPTEE_CAP_TZ,
		.gen_caps = TEE_GEN_CAP_GP | TEE_GEN_CAP_REG_MEM |
			    TEE_GEN_CAP_MEMREF_NULL,
	};

	*vers = v;
}

static int optee_riscv_open(struct tee_context *ctx)
{
	return optee_open(ctx, true);
}

static const struct tee_driver_ops optee_riscv_clnt_ops = {
	.get_version = optee_riscv_get_version,
	.get_tee_revision = optee_get_revision,
	.open = optee_riscv_open,
	.release = optee_release,
	.open_session = optee_open_session,
	.close_session = optee_close_session,
	.invoke_func = optee_invoke_func,
	.cancel_req = optee_cancel_req,
	.shm_register = optee_riscv_shm_register,
	.shm_unregister = optee_riscv_shm_unregister,
};

static const struct tee_desc optee_riscv_clnt_desc = {
	.name = DRIVER_NAME "-riscv-clnt",
	.ops = &optee_riscv_clnt_ops,
	.owner = THIS_MODULE,
};

static const struct tee_driver_ops optee_riscv_supp_ops = {
	.get_version = optee_riscv_get_version,
	.get_tee_revision = optee_get_revision,
	.open = optee_riscv_open,
	.release = optee_release_supp,
	.supp_recv = optee_supp_recv,
	.supp_send = optee_supp_send,
	.shm_register = optee_riscv_shm_register, /* same as for clnt ops */
	.shm_unregister = optee_riscv_shm_unregister_supp,
};

static const struct tee_desc optee_riscv_supp_desc = {
	.name = DRIVER_NAME "-riscv-supp",
	.ops = &optee_riscv_supp_ops,
	.owner = THIS_MODULE,
	.flags = TEE_DESC_PRIVILEGED,
};

static const struct optee_ops optee_riscv_ops = {
	.do_call_with_arg = optee_riscv_do_call_with_arg,
	.to_msg_param = optee_riscv_to_msg_param,
	.from_msg_param = optee_riscv_from_msg_param,
};

/*
 * The RPMI TEE service group is described in the device tree by a single
 * node whose "mboxes" property lists one SBI MPXY channel per hart, in hart
 * order. The driver requests each list entry by index and validates the
 * transport before building the OP-TEE device.
 */

static int optee_riscv_request_channels(struct optee *optee)
{
	struct device *dev = optee->riscv.dev;
	int nr_mboxes;
	unsigned int cpuid;

	nr_mboxes = of_count_phandle_with_args(dev->of_node, "mboxes",
					       "#mbox-cells");
	if (nr_mboxes != optee->riscv.nr_chan)
		return dev_err_probe(dev, -EINVAL,
				     "Expected %u mailbox channels, got %d\n",
				     optee->riscv.nr_chan, nr_mboxes);

	for (cpuid = 0; cpuid < optee->riscv.nr_chan; cpuid++) {
		optee->riscv.chan[cpuid] =
			mbox_request_channel(optee->riscv.client, cpuid);
		if (IS_ERR(optee->riscv.chan[cpuid])) {
			int ret = PTR_ERR(optee->riscv.chan[cpuid]);

			optee->riscv.chan[cpuid] = NULL;
			return dev_err_probe(dev, ret,
					     "Failed to request channel %u\n",
					     cpuid);
		}
	}

	return 0;
}

static void optee_riscv_free_channels(struct optee *optee)
{
	unsigned int i;

	for (i = 0; i < optee->riscv.nr_chan; i++) {
		if (optee->riscv.chan[i])
			mbox_free_channel(optee->riscv.chan[i]);
	}
}

/* Confirm the TEE service group and read its transport attributes. */
static int optee_riscv_check_transport(struct optee *optee)
{
	struct device *dev = optee->riscv.dev;
	struct rpmi_mbox_message msg;
	int ret;

	rpmi_mbox_init_get_attribute(&msg, RPMI_MBOX_ATTR_SERVICEGROUP_ID);
	ret = optee_riscv_send(optee, &msg);
	if (ret)
		return dev_err_probe(dev, ret,
				     "Failed to get service group id\n");
	if (msg.attr.value != RPMI_SRVGRP_TEE)
		return dev_err_probe(dev, -ENODEV,
				     "Not a TEE service group channel (0x%x)\n",
				     msg.attr.value);

	rpmi_mbox_init_get_attribute(&msg, RPMI_MBOX_ATTR_MAX_MSG_DATA_SIZE);
	ret = optee_riscv_send(optee, &msg);
	if (ret)
		return dev_err_probe(dev, ret,
				     "Failed to get max msg data size\n");
	optee->riscv.max_msg_data_size = msg.attr.value;

	return 0;
}

/*
 * TEE_PROBE_FEATURES (0x02) reports which framework features are available;
 * memory parcels carry normal-world shared memory to OP-TEE, so the framework
 * must support sharing memory between the REE and a TEE.
 */
static int optee_riscv_probe_feature(struct optee *optee, u32 feature_id,
				     u32 *value)
{
	struct rpmi_tee_probe_features_req tx = {
		.feature_id = cpu_to_le32(feature_id),
	};
	struct rpmi_tee_probe_features_resp rx = { };
	struct rpmi_mbox_message msg;
	int ret;

	rpmi_mbox_init_send_with_response(&msg, RPMI_TEE_SRV_PROBE_FEATURES,
					  &tx, sizeof(tx), &rx, sizeof(rx));
	ret = optee_riscv_send(optee, &msg);
	if (ret)
		return ret;
	if (rx.status)
		return rpmi_to_linux_error(le32_to_cpu(rx.status));

	if (value)
		*value = le32_to_cpu(rx.value);

	return 0;
}

static int optee_riscv_features(struct optee *optee)
{
	u32 share = RPMI_TEE_MEMORY_SHARE_NONE;
	int ret;

	ret = optee_riscv_probe_feature(optee, RPMI_TEE_FEAT_MEMORY_SHARE,
					&share);
	if (ret) {
		pr_err("Failed to probe MEMORY_SHARE feature: %d\n", ret);
		return ret;
	}
	if (share != RPMI_TEE_MEMORY_SHARE_FULL) {
		pr_err("Framework cannot share memory between REE and TEE (%u)\n",
		       share);
		return -EOPNOTSUPP;
	}

	return 0;
}

static int optee_riscv_enable_notif(struct optee *optee)
{
	struct rpmi_tee_probe_features_resp rx = { };
	struct rpmi_mbox_message msg;
	int ret;

	rpmi_mbox_init_send_with_response(&msg, RPMI_TEE_SRV_ENABLE_NOTIFICATION,
					  NULL, 0, &rx, sizeof(rx));
	ret = optee_riscv_send(optee, &msg);
	if (ret)
		return ret;

	/*
	 * The TEE service group defines no notification events on this
	 * platform, so RPMI_ERR_NOTSUPP is expected and not fatal.
	 */
	if (rx.status && le32_to_cpu(rx.status) != (u32)RPMI_ERR_NOTSUPP)
		return rpmi_to_linux_error(le32_to_cpu(rx.status));

	return 0;
}

static int optee_riscv_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	unsigned int rpc_param_count;
	unsigned int max_notif_value;
	struct tee_shm_pool *pool;
	struct tee_device *teedev;
	struct tee_context *ctx;
	struct mbox_client *client;
	struct optee *optee;
	u32 sec_caps;
	unsigned int nr_cpus;
	int rc;

	nr_cpus = num_possible_cpus();
	if (!nr_cpus)
		return dev_err_probe(dev, -ENODEV, "No harts found\n");

	optee = kzalloc_obj(*optee);
	if (!optee)
		return -ENOMEM;

	client = devm_kzalloc(dev, sizeof(*client), GFP_KERNEL);
	if (!client) {
		rc = -ENOMEM;
		goto err_free_optee;
	}
	client->dev		= dev;
	client->rx_callback	= NULL;
	client->tx_block	= false;
	client->knows_txdone	= true;
	client->tx_tout		= 0;

	optee->riscv.dev = dev;
	optee->riscv.client = client;
	optee->riscv.nr_chan = nr_cpus;
	optee->riscv.chan = kcalloc(nr_cpus, sizeof(*optee->riscv.chan),
				    GFP_KERNEL);
	if (!optee->riscv.chan) {
		rc = -ENOMEM;
		goto err_free_optee;
	}

	rc = optee_riscv_request_channels(optee);
	if (rc)
		goto err_free_channels;

	rc = optee_riscv_check_transport(optee);
	if (rc)
		goto err_free_channels;

	rc = optee_riscv_features(optee);
	if (rc) {
		dev_err_probe(dev, rc, "Missing required TEE features\n");
		goto err_free_channels;
	}

	rc = optee_riscv_enable_notif(optee);
	if (rc) {
		dev_err_probe(dev, rc, "Failed to enable notifications\n");
		goto err_free_channels;
	}

	if (!optee_riscv_api_is_compatible(optee)) {
		rc = -EINVAL;
		goto err_free_channels;
	}

	if (!optee_riscv_get_os_revision(optee)) {
		rc = -EINVAL;
		goto err_free_channels;
	}

	if (!optee_riscv_exchange_caps(optee, &sec_caps, &rpc_param_count,
				       &max_notif_value)) {
		rc = -EINVAL;
		goto err_free_channels;
	}

	pool = optee_riscv_shm_pool_alloc_pages();
	if (IS_ERR(pool)) {
		rc = PTR_ERR(pool);
		goto err_free_channels;
	}
	optee->pool = pool;

	optee->ops = &optee_riscv_ops;
	optee->rpc_param_count = rpc_param_count;

	if (IS_REACHABLE(CONFIG_RPMB) &&
	    (sec_caps & OPTEE_ABI_SEC_CAP_RPMB_PROBE))
		optee->in_kernel_rpmb_routing = true;

	teedev = tee_device_alloc(&optee_riscv_clnt_desc, NULL, optee->pool,
				  optee);
	if (IS_ERR(teedev)) {
		rc = PTR_ERR(teedev);
		goto err_free_shm_pool;
	}
	optee->teedev = teedev;

	teedev = tee_device_alloc(&optee_riscv_supp_desc, NULL, optee->pool,
				  optee);
	if (IS_ERR(teedev)) {
		rc = PTR_ERR(teedev);
		goto err_unreg_teedev;
	}
	optee->supp_teedev = teedev;

	optee_set_dev_group(optee);

	rc = tee_device_register(optee->teedev);
	if (rc)
		goto err_unreg_supp_teedev;

	rc = tee_device_register(optee->supp_teedev);
	if (rc)
		goto err_unreg_supp_teedev;

	rc = rhashtable_init(&optee->riscv.global_ids, &shm_rhash_params);
	if (rc)
		goto err_unreg_supp_teedev;
	mutex_init(&optee->riscv.mutex);
	atomic_set(&optee->riscv.next_nonce, 0);
	optee_cq_init(&optee->call_queue, 0);
	optee_supp_init(&optee->supp);
	optee_shm_arg_cache_init(optee, 0);
	mutex_init(&optee->rpmb_dev_mutex);
	platform_set_drvdata(pdev, optee);

	ctx = teedev_open(optee->teedev);
	if (IS_ERR(ctx)) {
		rc = PTR_ERR(ctx);
		goto err_rhashtable_free;
	}
	optee->ctx = ctx;

	rc = optee_notif_init(optee, max_notif_value);
	if (rc)
		goto err_close_ctx;

	rc = optee_enumerate_devices(PTA_CMD_GET_DEVICES);
	if (rc)
		goto err_unregister_devices;

	INIT_WORK(&optee->rpmb_scan_bus_work, optee_bus_scan_rpmb);
	optee->rpmb_intf.notifier_call = optee_rpmb_intf_rdev;
	blocking_notifier_chain_register(&optee_rpmb_intf_added,
					 &optee->rpmb_intf);

	dev_info(dev, "initialized driver\n");

	return 0;

err_unregister_devices:
	optee_unregister_devices();
	optee_notif_uninit(optee);
err_close_ctx:
	teedev_close_context(ctx);
err_rhashtable_free:
	rhashtable_free_and_destroy(&optee->riscv.global_ids, rh_free_fn, NULL);
	rpmb_dev_put(optee->rpmb_dev);
	mutex_destroy(&optee->rpmb_dev_mutex);
	optee_supp_uninit(&optee->supp);
	mutex_destroy(&optee->call_queue.mutex);
	mutex_destroy(&optee->riscv.mutex);
err_unreg_supp_teedev:
	tee_device_unregister(optee->supp_teedev);
err_unreg_teedev:
	tee_device_unregister(optee->teedev);
err_free_shm_pool:
	tee_shm_pool_free(pool);
err_free_channels:
	optee_riscv_free_channels(optee);
	kfree(optee->riscv.chan);
err_free_optee:
	kfree(optee);
	return rc;
}

static void optee_riscv_remove(struct platform_device *pdev)
{
	struct optee *optee = platform_get_drvdata(pdev);

	optee_remove_common(optee);

	mutex_destroy(&optee->riscv.mutex);
	rhashtable_free_and_destroy(&optee->riscv.global_ids, rh_free_fn, NULL);

	optee_riscv_free_channels(optee);
	kfree(optee->riscv.chan);
	kfree(optee);
}

static const struct of_device_id optee_riscv_match[] = {
	{ .compatible = "riscv,rpmi-mpxy-tee" },
	{ }
};
MODULE_DEVICE_TABLE(of, optee_riscv_match);

static struct platform_driver optee_riscv_driver = {
	.driver = {
		.name = DRIVER_NAME "-riscv",
		.of_match_table = optee_riscv_match,
	},
	.probe = optee_riscv_probe,
	.remove = optee_riscv_remove,
};

int optee_riscv_abi_register(void)
{
	return platform_driver_register(&optee_riscv_driver);
}

void optee_riscv_abi_unregister(void)
{
	platform_driver_unregister(&optee_riscv_driver);
}
