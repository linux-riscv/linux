/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Bao Hypervisor Hypercall Interface
 *
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 *
 * Authors:
 *	João Peixoto <joaopeixoto@osyx.tech>
 *	José Martins <jose@osyx.tech>
 *	David Cerdeira <davidmcerdeira@osyx.tech>
 */

#ifndef __ASM_ARM64_BAO_H
#define __ASM_ARM64_BAO_H

#include <linux/arm-smccc.h>
#include <linux/bao.h>

static inline unsigned long bao_ipcshmem_hypercall(unsigned long hypercall_id,
						   unsigned long ipcshmem_id)
{
	struct arm_smccc_res res;

	arm_smccc_hvc(ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL, ARM_SMCCC_SMC_64,
					 ARM_SMCCC_OWNER_VENDOR_HYP,
					 hypercall_id),
		      ipcshmem_id, 0, 0, 0, 0, 0, 0, &res);

	return res.a0;
}

static inline unsigned long
bao_remio_hypercall(struct bao_remio_hypercall_ctx *ctx)
{
	register int x0 asm("x0") =
		ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL, ARM_SMCCC_SMC_64,
				   ARM_SMCCC_OWNER_VENDOR_HYP, BAO_REMIO_HYPERCALL_ID);
	register u64 x1 asm("x1") = ctx->dm_id;
	register u64 x2 asm("x2") = ctx->addr;
	register u64 x3 asm("x3") = ctx->op;
	register u64 x4 asm("x4") = ctx->value;
	register u64 x5 asm("x5") = ctx->request_id;
	register u64 x6 asm("x6") = 0;

	asm volatile("hvc 0\n\t"
		     : "=r"(x0), "=r"(x1), "=r"(x2), "=r"(x3), "=r"(x4),
		       "=r"(x5), "=r"(x6)
		     : "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
		     : "memory");

	ctx->addr = x1;
	ctx->op = x2;
	ctx->value = x3;
	ctx->access_width = x4;
	ctx->request_id = x5;
	ctx->npend_req = x6;

	return x0;
}

#endif /* __ASM_ARM64_BAO_H */
