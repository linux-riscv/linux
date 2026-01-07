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

#ifndef __ASM_ARM_BAO_H
#define __ASM_ARM_BAO_H

#include <linux/arm-smccc.h>
#include <linux/bao.h>

static inline unsigned long bao_ipcshmem_hypercall(unsigned long hypercall_id,
						   unsigned long ipcshmem_id)
{
	struct arm_smccc_res res;

	arm_smccc_hvc(ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL, ARM_SMCCC_SMC_32,
					 ARM_SMCCC_OWNER_VENDOR_HYP,
					 hypercall_id),
		      ipcshmem_id, 0, 0, 0, 0, 0, 0, &res);

	return res.a0;
}

static inline unsigned long
bao_remio_hypercall(struct bao_remio_hypercall_ctx *ctx)
{
	register int r0 asm("r0") =
		ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL, ARM_SMCCC_SMC_32,
				   ARM_SMCCC_OWNER_VENDOR_HYP, BAO_REMIO_HYPERCALL_ID);
	register u32 r1 asm("r1") = ctx->dm_id;
	register u32 r2 asm("r2") = ctx->addr;
	register u32 r3 asm("r3") = ctx->op;
	register u32 r4 asm("r4") = ctx->value;
	register u32 r5 asm("r5") = ctx->request_id;
	register u32 r6 asm("r6") = 0;

	asm volatile("hvc 0\n\t"
		     : "=r"(r0), "=r"(r1), "=r"(r2), "=r"(r3), "=r"(r4),
		       "=r"(r5), "=r"(r6)
		     : "r"(r0), "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5)
		     : "memory");

	ctx->addr = r1;
	ctx->op = r2;
	ctx->value = r3;
	ctx->access_width = r4;
	ctx->request_id = r5;
	ctx->npend_req = r6;

	return r0;
}

#endif /* __ASM_ARM_BAO_H */
