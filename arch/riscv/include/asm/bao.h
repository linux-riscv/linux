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

#ifndef __ASM_RISCV_BAO_H
#define __ASM_RISCV_BAO_H

#include <asm/sbi.h>
#include <linux/bao.h>

#define BAO_SBI_EXT_ID 0x08000ba0

static inline unsigned long bao_ipcshmem_hypercall(unsigned long ipcshmem_id)
{
	struct sbiret ret;

	ret = sbi_ecall(BAO_SBI_EXT_ID, BAO_IPCSHMEM_HYPERCALL_ID, ipcshmem_id,
			0, 0, 0, 0, 0);

	return ret.error;
}

static inline unsigned long
bao_remio_hypercall(struct bao_remio_hypercall_ctx *ctx)
{
	register uintptr_t a0 asm("a0") = (uintptr_t)(ctx->dm_id);
	register uintptr_t a1 asm("a1") = (uintptr_t)(ctx->addr);
	register uintptr_t a2 asm("a2") = (uintptr_t)(ctx->op);
	register uintptr_t a3 asm("a3") = (uintptr_t)(ctx->value);
	register uintptr_t a4 asm("a4") = (uintptr_t)(ctx->request_id);
	register uintptr_t a5 asm("a5") = (uintptr_t)(0);
	register uintptr_t a6 asm("a6") = (uintptr_t)(BAO_REMIO_HYPERCALL_ID);
	register uintptr_t a7 asm("a7") = (uintptr_t)(0x08000ba0);

	asm volatile("ecall"
		     : "+r"(a0), "+r"(a1), "+r"(a2), "+r"(a3), "+r"(a4),
		       "+r"(a5), "+r"(a6), "+r"(a7)
		     : "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5),
		       "r"(a6), "r"(a7)
		     : "memory");

	ctx->addr = a2;
	ctx->op = a3;
	ctx->value = a4;
	ctx->access_width = a5;
	ctx->request_id = a6;
	ctx->npend_req = a7;

	return a0;
}

#endif /* __ASM_RISCV_BAO_H */
