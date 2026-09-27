/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Bao Hypervisor hypercall interface
 *
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 *
 * Authors:
 *	João Peixoto <jpeixoto@osyx.tech>
 *	José Martins <jose@osyx.tech>
 *	David Cerdeira <davidmcerdeira@osyx.tech>
 *
 * Bao exposes its hypercalls through the architecture's standard hypervisor
 * call convention: SMCCC fast calls in the vendor-specific hypervisor service
 * range, issued with HVC, on arm/arm64 and an SBI extension, issued with
 * ecall, on RISC-V. The helpers below are built on the generic SMCCC and SBI
 * support, so no architecture-specific code is needed.
 */

#ifndef __BAO_HYPERCALL_H
#define __BAO_HYPERCALL_H

#include <linux/types.h>

/* IPC through shared-memory hypercall ID */
#define BAO_IPCSHMEM_HYPERCALL_ID 0x1

/* Remote I/O hypercall ID */
#define BAO_REMIO_HYPERCALL_ID 0x2

/**
 * struct bao_remio_hypercall_ctx - Remote I/O hypercall context
 * @dm_id: Device model identifier
 * @addr: Target address
 * @op: Operation code
 * @value: Value to read/write
 * @access_width: Access width in bytes
 * @request_id: Request identifier
 * @npend_req: Number of pending requests
 *
 * @dm_id, @addr, @op, @value and @request_id are passed to the hypervisor;
 * @addr, @op, @value, @access_width, @request_id and @npend_req are updated
 * with the values it returns.
 */
struct bao_remio_hypercall_ctx {
	u64 dm_id;
	u64 addr;
	u64 op;
	u64 value;
	u64 access_width;
	u64 request_id;
	u64 npend_req;
};

#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)

#include <linux/arm-smccc.h>

#ifdef CONFIG_ARM64
#define BAO_SMCCC_CONV ARM_SMCCC_SMC_64
#else
#define BAO_SMCCC_CONV ARM_SMCCC_SMC_32
#endif

/* Bao hypercalls are fast calls in the vendor-specific hypervisor range. */
#define BAO_HYPERCALL_FID(id)						\
	ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL, BAO_SMCCC_CONV,		\
			   ARM_SMCCC_OWNER_VENDOR_HYP, (id))

/**
 * bao_ipcshmem_hypercall - Notify the peer of an IPC shared-memory channel
 * @ipcshmem_id: Hypervisor-assigned channel identifier
 *
 * Return: The hypervisor status code, 0 on success.
 */
static inline unsigned long bao_ipcshmem_hypercall(unsigned long ipcshmem_id)
{
	struct arm_smccc_res res;

	arm_smccc_hvc(BAO_HYPERCALL_FID(BAO_IPCSHMEM_HYPERCALL_ID), ipcshmem_id,
		      0, 0, 0, 0, 0, 0, &res);

	return res.a0;
}

#ifdef CONFIG_ARM64
/**
 * bao_remio_hypercall - Issue a Remote I/O hypercall
 * @ctx: Hypercall context, updated with the values returned by the hypervisor
 *
 * The hypervisor returns the request in x1-x6 on top of the status in x0,
 * which is only expressible with an SMCCC v1.2 call.
 *
 * Return: The hypervisor status code, 0 on success.
 */
static inline unsigned long
bao_remio_hypercall(struct bao_remio_hypercall_ctx *ctx)
{
	struct arm_smccc_1_2_regs args = {
		.a0 = BAO_HYPERCALL_FID(BAO_REMIO_HYPERCALL_ID),
		.a1 = ctx->dm_id,
		.a2 = ctx->addr,
		.a3 = ctx->op,
		.a4 = ctx->value,
		.a5 = ctx->request_id,
	};
	struct arm_smccc_1_2_regs res;

	arm_smccc_1_2_hvc(&args, &res);

	ctx->addr = res.a1;
	ctx->op = res.a2;
	ctx->value = res.a3;
	ctx->access_width = res.a4;
	ctx->request_id = res.a5;
	ctx->npend_req = res.a6;

	return res.a0;
}
#endif /* CONFIG_ARM64 */

#elif defined(CONFIG_RISCV)

#include <asm/sbi.h>

/*
 * Bao SBI extension ID.
 *
 * This currently lives in the SBI experimental extension space
 * (0x08000000-0x08FFFFFF). A permanent ID has to be assigned through the
 * RISC-V SBI specification before the RISC-V support can be considered
 * stable; until then the RISC-V backend is experimental.
 */
#define BAO_SBI_EXT_ID 0x08000ba0

/**
 * bao_ipcshmem_hypercall - Notify the peer of an IPC shared-memory channel
 * @ipcshmem_id: Hypervisor-assigned channel identifier
 *
 * Return: The SBI error code, 0 on success.
 */
static inline unsigned long bao_ipcshmem_hypercall(unsigned long ipcshmem_id)
{
	struct sbiret ret;

	ret = sbi_ecall(BAO_SBI_EXT_ID, BAO_IPCSHMEM_HYPERCALL_ID, ipcshmem_id,
			0, 0, 0, 0, 0);

	return ret.error;
}

/**
 * bao_remio_hypercall - Issue a Remote I/O hypercall
 * @ctx: Hypercall context, updated with the values returned by the hypervisor
 *
 * The hypervisor returns the request in a2-a7 on top of the SBI error in a0,
 * which sbi_ecall() cannot express as it only exposes a0 and a1.
 *
 * Return: The SBI error code, 0 on success.
 */
static inline unsigned long
bao_remio_hypercall(struct bao_remio_hypercall_ctx *ctx)
{
	register unsigned long a0 asm("a0") = ctx->dm_id;
	register unsigned long a1 asm("a1") = ctx->addr;
	register unsigned long a2 asm("a2") = ctx->op;
	register unsigned long a3 asm("a3") = ctx->value;
	register unsigned long a4 asm("a4") = ctx->request_id;
	register unsigned long a5 asm("a5") = 0;
	register unsigned long a6 asm("a6") = BAO_REMIO_HYPERCALL_ID;
	register unsigned long a7 asm("a7") = BAO_SBI_EXT_ID;

	asm volatile("ecall"
		     : "+r"(a0), "+r"(a1), "+r"(a2), "+r"(a3), "+r"(a4),
		       "+r"(a5), "+r"(a6), "+r"(a7)
		     :
		     : "memory");

	ctx->addr = a2;
	ctx->op = a3;
	ctx->value = a4;
	ctx->access_width = a5;
	ctx->request_id = a6;
	ctx->npend_req = a7;

	return a0;
}

#endif

#endif /* __BAO_HYPERCALL_H */
