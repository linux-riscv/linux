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

#endif

#endif /* __BAO_HYPERCALL_H */
