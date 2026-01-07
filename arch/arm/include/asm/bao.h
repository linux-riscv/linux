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

#endif /* __ASM_ARM_BAO_H */
