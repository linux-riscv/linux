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

#define BAO_SBI_EXT_ID 0x08000ba0

static inline unsigned long bao_ipcshmem_hypercall(unsigned long hypercall_id,
						   unsigned long ipcshmem_id)
{
	struct sbiret ret;

	ret = sbi_ecall(BAO_SBI_EXT_ID, hypercall_id, ipcshmem_id, 0, 0, 0, 0,
			0);

	return ret.error;
}

#endif /* __ASM_RISCV_BAO_H */
