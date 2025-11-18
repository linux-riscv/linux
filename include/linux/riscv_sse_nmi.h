/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef __LINUX_RISCV_SSE_NMI_H
#define __LINUX_RISCV_SSE_NMI_H

#include <linux/cpumask.h>

enum local_nmi_type {
	LOCAL_NMI_NONE		= 0U,
	LOCAL_NMI_STOP		= BIT(0),
	LOCAL_NMI_CRASH		= BIT(1),
	LOCAL_NMI_BACKTRACE	= BIT(2),
	LOCAL_NMI_KGDB		= BIT(3),
};

#ifdef CONFIG_RISCV_SSE_NMI
bool nmi_support(void);
void send_nmi_mask(cpumask_t *mask, enum local_nmi_type type);
void send_nmi_single(unsigned int cpu, enum local_nmi_type type);
#else
static inline bool nmi_support(void) { return false; }
static inline void send_nmi_mask(cpumask_t *mask) { };
static inline void send_nmi_single(unsigned int cpu) { };
#endif

#endif
