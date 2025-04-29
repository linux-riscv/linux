/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_CONTEXT_TRACKING_WORK_H
#define _ASM_X86_CONTEXT_TRACKING_WORK_H

#include <asm/sync_core.h>

static __always_inline void arch_context_tracking_work(enum ct_work work)
{
	switch (work) {
	case CT_WORK_SYNC:
		sync_core();
		break;
	case CT_WORK_MAX:
		WARN_ON_ONCE(true);
	}
}

#endif
