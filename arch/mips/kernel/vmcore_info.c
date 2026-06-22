// SPDX-License-Identifier: GPL-2.0-only

#include <linux/vmcore_info.h>

#include <asm/pgtable.h>
#include <asm/sigcontext.h>

extern void mips_rt_signal_frame(void);

void arch_crash_save_vmcoreinfo(void)
{
	mips_rt_signal_frame();
	VMCOREINFO_OFFSET(sigcontext, sc_regs);
	VMCOREINFO_NUMBER(PAGE_SHIFT);
	VMCOREINFO_NUMBER(_PFN_MASK);
	VMCOREINFO_NUMBER(_PAGE_PRESENT);
	VMCOREINFO_NUMBER(_PAGE_VALID);
	VMCOREINFO_NUMBER(_PAGE_GLOBAL);
	VMCOREINFO_NUMBER(PTRS_PER_PGD);
	VMCOREINFO_NUMBER(PTRS_PER_PMD);
	VMCOREINFO_NUMBER(PTRS_PER_PTE);
}
