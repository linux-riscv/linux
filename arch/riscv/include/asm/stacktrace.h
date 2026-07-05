/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_RISCV_STACKTRACE_H
#define _ASM_RISCV_STACKTRACE_H

#include <linux/sched.h>
#include <asm/ptrace.h>

struct stackframe {
	unsigned long fp;
	unsigned long ra;
};

extern void notrace walk_stackframe(struct task_struct *task, struct pt_regs *regs,
				    bool (*fn)(void *, unsigned long), void *arg);
extern void dump_backtrace(struct pt_regs *regs, struct task_struct *task,
			   const char *loglvl);

static inline bool on_thread_stack(void)
{
	return !(((unsigned long)(current->stack) ^ current_stack_pointer) & ~(THREAD_SIZE - 1));
}


/*
 * Declare unconditionally so that arch/riscv/kernel/stacktrace.c can use
 * IS_ENABLED(CONFIG_VMAP_STACK) rather than #ifdef, in line with the kernel
 * coding style. The DEFINE_PER_CPU (memory allocation) remains guarded by
 * CONFIG_VMAP_STACK in traps.c.
 */
DECLARE_PER_CPU(unsigned long [OVERFLOW_STACK_SIZE/sizeof(long)], overflow_stack);

#endif /* _ASM_RISCV_STACKTRACE_H */
