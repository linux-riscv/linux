// SPDX-License-Identifier: GPL-2.0

#include <linux/entry-common.h>

#define CREATE_TRACE_POINTS
#include <trace/events/syscalls.h>

/* Out of line to prevent tracepoint code duplication */

bool trace_syscall_enter(struct pt_regs *regs, long *syscall)
{
	trace_sys_enter(regs, *syscall);
	/*
	 * Probes or BPF hooks in the tracepoint may have changed the
	 * system call number. Reread it.
	 */
	*syscall = syscall_get_nr(current, regs);
	return *syscall != -1L;
}

void trace_syscall_exit(struct pt_regs *regs, long ret)
{
	trace_sys_exit(regs, ret);
}
