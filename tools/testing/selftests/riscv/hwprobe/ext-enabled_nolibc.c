// SPDX-License-Identifier: GPL-2.0-only
/*
 * nolibc worker for the RISCV_HWPROBE_KEY_EXT_ENABLED test.
 *
 * ext-enabled execs this program with V disabled for the process. It is built
 * with nolibc on purpose: there is no libc here, so no vector-optimized libc
 * routine can run and take a SIGILL while V is off. It probes the canonical
 * [present, modifier, enabled] request and reports a verdict via exit code:
 *
 *	0  present keeps V, enabled masks it  (correct)
 *	1  enabled view still reports V        (bug)
 *	2  setup problem (V not off, or hwprobe failed)
 */

#ifndef __NR_riscv_hwprobe
#define __NR_riscv_hwprobe		258
#endif

#ifndef PR_RISCV_V_GET_CONTROL
#define PR_RISCV_V_GET_CONTROL		70
#define PR_RISCV_V_VSTATE_CTRL_OFF	1
#define PR_RISCV_V_VSTATE_CTRL_CUR_MASK	0x3
#endif

#define RISCV_HWPROBE_KEY_IMA_EXT_0	4
#define RISCV_HWPROBE_KEY_EXT_ENABLED	17
#define RISCV_HWPROBE_IMA_V		(1 << 2)

struct riscv_hwprobe {
	long long key;
	unsigned long long value;
};

int main(void)
{
	struct riscv_hwprobe pairs[3] = {
		{ .key = RISCV_HWPROBE_KEY_IMA_EXT_0 },
		{ .key = RISCV_HWPROBE_KEY_EXT_ENABLED },
		{ .key = RISCV_HWPROBE_KEY_IMA_EXT_0 },
	};
	long ctrl;

	/* We must really be running with V turned off. */
	ctrl = prctl(PR_RISCV_V_GET_CONTROL, 0, 0, 0, 0);
	if (ctrl < 0 ||
	    (ctrl & PR_RISCV_V_VSTATE_CTRL_CUR_MASK) != PR_RISCV_V_VSTATE_CTRL_OFF)
		return 2;

	if (syscall(__NR_riscv_hwprobe, pairs, 3, 0, 0, 0))
		return 2;

	/* Present view must still carry V (it is in hardware). */
	if (!(pairs[0].value & RISCV_HWPROBE_IMA_V))
		return 2;

	/* Enabled view must have masked V out. */
	return (pairs[2].value & RISCV_HWPROBE_IMA_V) ? 1 : 0;
}
