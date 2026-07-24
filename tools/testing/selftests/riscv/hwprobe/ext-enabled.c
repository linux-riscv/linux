// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test the RISCV_HWPROBE_KEY_EXT_ENABLED positional modifier.
 *
 * The modifier is a one-way switch within a single hwprobe request: keys
 * before it report what is present in hardware, keys after it report what is
 * also enabled for the calling process. A single query returns both views:
 *
 *	[ {IMA_EXT_0}, {EXT_ENABLED}, {IMA_EXT_0} ]
 *	    present       modifier       enabled
 *
 * When V is disabled for the process it must drop out of the enabled view but
 * stay in the present view. V cannot be turned off for a thread that already
 * has it on (prctl returns -EPERM); the NEXT control only takes effect across
 * execve(). So the disabled-V case runs in a forked child that sets NEXT=off
 * and execs a nolibc worker (built without libc so no vector-optimized libc
 * routine can SIGILL while V is off). The worker reports back via exit code.
 */
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include "hwprobe.h"
#include "kselftest.h"

#ifndef PR_RISCV_V_SET_CONTROL
#define PR_RISCV_V_SET_CONTROL		69
#define PR_RISCV_V_VSTATE_CTRL_OFF	1
#endif
#define VSTATE_CTRL_NEXT_SHIFT		2

#define WORKER "./ext-enabled_nolibc"

/* Verdicts returned by the worker. */
#define VOFF_OK		0	/* present keeps V, enabled masks it */
#define VOFF_BUG	1	/* enabled view still reported V */
#define VOFF_SETUP	2	/* could not disable V / probe failed */

/* Run the canonical present/enabled query; returns the raw syscall result. */
static long query(__u64 *present, __u64 *enabled, __s64 *mod_key)
{
	struct riscv_hwprobe pairs[3] = {
		{ .key = RISCV_HWPROBE_KEY_IMA_EXT_0, },
		{ .key = RISCV_HWPROBE_KEY_EXT_ENABLED, },
		{ .key = RISCV_HWPROBE_KEY_IMA_EXT_0, },
	};
	long ret = riscv_hwprobe(pairs, 3, 0, NULL, 0);

	*present = pairs[0].value;
	*mod_key = pairs[1].key;
	*enabled = pairs[2].value;
	return ret;
}

/* Fork a child that disables V across execve, and return the worker verdict. */
static int probe_with_v_disabled(void)
{
	char * const argv[] = { WORKER, NULL };
	char * const envp[] = { NULL };
	int status;
	pid_t pid = fork();

	if (pid < 0)
		return VOFF_SETUP;
	if (pid == 0) {
		/* Disable V for the next execve of this child. */
		prctl(PR_RISCV_V_SET_CONTROL,
		      PR_RISCV_V_VSTATE_CTRL_OFF << VSTATE_CTRL_NEXT_SHIFT);
		execve(WORKER, argv, envp);
		_exit(VOFF_SETUP);		/* execve failed */
	}
	if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status))
		return VOFF_SETUP;
	return WEXITSTATUS(status);
}

/*
 * This test assumes the user space allow executing vector instruction as a
 * default behavior. Namely, /proc/sys/abi/riscv_v_default_allow is 1
 */
int main(void)
{
	__u64 present = 0, enabled = 0;
	__s64 mod_key = 0;
	int verdict;

	ksft_print_header();
	ksft_set_plan(2);

	if (query(&present, &enabled, &mod_key))
		ksft_exit_fail_msg("hwprobe() failed\n");

	ksft_test_result(mod_key == RISCV_HWPROBE_KEY_EXT_ENABLED,
			 "RISCV_HWPROBE_KEY_EXT_ENABLED is recognized\n");

	/* The remaining checks need both the modifier and V in hardware. */
	if (mod_key != RISCV_HWPROBE_KEY_EXT_ENABLED ||
	    !(enabled & RISCV_HWPROBE_IMA_V)) {
		ksft_test_result_skip("V off: present keeps V, enabled masks it\n");
		ksft_finished();
	}

	/* V off (only reachable across execve): enabled view masks it. */
	verdict = probe_with_v_disabled();
	if (verdict == VOFF_SETUP)
		ksft_test_result_skip("V off: present keeps V, but could not disable V\n");
	else
		ksft_test_result(verdict == VOFF_OK,
				 "V off: present keeps V, enabled masks it\n");

	ksft_finished();
}
