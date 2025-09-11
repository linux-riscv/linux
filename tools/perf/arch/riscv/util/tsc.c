// SPDX-License-Identifier: GPL-2.0

#include <linux/types.h>

#include "../../../util/tsc.h"

u64 rdtsc(void)
{
	u64 val;

	// https://lore.kernel.org/all/YxIzgYP3MujXdqwj@aurel32.net/T/
	asm volatile("rdtime %0" : "=r"(val));

	return val;
}
