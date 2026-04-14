// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(C) 2026 Spacemit Limited. All rights reserved.
 */

#include <string.h>
#include <linux/perf_event.h>

#include "../../../util/pmu.h"

#define RVTRACE_PMU_NAME "rvtrace"

void perf_pmu__arch_init(struct perf_pmu *pmu)
{
	if (!strcmp(pmu->name, RVTRACE_PMU_NAME)) {
		pmu->auxtrace = true;
		pmu->selectable = true;
	}
}

