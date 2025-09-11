// SPDX-License-Identifier: GPL-2.0

#include <dirent.h>
#include <stdbool.h>
#include <linux/zalloc.h>
#include <api/fs/fs.h>

#include "../../../util/auxtrace.h"
#include "../../../util/debug.h"
#include "../../../util/evlist.h"
#include "../../../util/pmu.h"
#include "../../../util/pmus.h"
#include "riscv-trace.h"

struct auxtrace_record
*auxtrace_record__init(struct evlist *evlist, int *err)
{
	struct perf_pmu	*riscv_trace_pmu = NULL;
	struct evsel *evsel;
	bool found_riscv_trace = false;

	riscv_trace_pmu = perf_pmus__find(RISCV_TRACE_PMU_NAME);

	evlist__for_each_entry(evlist, evsel) {
		if (riscv_trace_pmu && evsel->core.attr.type == riscv_trace_pmu->type)
			found_riscv_trace = true;
	}

	if (found_riscv_trace)
		return riscv_trace_recording_init(err, riscv_trace_pmu);

	return NULL;
}
