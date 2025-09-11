/* SPDX-License-Identifier: GPL-2.0 */
#ifndef INCLUDE__PERF_RISCV_TRACE_H__
#define INCLUDE__PERF_RISCV_TRACE_H__

#define RISCV_TRACE_PMU_NAME		"riscv_trace"
#define RISCV_TRACE_AUXTRACE_PRIV_SIZE	sizeof(u64)

union perf_event;
struct perf_session;
struct perf_pmu;

struct auxtrace_record *riscv_trace_recording_init(int *err,
						struct perf_pmu *riscv_ntrace_pmu);

int riscv_trace_process_auxtrace_info(union perf_event *event,
				   struct perf_session *session);

#endif
