// SPDX-License-Identifier: GPL-2.0
#include <byteswap.h>
#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/log2.h>
#include <linux/types.h>
#include <linux/zalloc.h>
#include <stdlib.h>
#include <unistd.h>

#include "auxtrace.h"
#include "color.h"
#include "debug.h"
#include "evsel.h"
#include "riscv-trace.h"
#include "machine.h"
#include "session.h"
#include "tool.h"
#include <internal/lib.h>

struct riscv_trace {
	struct auxtrace auxtrace;
	u32 auxtrace_type;
	struct perf_session *session;
	struct machine *machine;
	u32 pmu_type;
};

static void riscv_trace_dump(struct riscv_trace *trace __maybe_unused,
			  unsigned char *buf, size_t len)
{

	const char *color = PERF_COLOR_BLUE;

	color_fprintf(stdout, color, ". ... %s: buf=%p len=%zubytes\n", __func__, buf, len);
	for (size_t i = 0; i < len; i++)
		printf("%02x ", buf[i]);
}

static void riscv_trace_dump_event(struct riscv_trace *trace, unsigned char *buf,
				size_t len)
{
	printf(".\n");

	riscv_trace_dump(trace, buf, len);
}

static int riscv_trace_process_event(struct perf_session *session __maybe_unused,
				  union perf_event *event __maybe_unused,
				  struct perf_sample *sample __maybe_unused,
				  const struct perf_tool *tool __maybe_unused)
{
	return 0;
}

static int riscv_trace_process_auxtrace_event(struct perf_session *session,
					   union perf_event *event,
					   const struct perf_tool *tool __maybe_unused)
{
	struct riscv_trace *trace = container_of(session->auxtrace, struct riscv_trace,
					    auxtrace);
	int fd = perf_data__fd(session->data);
	int size = event->auxtrace.size;
	void *data = malloc(size);
	off_t data_offset;
	int err;

	if (!data)
		return -errno;

	if (perf_data__is_pipe(session->data)) {
		data_offset = 0;
	} else {
		data_offset = lseek(fd, 0, SEEK_CUR);
		if (data_offset == -1) {
			free(data);
			return -errno;
		}
	}

	err = readn(fd, data, size);
	if (err != (ssize_t)size) {
		free(data);
		return -errno;
	}

	if (dump_trace)
		riscv_trace_dump_event(trace, data, size);

	free(data);
	return 0;
}

static int riscv_trace_flush(struct perf_session *session __maybe_unused,
			  const struct perf_tool *tool __maybe_unused)
{
	return 0;
}

static void riscv_trace_free_events(struct perf_session *session __maybe_unused)
{
}

static void riscv_trace_free(struct perf_session *session)
{
	struct riscv_trace *trace = container_of(session->auxtrace, struct riscv_trace,
					    auxtrace);

	session->auxtrace = NULL;
	free(trace);
}

static bool riscv_trace_evsel_is_auxtrace(struct perf_session *session,
				       struct evsel *evsel)
{
	struct riscv_trace *trace = container_of(session->auxtrace, struct riscv_trace, auxtrace);

	return evsel->core.attr.type == trace->pmu_type;
}

static void riscv_trace_print_info(__u64 type)
{
	if (!dump_trace)
		return;

	fprintf(stdout, "  PMU Type           %" PRId64 "\n", (s64) type);
}

int riscv_trace_process_auxtrace_info(union perf_event *event,
				   struct perf_session *session)
{
	struct perf_record_auxtrace_info *auxtrace_info = &event->auxtrace_info;
	struct riscv_trace *trace;

	if (auxtrace_info->header.size < RISCV_TRACE_AUXTRACE_PRIV_SIZE +
				sizeof(struct perf_record_auxtrace_info))
		return -EINVAL;

	trace = zalloc(sizeof(*trace));
	if (!trace)
		return -ENOMEM;

	trace->session = session;
	trace->machine = &session->machines.host; /* No kvm support */
	trace->auxtrace_type = auxtrace_info->type;
	trace->pmu_type = auxtrace_info->priv[0];

	trace->auxtrace.process_event = riscv_trace_process_event;
	trace->auxtrace.process_auxtrace_event = riscv_trace_process_auxtrace_event;
	trace->auxtrace.flush_events = riscv_trace_flush;
	trace->auxtrace.free_events = riscv_trace_free_events;
	trace->auxtrace.free = riscv_trace_free;
	trace->auxtrace.evsel_is_auxtrace = riscv_trace_evsel_is_auxtrace;
	session->auxtrace = &trace->auxtrace;

	riscv_trace_print_info(auxtrace_info->priv[0]);

	return 0;
}
