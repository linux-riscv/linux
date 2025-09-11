/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __RISCV_TRACE_H__
#define __RISCV_TRACE_H__

#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/types.h>
#include <linux/perf_event.h>

#define RISCV_TRACE_ADDR_MASK GENMASK(63, 0)

enum RISCV_TRACE_COMPONENT_TYPE {
	RISCV_TRACE_ENCODER = 0,
	RISCV_TRACE_FUNNEL,
	RISCV_TRACE_SINK,
};

enum RISCV_TRACE_FUNNEL_LEVEL {
	LEVEL1_FUNNEL = 1,
	LEVEL2_FUNNEL = 2,
};

enum RISCV_TRACE_PRIV_MODE_TYPE {
	RISCV_TRACE_PRIV_MODE_EXCL_NONE = 0,
	RISCV_TRACE_PRIV_MODE_EXCL_KERN,
	RISCV_TRACE_PRIV_MODE_EXCL_USER,
};

struct riscv_trace_filter_attr {
	u64 start_addr;
	u64 stop_addr;
	u32 priv_mode;		// user&kernel
};

struct riscv_io_port {
	bool is_input;		// input=1, output=0
	u32 endpoint_num;
	enum RISCV_TRACE_COMPONENT_TYPE type;
	u64 base_addr;
};

struct riscv_trace_encoder {
	u32 cpu;
};

struct riscv_trace_funnel {
	enum RISCV_TRACE_FUNNEL_LEVEL level;
};

struct riscv_trace_sink {
	;
};

struct riscv_trace_component {
	enum RISCV_TRACE_COMPONENT_TYPE type;
	u64 reg_base;
	u64 reg_size;
	struct list_head list;

	union {
		struct riscv_trace_encoder encoder;
		struct riscv_trace_funnel funnel;
		struct riscv_trace_sink sink;
	};

	u32 in_num;
	u32 out_num;
	struct riscv_io_port **in;
	struct riscv_io_port **out;
};

extern struct list_head riscv_trace_controllers;

struct riscv_trace_pmu {
	struct pmu pmu;
	struct riscv_trace_filter_attr filter_attr;
};

static inline const char *riscv_trace_type2str(enum RISCV_TRACE_COMPONENT_TYPE
					       type)
{
	switch (type) {
	case RISCV_TRACE_ENCODER:
		return "encoder";
	case RISCV_TRACE_FUNNEL:
		return "funnel";
	case RISCV_TRACE_SINK:
		return "sink";
	default:
		return "none";
	}
}

static inline int count_device_node_child(struct device_node *parent)
{
	struct device_node *child;
	int count = 0;

	for_each_child_of_node(parent, child) {
		count++;
	}

	return count;
}

static inline int get_list_count(struct list_head *head)
{
	u32 count = 0;
	struct list_head *pos;

	list_for_each(pos, head) {
		count++;
	}

	return count;
}

int riscv_trace_encoder_init(void);
int riscv_trace_funnel_init(void);
int riscv_trace_sink_init(void);

#endif /* __RISCV_TRACE_H__ */
