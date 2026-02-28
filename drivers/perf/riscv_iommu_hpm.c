// SPDX-License-Identifier: GPL-2.0-only
/*
 * RISC-V IOMMU Hardware Performance Monitor driver
 *
 * This driver provides perf-based performance monitoring for RISC-V IOMMU
 * devices via the auxiliary bus framework.
 *
 * Copyright (C) 2026 SpacemiT Technologies Inc.
 *    Author: 2026 Jingyu Li <joey.li@spacemit.com>
 *                 Lv Zheng <lv.zheng@spacemit.com>
 */

#include <linux/bitfield.h>
#include <linux/perf_event.h>
#include <linux/riscv_iommu.h>

/* Performance monitoring registers */
#define RISCV_IOMMU_REG_IOCOUNTOVF	0x0000
#define RISCV_IOMMU_IOCOUNTOVF_CY	BIT(0)
#define RISCV_IOMMU_IOCOUNTOVF_HPM	GENMASK_ULL(31, 1)

#define RISCV_IOMMU_REG_IOCOUNTINH	0x0004
#define RISCV_IOMMU_IOCOUNTINH_CY	BIT(0)
#define RISCV_IOMMU_IOCOUNTINH_HPM	GENMASK(31, 1)

#define RISCV_IOMMU_REG_IOHPMCYCLES	0x0008
#define RISCV_IOMMU_IOHPMCYCLES_COUNTER	GENMASK_ULL(62, 0)
#define RISCV_IOMMU_IOHPMCYCLES_OF	BIT_ULL(63)

#define RISCV_IOMMU_REG_IOHPMCTR_BASE	0x0010
#define RISCV_IOMMU_REG_IOHPMCTR(_n)	(RISCV_IOMMU_REG_IOHPMCTR_BASE + ((_n) * 0x8))
#define RISCV_IOMMU_IOHPMEVENT_COUNTER	GENMASK_ULL(63, 0)

#define RISCV_IOMMU_REG_IOHPMEVT_BASE	0x0108
#define RISCV_IOMMU_REG_IOHPMEVT(_n)	(RISCV_IOMMU_REG_IOHPMEVT_BASE + ((_n) * 0x8))
#define RISCV_IOMMU_IOHPMEVT_EVENTID	GENMASK_ULL(14, 0)
#define RISCV_IOMMU_IOHPMEVT_DMASK	BIT_ULL(15)
#define RISCV_IOMMU_IOHPMEVT_PID_PSCID	GENMASK_ULL(35, 16)
#define RISCV_IOMMU_IOHPMEVT_DID_GSCID	GENMASK_ULL(59, 36)
#define RISCV_IOMMU_IOHPMEVT_PV_PSCV	BIT_ULL(60)
#define RISCV_IOMMU_IOHPMEVT_DV_GSCV	BIT_ULL(61)
#define RISCV_IOMMU_IOHPMEVT_IDT	BIT_ULL(62)
#define RISCV_IOMMU_IOHPMEVT_OF		BIT_ULL(63)

/* HPM counter definitions */
#define RISCV_IOMMU_IOHPMEVT_CNT	31
#define RISCV_IOMMU_HPMCOUNTER_CYCLES	RISCV_IOMMU_IOHPMEVT_CNT
#define RISCV_IOMMU_HPMCOUNTER_MAX	(RISCV_IOMMU_IOHPMEVT_CNT + 1)

/* HPM event IDs */
enum riscv_iommu_hpmevent_id {
	RISCV_IOMMU_HPMEVENT_INVALID    = 0,
	RISCV_IOMMU_HPMEVENT_URQ        = 1,
	RISCV_IOMMU_HPMEVENT_TRQ        = 2,
	RISCV_IOMMU_HPMEVENT_ATS_RQ     = 3,
	RISCV_IOMMU_HPMEVENT_TLB_MISS   = 4,
	RISCV_IOMMU_HPMEVENT_DD_WALK    = 5,
	RISCV_IOMMU_HPMEVENT_PD_WALK    = 6,
	RISCV_IOMMU_HPMEVENT_S_VS_WALKS = 7,
	RISCV_IOMMU_HPMEVENT_G_WALKS    = 8,
	RISCV_IOMMU_HPMEVENT_MAX        = 128
};

#define RISCV_IOMMU_HPMEVENT_CYCLES	RISCV_IOMMU_HPMEVENT_INVALID
#define RISCV_IOMMU_HPMEVENT_MAX	128

#define to_iommu_hpm(p) (container_of(p, struct riscv_iommu_hpm, pmu))

#define RISCV_IOMMU_HPM_EVENT_EXTRACTOR(_n, _c, _s, _e)		\
	static inline u32 get_##_n(struct perf_event *event)	\
	{							\
		return FIELD_GET(GENMASK_ULL(_e, _s),		\
				 event->attr._c);		\
	}

RISCV_IOMMU_HPM_EVENT_EXTRACTOR(event, config, 0, 14);
RISCV_IOMMU_HPM_EVENT_EXTRACTOR(filter_dmask, config1, 15, 15);
RISCV_IOMMU_HPM_EVENT_EXTRACTOR(filter_pid_pscid, config1, 16, 35);
RISCV_IOMMU_HPM_EVENT_EXTRACTOR(filter_did_gscid, config1, 36, 59);
RISCV_IOMMU_HPM_EVENT_EXTRACTOR(filter_pv_pscv, config1, 60, 60);
RISCV_IOMMU_HPM_EVENT_EXTRACTOR(filter_dv_gscv, config1, 61, 61);
RISCV_IOMMU_HPM_EVENT_EXTRACTOR(filter_idt, config1, 62, 62);

struct riscv_iommu_hpm {
	struct pmu pmu;
	struct riscv_iommu_subdev *subdev;
	void __iomem *base;
	unsigned int irq;
	unsigned int on_cpu;
	struct hlist_node node;
	/*
	 * Layout of events:
	 * 0       -> HPMCYCLES
	 * 1...n-1 -> HPMEVENTS
	 */
	struct perf_event *events[RISCV_IOMMU_HPMCOUNTER_MAX];
	DECLARE_BITMAP(supported_events, RISCV_IOMMU_HPMEVENT_MAX);
	DECLARE_BITMAP(used_counters, RISCV_IOMMU_HPMCOUNTER_MAX);
	unsigned int num_counters;
};

static DEFINE_MUTEX(riscv_iommu_hpm_lock);
static int cpuhp_state_num = -1;

static inline void riscv_iommu_hpm_writel(struct riscv_iommu_hpm *hpm, u32 reg,
					  u32 val)
{
	writel_relaxed(val, hpm->base + reg);
}

static inline u32 riscv_iommu_hpm_readl(struct riscv_iommu_hpm *hpm, u32 reg)
{
	return readl_relaxed(hpm->base + reg);
}

static inline void riscv_iommu_hpm_writeq(struct riscv_iommu_hpm *hpm, u32 reg,
					  u64 val)
{
	writeq_relaxed(val, hpm->base + reg);
}

static inline u64 riscv_iommu_hpm_readq(struct riscv_iommu_hpm *hpm, u32 reg)
{
	return readq_relaxed(hpm->base + reg);
}

/* All iohpmcycles and iohpmctr registers are 64-bit wide and WARL. If a
 * 32-bit counter width should be supported according to a newer revision
 * of the standard or a vendor specific implementation, the following
 * functions should be extended.
 */
static inline void riscv_iommu_hpm_cycles_set_value(struct riscv_iommu_hpm *hpm,
						    u64 value)
{
	riscv_iommu_hpm_writeq(hpm, RISCV_IOMMU_REG_IOHPMCYCLES,
			       value & RISCV_IOMMU_IOHPMCYCLES_COUNTER);
}

static inline u64 riscv_iommu_hpm_cycles_get_value(struct riscv_iommu_hpm *hpm)
{
	return riscv_iommu_hpm_readq(hpm, RISCV_IOMMU_REG_IOHPMCYCLES) &
	       RISCV_IOMMU_IOHPMCYCLES_COUNTER;
}

static inline void riscv_iommu_hpm_counter_set_value(struct riscv_iommu_hpm *hpm,
						     u32 idx, u64 value)
{
	riscv_iommu_hpm_writeq(hpm, RISCV_IOMMU_REG_IOHPMCTR(idx), value);
}

static inline u64 riscv_iommu_hpm_counter_get_value(struct riscv_iommu_hpm *hpm,
						    u32 idx)
{
	return riscv_iommu_hpm_readq(hpm, RISCV_IOMMU_REG_IOHPMCTR(idx));
}

static inline void riscv_iommu_hpm_cycles_enable(struct riscv_iommu_hpm *hpm)
{
	u32 val = riscv_iommu_hpm_readl(hpm, RISCV_IOMMU_REG_IOCOUNTINH);

	val &= ~RISCV_IOMMU_IOCOUNTINH_CY;
	riscv_iommu_hpm_writel(hpm, RISCV_IOMMU_REG_IOCOUNTINH, val);
}

static inline void riscv_iommu_hpm_cycles_disable(struct riscv_iommu_hpm *hpm)
{
	u32 val = riscv_iommu_hpm_readl(hpm, RISCV_IOMMU_REG_IOCOUNTINH);

	val |= RISCV_IOMMU_IOCOUNTINH_CY;
	riscv_iommu_hpm_writel(hpm, RISCV_IOMMU_REG_IOCOUNTINH, val);
}

static inline void riscv_iommu_hpm_counter_enable(struct riscv_iommu_hpm *hpm,
						  u32 idx)
{
	u32 val = riscv_iommu_hpm_readl(hpm, RISCV_IOMMU_REG_IOCOUNTINH);

	val &= ~BIT(idx + 1);
	riscv_iommu_hpm_writel(hpm, RISCV_IOMMU_REG_IOCOUNTINH, val);
}

static inline void riscv_iommu_hpm_counter_disable(struct riscv_iommu_hpm *hpm,
						   u32 idx)
{
	u32 val = riscv_iommu_hpm_readl(hpm, RISCV_IOMMU_REG_IOCOUNTINH);

	val |= BIT(idx + 1);
	riscv_iommu_hpm_writel(hpm, RISCV_IOMMU_REG_IOCOUNTINH, val);
}

static inline void riscv_iommu_hpm_cycles_clear_ovf(struct riscv_iommu_hpm *hpm)
{
	u64 val = riscv_iommu_hpm_readq(hpm, RISCV_IOMMU_REG_IOHPMCYCLES);

	val &= ~RISCV_IOMMU_IOHPMCYCLES_OF;
	riscv_iommu_hpm_writeq(hpm, RISCV_IOMMU_REG_IOHPMCYCLES, val);
}

static inline void riscv_iommu_hpm_counter_clear_ovf(struct riscv_iommu_hpm *hpm,
						     u32 idx)
{
	u64 val = riscv_iommu_hpm_readq(hpm, RISCV_IOMMU_REG_IOHPMEVT(idx));

	val &= ~RISCV_IOMMU_IOHPMEVT_OF;
	riscv_iommu_hpm_writeq(hpm, RISCV_IOMMU_REG_IOHPMEVT(idx), val);
}

static inline void riscv_iommu_hpm_interrupt_clear(struct riscv_iommu_hpm *hpm)
{
	riscv_iommu_clear_pmip(hpm->subdev);
}

/**
 * riscv_iommu_hpm_event_update() - Update and return RISC-V IOMMU HPM
 *                                  event counters
 *
 * @event: IOMMU performance event
 *
 * This function can be used to implement the .read() interface of pmu.
 */
static void riscv_iommu_hpm_event_update(struct perf_event *event)
{
	struct hw_perf_event *hwc = &event->hw;
	struct riscv_iommu_hpm *hpm = to_iommu_hpm(event->pmu);
	u64 delta, prev, now;
	u32 idx = hwc->idx;

	do {
		prev = local64_read(&hwc->prev_count);
		if (idx == RISCV_IOMMU_HPMCOUNTER_CYCLES)
			now = riscv_iommu_hpm_cycles_get_value(hpm);
		else
			now = riscv_iommu_hpm_counter_get_value(hpm, idx);
	} while (local64_cmpxchg(&hwc->prev_count, prev, now) != prev);

	delta = now - prev;
	if (idx == RISCV_IOMMU_HPMCOUNTER_CYCLES)
		delta &= RISCV_IOMMU_IOHPMCYCLES_COUNTER;
	else
		delta &= RISCV_IOMMU_IOHPMEVENT_COUNTER;

	local64_add(delta, &event->count);
}

static void riscv_iommu_hpm_set_period(struct riscv_iommu_hpm *hpm,
				       struct hw_perf_event *hwc)
{
	u32 idx = hwc->idx;
	u64 new, max_period;

	if (idx == RISCV_IOMMU_HPMCOUNTER_CYCLES)
		max_period = RISCV_IOMMU_IOHPMCYCLES_COUNTER;
	else
		max_period = RISCV_IOMMU_IOHPMEVENT_COUNTER;

	/* Start at half the counter range */
	new = max_period >> 1;

	if (idx == RISCV_IOMMU_HPMCOUNTER_CYCLES)
		riscv_iommu_hpm_cycles_set_value(hpm, new);
	else
		riscv_iommu_hpm_counter_set_value(hpm, idx, new);

	local64_set(&hwc->prev_count, new);
}

/**
 * riscv_iommu_hpm_event_start() - Start RISC-V IOMMU HPM event
 *
 * @event: IOMMU performance event
 * @flags: Performance event flags
 *
 * This function can be used to implement the .start() interface of pmu.
 */
static void riscv_iommu_hpm_event_start(struct perf_event *event, int flags)
{
	struct riscv_iommu_hpm *hpm = to_iommu_hpm(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	u32 idx = hwc->idx;

	hwc->state = 0;
	riscv_iommu_hpm_set_period(hpm, hwc);

	if (idx == RISCV_IOMMU_HPMCOUNTER_CYCLES)
		riscv_iommu_hpm_cycles_enable(hpm);
	else
		riscv_iommu_hpm_counter_enable(hpm, idx);
}

/**
 * riscv_iommu_hpm_event_stop() - Stop RISC-V IOMMU HPM event
 *
 * @event: IOMMU performance event
 * @flags: Performance event flags
 *
 * This function can be used to implement the .stop() interface of pmu.
 */
static void riscv_iommu_hpm_event_stop(struct perf_event *event, int flags)
{
	struct riscv_iommu_hpm *hpm = to_iommu_hpm(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	u32 idx = hwc->idx;

	if (hwc->state & PERF_HES_STOPPED)
		return;

	if (idx == RISCV_IOMMU_HPMCOUNTER_CYCLES)
		riscv_iommu_hpm_cycles_disable(hpm);
	else
		riscv_iommu_hpm_counter_disable(hpm, idx);

	if (flags & PERF_EF_UPDATE)
		riscv_iommu_hpm_event_update(event);
	hwc->state |= PERF_HES_STOPPED | PERF_HES_UPTODATE;
}

static void riscv_iommu_hpm_set_event_filter(struct perf_event *event, int idx,
					     u32 pid_pscid, u32 did_gscid,
					     u32 pv_pscv,
					     u32 dv_gscv, u32 idt, u32 dmask)
{
	struct riscv_iommu_hpm *hpm = to_iommu_hpm(event->pmu);
	u64 event_cfg;

	/* Start with event ID */
	event_cfg = get_event(event);
	/* Set ID fields - values of 0 are valid */
	event_cfg |= FIELD_PREP(RISCV_IOMMU_IOHPMEVT_PID_PSCID,
				pid_pscid & 0xFFFFF);
	event_cfg |= FIELD_PREP(RISCV_IOMMU_IOHPMEVT_DID_GSCID,
				did_gscid & 0xFFFFFF);
	/* Set control flags - 0 means disabled, 1 means enabled */
	if (pv_pscv)
		event_cfg |= RISCV_IOMMU_IOHPMEVT_PV_PSCV;
	if (dv_gscv)
		event_cfg |= RISCV_IOMMU_IOHPMEVT_DV_GSCV;
	if (idt)
		event_cfg |= RISCV_IOMMU_IOHPMEVT_IDT;
	if (dmask)
		event_cfg |= RISCV_IOMMU_IOHPMEVT_DMASK;

	/* Write to the specific event register for this counter */
	riscv_iommu_hpm_writeq(hpm,
			       RISCV_IOMMU_REG_IOHPMEVT(idx), event_cfg);
}

static void riscv_iommu_hpm_apply_event_filter(struct riscv_iommu_hpm *hpm,
					       struct perf_event *event, int idx)
{
	u32 pid_pscid, did_gscid, pv_pscv, dv_gscv, idt, dmask;

	pid_pscid = get_filter_pid_pscid(event);
	did_gscid = get_filter_did_gscid(event);
	pv_pscv = get_filter_pv_pscv(event);
	dv_gscv = get_filter_dv_gscv(event);
	idt = get_filter_idt(event);
	dmask = get_filter_dmask(event);

	riscv_iommu_hpm_set_event_filter(event, idx, pid_pscid, did_gscid,
					 pv_pscv, dv_gscv, idt, dmask);
}

static int riscv_iommu_hpm_get_event_idx(struct riscv_iommu_hpm *hpm,
					 struct perf_event *event)
{
	int idx;
	unsigned int num_ctrs = hpm->num_counters;
	u16 event_id = get_event(event);

	/* Handle cycles event specially */
	if (event_id == RISCV_IOMMU_HPMEVENT_CYCLES) {
		/* Check if cycles counter is already in use */
		if (test_and_set_bit(RISCV_IOMMU_HPMCOUNTER_CYCLES,
				     hpm->used_counters)) {
			dev_dbg(hpm->pmu.dev,
				"Cycles counter already in use\n");
			return -EAGAIN;
		}
		return RISCV_IOMMU_HPMCOUNTER_CYCLES;
	}

	idx = find_first_zero_bit(hpm->used_counters, num_ctrs - 1);
	if (idx == num_ctrs - 1) {
		dev_dbg(hpm->pmu.dev, "All counters already in use\n");
		return -EAGAIN;
	}

	riscv_iommu_hpm_apply_event_filter(hpm, event, idx);
	set_bit(idx, hpm->used_counters);

	return idx;
}

/**
 * riscv_iommu_hpm_event_add() - Add a RISC-V IOMMU HPM event
 *
 * @event - IOMMU performance event
 * @flags - Performance event flags
 *
 * This function can be used to implement the .add() interface of pmu.
 */
static int riscv_iommu_hpm_event_add(struct perf_event *event, int flags)
{
	struct riscv_iommu_hpm *hpm = to_iommu_hpm(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	int idx;

	idx = riscv_iommu_hpm_get_event_idx(hpm, event);
	if (idx < 0)
		return idx;

	hwc->idx = idx;
	if (idx == RISCV_IOMMU_HPMCOUNTER_CYCLES)
		hpm->events[0] = event;
	else
		hpm->events[idx + 1] = event;

	hwc->state = PERF_HES_UPTODATE | PERF_HES_STOPPED;
	if (flags & PERF_EF_START)
		riscv_iommu_hpm_event_start(event, flags);
	perf_event_update_userpage(event);

	return 0;
}

/**
 * riscv_iommu_hpm_event_del() - Delete a RISC-V IOMMU HPM event
 *
 * @event: IOMMU performance event
 * @flags: Performance event flags
 *
 * This function can be used to implement the .del() interface of pmu.
 */
static void riscv_iommu_hpm_event_del(struct perf_event *event, int flags)
{
	struct riscv_iommu_hpm *hpm = to_iommu_hpm(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	u32 idx = hwc->idx;

	riscv_iommu_hpm_event_stop(event, flags | PERF_EF_UPDATE);

	/* Clear the used counter bit and event array entry */
	if (idx == RISCV_IOMMU_HPMCOUNTER_CYCLES) {
		clear_bit(RISCV_IOMMU_HPMCOUNTER_CYCLES,
			  hpm->used_counters);
		hpm->events[0] = NULL;
	} else {
		clear_bit(idx, hpm->used_counters);
		hpm->events[idx + 1] = NULL;
	}

	perf_event_update_userpage(event);
}

/**
 * riscv_iommu_hpm_event_init() - Initialize HPM event attributes
 *
 * @event: IOMMU performance event
 *
 * This function can be used to implement the .event_init() interface of
 * pmu.
 */
static int riscv_iommu_hpm_event_init(struct perf_event *event)
{
	struct riscv_iommu_hpm *hpm = to_iommu_hpm(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	struct perf_event *sibling;
	int group_num_events = 1;
	u16 event_id;

	if (event->attr.type != event->pmu->type)
		return -ENOENT;
	if (hwc->sample_period)
		return -EINVAL;
	if (event->cpu < 0)
		return -EINVAL;

	event_id = get_event(event);
	if (event_id >= RISCV_IOMMU_HPMEVENT_MAX ||
	    !test_bit(event_id, hpm->supported_events)) {
		dev_dbg(hpm->pmu.dev, "Invalid event %d for this HPM\n",
			event_id);
		return -EINVAL;
	}

	if (!is_software_event(event->group_leader)) {
		if (++group_num_events > hpm->num_counters)
			return -EINVAL;
	}

	for_each_sibling_event(sibling, event->group_leader) {
		if (is_software_event(sibling))
			continue;
		if (++group_num_events > hpm->num_counters)
			return -EINVAL;
	}

	event->cpu = hpm->on_cpu;
	hwc->idx = -1;

	return 0;
}

static ssize_t riscv_iommu_hpm_cpumask_show(struct device *dev,
					    struct device_attribute *attr,
					    char *buf)
{
	struct riscv_iommu_hpm *hpm = dev_get_drvdata(dev);

	return cpumap_print_to_pagebuf(true, buf, cpumask_of(hpm->on_cpu));
}

static struct device_attribute riscv_iommu_hpm_cpumask_attr =
	__ATTR(cpumask, 0444, riscv_iommu_hpm_cpumask_show, NULL);

static struct attribute *riscv_iommu_hpm_cpumask_attrs[] = {
	&riscv_iommu_hpm_cpumask_attr.attr,
	NULL
};

static const struct attribute_group riscv_iommu_hpm_cpumask_group = {
	.attrs = riscv_iommu_hpm_cpumask_attrs,
};

#define IOMMU_HPM_EVENT_ATTR(name, config)		\
	PMU_EVENT_ATTR_ID(name, riscv_iommu_hpm_event_show, config)

static ssize_t riscv_iommu_hpm_event_show(struct device *dev,
					  struct device_attribute *attr,
					  char *page)
{
	struct perf_pmu_events_attr *hpm_attr;

	hpm_attr = container_of(attr, struct perf_pmu_events_attr, attr);
	return sysfs_emit(page, "event=0x%02llx\n", hpm_attr->id);
}

static struct attribute *riscv_iommu_hpm_events[] = {
	IOMMU_HPM_EVENT_ATTR(cycles, RISCV_IOMMU_HPMEVENT_CYCLES),
	IOMMU_HPM_EVENT_ATTR(untrans_rq, RISCV_IOMMU_HPMEVENT_URQ),
	IOMMU_HPM_EVENT_ATTR(trans_rq, RISCV_IOMMU_HPMEVENT_TRQ),
	IOMMU_HPM_EVENT_ATTR(ats_rq, RISCV_IOMMU_HPMEVENT_ATS_RQ),
	IOMMU_HPM_EVENT_ATTR(tlb_mis, RISCV_IOMMU_HPMEVENT_TLB_MISS),
	IOMMU_HPM_EVENT_ATTR(dd_walk, RISCV_IOMMU_HPMEVENT_DD_WALK),
	IOMMU_HPM_EVENT_ATTR(pd_walk, RISCV_IOMMU_HPMEVENT_PD_WALK),
	IOMMU_HPM_EVENT_ATTR(s_walk, RISCV_IOMMU_HPMEVENT_S_VS_WALKS),
	IOMMU_HPM_EVENT_ATTR(g_walk, RISCV_IOMMU_HPMEVENT_G_WALKS),
	NULL
};

static umode_t riscv_iommu_hpm_event_is_visible(struct kobject *kobj,
						struct attribute *attr,
						int unused)
{
	struct device *dev = kobj_to_dev(kobj);
	struct riscv_iommu_hpm *hpm = dev_get_drvdata(dev);
	struct perf_pmu_events_attr *hpm_attr;

	hpm_attr = container_of(attr, struct perf_pmu_events_attr, attr.attr);
	if (test_bit(hpm_attr->id, hpm->supported_events))
		return attr->mode;

	return 0;
}

static const struct attribute_group riscv_iommu_hpm_events_group = {
	.name = "events",
	.attrs = riscv_iommu_hpm_events,
	.is_visible = riscv_iommu_hpm_event_is_visible,
};

PMU_FORMAT_ATTR(event, "config:0-14");
PMU_FORMAT_ATTR(filter_pid_pscid, "config1:16-35");
PMU_FORMAT_ATTR(filter_did_gscid, "config1:36-59");
PMU_FORMAT_ATTR(filter_pv_pscv, "config1:60");
PMU_FORMAT_ATTR(filter_dv_gscv, "config1:61");
PMU_FORMAT_ATTR(filter_idt, "config1:62");
PMU_FORMAT_ATTR(filter_dmask, "config1:15");

static struct attribute *riscv_iommu_hpm_formats[] = {
	&format_attr_event.attr,
	&format_attr_filter_pid_pscid.attr,
	&format_attr_filter_did_gscid.attr,
	&format_attr_filter_pv_pscv.attr,
	&format_attr_filter_dv_gscv.attr,
	&format_attr_filter_idt.attr,
	&format_attr_filter_dmask.attr,
	NULL
};

static const struct attribute_group riscv_iommu_hpm_format_group = {
	.name = "format",
	.attrs = riscv_iommu_hpm_formats,
};

static const struct attribute_group *riscv_iommu_hpm_attr_grps[] = {
	&riscv_iommu_hpm_cpumask_group,
	&riscv_iommu_hpm_events_group,
	&riscv_iommu_hpm_format_group,
	NULL
};

static irqreturn_t riscv_iommu_hpm_handle_irq(int irq_num, void *data)
{
	struct riscv_iommu_hpm *hpm = data;
	struct perf_event *event;
	int idx;
	u32 ovf;
	DECLARE_BITMAP(ovs, 32);

	if (!riscv_iommu_pmip_status(hpm->subdev))
		return IRQ_NONE;

	ovf = riscv_iommu_hpm_readl(hpm, RISCV_IOMMU_REG_IOCOUNTOVF);
	if (!ovf)
		return IRQ_HANDLED;

	/* Handle cycles counter overflow (always stored at index 0) */
	if (ovf & RISCV_IOMMU_IOCOUNTOVF_CY) {
		event = hpm->events[0];
		if (event && event->hw.idx == RISCV_IOMMU_HPMCOUNTER_CYCLES) {
			riscv_iommu_hpm_cycles_clear_ovf(hpm);
			riscv_iommu_hpm_event_update(event);
			riscv_iommu_hpm_set_period(hpm, &event->hw);
		}
	}

	/*
	 * Handle regular HPM counter overflows.
	 * IOCOUNTOVF bit mapping:
	 *   bit 0: cycles (already handled above)
	 *   bit 1: counter 0 -> events[1]
	 *   bit 2: counter 1 -> events[2]
	 *   ...
	 *   bit N: counter N-1 -> events[N]
	 * We need to check bits [1..num_counters] and skip bit 0.
	 */
	bitmap_from_u64(ovs, ovf);
	for_each_set_bit(idx, ovs, hpm->num_counters) {
		/* Skip bit 0 (cycles counter, already handled) */
		if (idx == 0)
			continue;

		/* IOCOUNTOVF bit N corresponds to counter N-1, stored in
		 * events[N]
		 */
		event = hpm->events[idx];
		if (WARN_ON_ONCE(!event))
			continue;

		dev_dbg(&hpm->subdev->auxdev.dev, "counter overflow: hw_idx=%d, counter=%d\n",
			idx, idx - 1);
		riscv_iommu_hpm_counter_clear_ovf(hpm, idx - 1);
		riscv_iommu_hpm_event_update(event);
		riscv_iommu_hpm_set_period(hpm, &event->hw);
	}

	riscv_iommu_hpm_interrupt_clear(hpm);

	return IRQ_HANDLED;
}

static int riscv_iommu_hpm_offline_cpu(unsigned int cpu,
				       struct hlist_node *node)
{
	struct riscv_iommu_hpm *hpm;
	unsigned int target;

	hpm = hlist_entry_safe(node, struct riscv_iommu_hpm, node);
	if (cpu != hpm->on_cpu)
		return 0;

	if (!hpm->irq)
		return 0;

	target = cpumask_any_but(cpu_online_mask, cpu);
	if (target >= nr_cpu_ids)
		return 0;

	perf_pmu_migrate_context(&hpm->pmu, cpu, target);
	hpm->on_cpu = target;
	if (hpm->irq > 0)
		WARN_ON(irq_set_affinity(hpm->irq, cpumask_of(target)));

	return 0;
}

/* Protected by riscv_iommu_hpm_lock. This block is self-contained; any
 * modifications to cpuhp handling must preserve mutex serialization around
 * cpuhp_state_num and the cpuhp_state_*() calls.
 */
static int riscv_iommu_hpm_cpuhp_add(struct hlist_node *node)
{
	int err = 0;

	mutex_lock(&riscv_iommu_hpm_lock);
	if (cpuhp_state_num < 0) {
		cpuhp_state_num = cpuhp_setup_state_multi(CPUHP_AP_ONLINE_DYN,
							  "perf/riscv/iommu:online",
							  NULL,
							  riscv_iommu_hpm_offline_cpu);
		if (cpuhp_state_num < 0) {
			err = -EINVAL;
			goto unlock;
		}
	}
	err = cpuhp_state_add_instance_nocalls(cpuhp_state_num, node);
unlock:
	mutex_unlock(&riscv_iommu_hpm_lock);
	return err;
}

static void riscv_iommu_hpm_cpuhp_remove(struct hlist_node *node)
{
	mutex_lock(&riscv_iommu_hpm_lock);
	if (cpuhp_state_num >= 0)
		cpuhp_state_remove_instance_nocalls(cpuhp_state_num, node);
	mutex_unlock(&riscv_iommu_hpm_lock);
}

static void riscv_iommu_hpm_reset(struct riscv_iommu_hpm *hpm)
{
	u64 counter_present_mask = (1ULL << hpm->num_counters) - 1;

	/* Disable all counters */
	riscv_iommu_hpm_writel(hpm, RISCV_IOMMU_REG_IOCOUNTINH,
			       counter_present_mask);
	/* Clear interrupt pending status */
	riscv_iommu_hpm_interrupt_clear(hpm);
}

static void riscv_iommu_hpm_set_standard_events(struct riscv_iommu_hpm *hpm)
{
	/* Cycles counter is always supported */
	set_bit(RISCV_IOMMU_HPMEVENT_CYCLES, hpm->supported_events);

	/* Standard RISC-V IOMMU HPM events */
	set_bit(RISCV_IOMMU_HPMEVENT_URQ, hpm->supported_events);
	set_bit(RISCV_IOMMU_HPMEVENT_TRQ, hpm->supported_events);
	set_bit(RISCV_IOMMU_HPMEVENT_ATS_RQ, hpm->supported_events);
	set_bit(RISCV_IOMMU_HPMEVENT_TLB_MISS, hpm->supported_events);
	set_bit(RISCV_IOMMU_HPMEVENT_DD_WALK, hpm->supported_events);
	set_bit(RISCV_IOMMU_HPMEVENT_PD_WALK, hpm->supported_events);
	set_bit(RISCV_IOMMU_HPMEVENT_S_VS_WALKS, hpm->supported_events);
	set_bit(RISCV_IOMMU_HPMEVENT_G_WALKS, hpm->supported_events);
}

static int riscv_iommu_hpm_probe(struct auxiliary_device *auxdev,
				 const struct auxiliary_device_id *id)
{
	struct riscv_iommu_subdev *subdev;
	struct riscv_iommu_hpm *hpm;
	struct device *dev = &auxdev->dev;
	struct riscv_iommu_hpm_info *info;
	const char *hpm_name;
	u32 val;
	int err;

	subdev = riscv_iommu_get_subdev(dev);
	if (!subdev) {
		dev_err(dev, "No auxiliary device data\n");
		return -ENODEV;
	}

	info = subdev->info;
	if (!info || info->irq <= 0) {
		dev_err(dev, "HPM: No IRQ available\n");
		return -EINVAL;
	}

	hpm = devm_kzalloc(dev, sizeof(*hpm), GFP_KERNEL);
	if (!hpm)
		return -ENOMEM;

	hpm->subdev = subdev;
	hpm->base = subdev->base;
	hpm->on_cpu = raw_smp_processor_id();
	hpm->irq = info->irq;

	bitmap_zero(hpm->used_counters, RISCV_IOMMU_HPMCOUNTER_MAX);
	bitmap_zero(hpm->supported_events, RISCV_IOMMU_HPMEVENT_MAX);

	riscv_iommu_hpm_writel(hpm, RISCV_IOMMU_REG_IOCOUNTINH, 0xFFFFFFFF);
	val = riscv_iommu_hpm_readl(hpm, RISCV_IOMMU_REG_IOCOUNTINH);
	hpm->num_counters = hweight32(val & RISCV_IOMMU_IOCOUNTINH_HPM);
	if (!hpm->num_counters)
		return -ENODEV;

	riscv_iommu_hpm_reset(hpm);
	riscv_iommu_hpm_set_standard_events(hpm);

	hpm_name = devm_kstrdup(dev, dev_name(dev), GFP_KERNEL);
	if (!hpm_name)
		return -ENOMEM;

	err = devm_request_threaded_irq(dev, hpm->irq, NULL,
					riscv_iommu_hpm_handle_irq,
					IRQF_SHARED | IRQF_ONESHOT,
					hpm_name, hpm);
	if (err)
		return err;
	WARN_ON(irq_set_affinity(hpm->irq, cpumask_of(hpm->on_cpu)));

	hpm->pmu = (struct pmu) {
		.name = hpm_name,
		.module = THIS_MODULE,
		.task_ctx_nr = perf_invalid_context,
		.event_init = riscv_iommu_hpm_event_init,
		.add = riscv_iommu_hpm_event_add,
		.del = riscv_iommu_hpm_event_del,
		.start = riscv_iommu_hpm_event_start,
		.stop = riscv_iommu_hpm_event_stop,
		.read = riscv_iommu_hpm_event_update,
		.attr_groups = riscv_iommu_hpm_attr_grps,
		.capabilities = PERF_PMU_CAP_NO_EXCLUDE,
	};

	err = perf_pmu_register(&hpm->pmu, hpm_name, -1);
	if (err) {
		dev_err(dev, "HPM: Failed to register PMU\n");
		return err;
	}

	dev_set_drvdata(dev, hpm);

	err = riscv_iommu_hpm_cpuhp_add(&hpm->node);
	if (err) {
		perf_pmu_unregister(&hpm->pmu);
		return err;
	}

	auxiliary_set_drvdata(auxdev, hpm);

	dev_info(dev, "HPM: Registered %s (%d counters, IRQ %d)\n",
		 hpm_name, hpm->num_counters, hpm->irq);

	return 0;
}

static void riscv_iommu_hpm_remove(struct auxiliary_device *auxdev)
{
	struct riscv_iommu_hpm *hpm = auxiliary_get_drvdata(auxdev);

	riscv_iommu_hpm_cpuhp_remove(&hpm->node);
	perf_pmu_unregister(&hpm->pmu);
}

static const struct auxiliary_device_id riscv_iommu_hpm_ids[] = {
	{ .name = "iommu.riscv_iommu_hpm" },
	{}
};
MODULE_DEVICE_TABLE(auxiliary, riscv_iommu_hpm_ids);

static struct auxiliary_driver riscv_iommu_hpm_driver = {
	.name = "riscv_iommu_hpm",
	.id_table = riscv_iommu_hpm_ids,
	.probe = riscv_iommu_hpm_probe,
	.remove = riscv_iommu_hpm_remove,
};

module_auxiliary_driver(riscv_iommu_hpm_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RISC-V IOMMU Hardware Performance Monitor");
