// SPDX-License-Identifier: GPL-2.0-only
/*
 * iommu-hpm.c: RISC-V IOMMU Hardware Performance Monitor driver
 *
 *  Copyright (C) 2026 SpacemiT Technologies Inc.
 *    Author: 2026 Jingyu Li <joey.li@spacemit.com>
 *                 Lv Zheng <lv.zheng@spacemit.com>
 */

#include "iommu.h"

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

static DEFINE_MUTEX(riscv_iommu_hpm_lock);
static atomic_t riscv_iommu_hpm_ids = ATOMIC_INIT(0);
static int cpuhp_state_num = -1;
static int cpuhp_refcnt;

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
	riscv_iommu_hpm_writel(hpm, RISCV_IOMMU_REG_IPSR, RISCV_IOMMU_IPSR_PMIP);
}

static bool riscv_iommu_hpm_check_global_filter(struct perf_event *curr,
						struct perf_event *new)
{
	return get_filter_pid_pscid(curr) == get_filter_pid_pscid(new) &&
	       get_filter_did_gscid(curr) == get_filter_did_gscid(new) &&
	       get_filter_pv_pscv(curr) == get_filter_pv_pscv(new) &&
	       get_filter_dv_gscv(curr) == get_filter_dv_gscv(new) &&
	       get_filter_idt(curr) == get_filter_idt(new) &&
	       get_filter_dmask(curr) == get_filter_dmask(new);
}

static bool riscv_iommu_hpm_events_compatible(struct perf_event *curr,
					      struct perf_event *new)
{
	if (new->pmu != curr->pmu)
		return false;

	if (to_iommu_hpm(new->pmu)->global_filter &&
	    !riscv_iommu_hpm_check_global_filter(curr, new))
		return false;

	return true;
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
	struct riscv_iommu_hpm *iommu_hpm = to_iommu_hpm(event->pmu);
	u64 delta, prev, now;
	u32 idx = hwc->idx;

	do {
		prev = local64_read(&hwc->prev_count);
		if (idx == RISCV_IOMMU_HPMCOUNTER_CYCLES)
			now = riscv_iommu_hpm_cycles_get_value(iommu_hpm);
		else
			now = riscv_iommu_hpm_counter_get_value(iommu_hpm, idx);
	} while (local64_cmpxchg(&hwc->prev_count, prev, now) != prev);

	delta = now - prev;
	if (idx == RISCV_IOMMU_HPMCOUNTER_CYCLES)
		delta &= RISCV_IOMMU_IOHPMCYCLES_COUNTER;
	else
		delta &= RISCV_IOMMU_IOHPMEVENT_COUNTER;

	local64_add(delta, &event->count);
}

static void riscv_iommu_hpm_set_period(struct riscv_iommu_hpm *iommu_hpm,
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
		riscv_iommu_hpm_cycles_set_value(iommu_hpm, new);
	else
		riscv_iommu_hpm_counter_set_value(iommu_hpm, idx, new);

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
	struct riscv_iommu_hpm *iommu_hpm = to_iommu_hpm(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	u32 idx = hwc->idx;

	hwc->state = 0;
	riscv_iommu_hpm_set_period(iommu_hpm, hwc);

	if (idx == RISCV_IOMMU_HPMCOUNTER_CYCLES)
		riscv_iommu_hpm_cycles_enable(iommu_hpm);
	else
		riscv_iommu_hpm_counter_enable(iommu_hpm, idx);
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
	struct riscv_iommu_hpm *iommu_hpm = to_iommu_hpm(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	u32 idx = hwc->idx;

	if (hwc->state & PERF_HES_STOPPED)
		return;

	if (idx == RISCV_IOMMU_HPMCOUNTER_CYCLES)
		riscv_iommu_hpm_cycles_disable(iommu_hpm);
	else
		riscv_iommu_hpm_counter_disable(iommu_hpm, idx);

	if (flags & PERF_EF_UPDATE)
		riscv_iommu_hpm_event_update(event);
	hwc->state |= PERF_HES_STOPPED | PERF_HES_UPTODATE;
}

static void riscv_iommu_hpm_set_event_filter(struct perf_event *event, int idx,
					     u32 pid_pscid, u32 did_gscid,
					     u32 pv_pscv,
					     u32 dv_gscv, u32 idt, u32 dmask)
{
	struct riscv_iommu_hpm *iommu_hpm = to_iommu_hpm(event->pmu);
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
	riscv_iommu_hpm_writeq(iommu_hpm,
			       RISCV_IOMMU_REG_IOHPMEVT(idx), event_cfg);
}

static int riscv_iommu_hpm_apply_event_filter(struct riscv_iommu_hpm *iommu_hpm,
					      struct perf_event *event, int idx)
{
	unsigned int cur_idx, num_ctrs = iommu_hpm->num_counters;
	u32 pid_pscid, did_gscid, pv_pscv, dv_gscv, idt, dmask;

	pid_pscid = get_filter_pid_pscid(event);
	did_gscid = get_filter_did_gscid(event);
	pv_pscv = get_filter_pv_pscv(event);
	dv_gscv = get_filter_dv_gscv(event);
	idt = get_filter_idt(event);
	dmask = get_filter_dmask(event);

	if (iommu_hpm->global_filter) {
		cur_idx = find_first_bit(iommu_hpm->used_counters, num_ctrs - 1);
		if (cur_idx == num_ctrs - 1) {
			/* First event, set the global filter */
			riscv_iommu_hpm_set_event_filter(event, 0, pid_pscid,
							 did_gscid,
							 pv_pscv, dv_gscv, idt, dmask);
		} else {
			/* Check if the new event's filter is compatible with
			 * the global filter
			 */
			if (!riscv_iommu_hpm_check_global_filter(iommu_hpm->events[cur_idx + 1],
								 event)) {
				dev_dbg(iommu_hpm->pmu.dev,
					"HPM: Filter incompatible with global filter\n");
				return -EAGAIN;
			}
		}
		return 0;
	}

	riscv_iommu_hpm_set_event_filter(event, idx, pid_pscid, did_gscid,
					 pv_pscv, dv_gscv, idt, dmask);
	return 0;
}

static int riscv_iommu_hpm_get_event_idx(struct riscv_iommu_hpm *iommu_hpm,
					 struct perf_event *event)
{
	int idx, err;
	unsigned int num_ctrs = iommu_hpm->num_counters;
	u16 event_id = get_event(event);

	/* Handle cycles event specially */
	if (event_id == RISCV_IOMMU_HPMEVENT_CYCLES) {
		/* Check if cycles counter is already in use */
		if (test_and_set_bit(RISCV_IOMMU_HPMCOUNTER_CYCLES,
				     iommu_hpm->used_counters)) {
			dev_dbg(iommu_hpm->pmu.dev,
				"Cycles counter already in use\n");
			return -EAGAIN;
		}
		return RISCV_IOMMU_HPMCOUNTER_CYCLES;
	}

	idx = find_first_zero_bit(iommu_hpm->used_counters, num_ctrs - 1);
	if (idx == num_ctrs - 1) {
		dev_dbg(iommu_hpm->pmu.dev, "All counters already in use\n");
		return -EAGAIN;
	}

	err = riscv_iommu_hpm_apply_event_filter(iommu_hpm, event, idx);
	if (err)
		return err;
	set_bit(idx, iommu_hpm->used_counters);

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
	struct riscv_iommu_hpm *iommu_hpm = to_iommu_hpm(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	int idx;

	idx = riscv_iommu_hpm_get_event_idx(iommu_hpm, event);
	hwc->idx = idx;
	if (idx == RISCV_IOMMU_HPMCOUNTER_CYCLES)
		iommu_hpm->events[0] = event;
	else
		iommu_hpm->events[idx + 1] = event;

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
	struct riscv_iommu_hpm *iommu_hpm = to_iommu_hpm(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	u32 idx = hwc->idx;

	riscv_iommu_hpm_event_stop(event, flags | PERF_EF_UPDATE);

	/* Clear the used counter bit and event array entry */
	if (idx == RISCV_IOMMU_HPMCOUNTER_CYCLES) {
		clear_bit(RISCV_IOMMU_HPMCOUNTER_CYCLES,
			  iommu_hpm->used_counters);
		iommu_hpm->events[0] = NULL;
	} else {
		clear_bit(idx, iommu_hpm->used_counters);
		iommu_hpm->events[idx + 1] = NULL;
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
	struct riscv_iommu_hpm *iommu_hpm = to_iommu_hpm(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	struct perf_event *sibling;
	int group_num_events = 1;
	u16 event_id;

	if (event->attr.type != event->pmu->type)
		return -ENOENT;
	if (hwc->sample_period) {
		dev_dbg(iommu_hpm->pmu.dev, "Sampling not supported\n");
		return -EOPNOTSUPP;
	}
	if (event->cpu < 0) {
		dev_dbg(iommu_hpm->pmu.dev, "Per-task mode not supported\n");
		return -EOPNOTSUPP;
	}

	event_id = get_event(event);
	if (event_id >= RISCV_IOMMU_HPMEVENT_MAX ||
	    !test_bit(event_id, iommu_hpm->supported_events)) {
		dev_dbg(iommu_hpm->pmu.dev, "Invalid event %d for this PMU\n",
			event_id);
		return -EINVAL;
	}

	if (!is_software_event(event->group_leader)) {
		if (!riscv_iommu_hpm_events_compatible(event->group_leader, event))
			return -EINVAL;
		if (++group_num_events > iommu_hpm->num_counters)
			return -EINVAL;
	}

	for_each_sibling_event(sibling, event->group_leader) {
		if (is_software_event(sibling))
			continue;
		if (!riscv_iommu_hpm_events_compatible(sibling, event))
			return -EINVAL;
		if (++group_num_events > iommu_hpm->num_counters)
			return -EINVAL;
	}

	event->cpu = iommu_hpm->on_cpu;
	hwc->idx = -1;

	return 0;
}

static ssize_t riscv_iommu_hpm_cpumask_show(struct device *dev,
					    struct device_attribute *attr,
					    char *buf)
{
	struct riscv_iommu_hpm *iommu_hpm = to_iommu_hpm(dev_get_drvdata(dev));

	return cpumap_print_to_pagebuf(true, buf, cpumask_of(iommu_hpm->on_cpu));
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

static ssize_t riscv_iommu_hpm_identifier_show(struct device *dev,
					       struct device_attribute *attr,
					       char *buf)
{
	struct riscv_iommu_hpm *iommu_hpm = to_iommu_hpm(dev_get_drvdata(dev));

	if (!iommu_hpm->identifier)
		return 0;

	return sysfs_emit(buf, "%s\n", iommu_hpm->identifier);
}

static struct device_attribute riscv_iommu_hpm_identifier_attr =
	__ATTR(identifier, 0444, riscv_iommu_hpm_identifier_show, NULL);

static struct attribute *riscv_iommu_hpm_identifier_attrs[] = {
	&riscv_iommu_hpm_identifier_attr.attr,
	NULL
};

static const struct attribute_group riscv_iommu_hpm_identifier_group = {
	.attrs = riscv_iommu_hpm_identifier_attrs,
};

#define IOMMU_HPM_EVENT_ATTR(name, config)		\
	PMU_EVENT_ATTR_ID(name, riscv_iommu_hpm_event_show, config)

static ssize_t riscv_iommu_hpm_event_show(struct device *dev,
					  struct device_attribute *attr,
					  char *page)
{
	struct perf_pmu_events_attr *pmu_attr;

	pmu_attr = container_of(attr, struct perf_pmu_events_attr, attr);
	return sysfs_emit(page, "event=0x%02llx\n", pmu_attr->id);
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
	struct riscv_iommu_hpm *iommu_hpm = to_iommu_hpm(dev_get_drvdata(dev));
	struct perf_pmu_events_attr *pmu_attr;

	pmu_attr = container_of(attr, struct perf_pmu_events_attr, attr.attr);
	if (test_bit(pmu_attr->id, iommu_hpm->supported_events))
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
	&riscv_iommu_hpm_identifier_group,
	NULL
};

static irqreturn_t riscv_iommu_hpm_handle_irq(int irq_num, void *data)
{
	struct riscv_iommu_hpm *iommu_hpm = data;
	struct riscv_iommu_device *iommu = iommu_hpm->iommu;
	struct perf_event *event;
	u32 val;
	int idx;
	u32 ovf;
	DECLARE_BITMAP(ovs, 32);

	val = riscv_iommu_hpm_readl(iommu_hpm, RISCV_IOMMU_REG_IPSR);
	if (!(val & RISCV_IOMMU_IPSR_PMIP))
		return IRQ_NONE;

	ovf = riscv_iommu_hpm_readl(iommu_hpm, RISCV_IOMMU_REG_IOCOUNTOVF);
	if (!ovf)
		return IRQ_HANDLED;

	/* Handle cycles counter overflow (always stored at index 0) */
	if (ovf & RISCV_IOMMU_IOCOUNTOVF_CY) {
		event = iommu_hpm->events[0];
		if (event && event->hw.idx == RISCV_IOMMU_HPMCOUNTER_CYCLES) {
			riscv_iommu_hpm_cycles_clear_ovf(iommu_hpm);
			riscv_iommu_hpm_event_update(event);
			riscv_iommu_hpm_set_period(iommu_hpm, &event->hw);
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
	for_each_set_bit(idx, ovs, iommu_hpm->num_counters) {
		/* Skip bit 0 (cycles counter, already handled) */
		if (idx == 0)
			continue;

		/* IOCOUNTOVF bit N corresponds to counter N-1, stored in
		 * events[N]
		 */
		event = iommu_hpm->events[idx];
		if (WARN_ON_ONCE(!event))
			continue;

		dev_dbg(iommu->dev, "counter overflow: hw_idx=%d, counter=%d\n",
			idx, idx - 1);
		riscv_iommu_hpm_counter_clear_ovf(iommu_hpm, idx - 1);
		riscv_iommu_hpm_event_update(event);
		riscv_iommu_hpm_set_period(iommu_hpm, &event->hw);
	}

	riscv_iommu_hpm_interrupt_clear(iommu_hpm);

	return IRQ_HANDLED;
}

static int riscv_iommu_hpm_offline_cpu(unsigned int cpu,
				       struct hlist_node *node)
{
	struct riscv_iommu_hpm *iommu_hpm;
	unsigned int target;

	iommu_hpm = hlist_entry_safe(node, struct riscv_iommu_hpm, node);
	if (cpu != iommu_hpm->on_cpu)
		return 0;

	if (!iommu_hpm->irq)
		return 0;

	target = cpumask_any_but(cpu_online_mask, cpu);
	if (target >= nr_cpu_ids)
		return 0;

	perf_pmu_migrate_context(&iommu_hpm->pmu, cpu, target);
	iommu_hpm->on_cpu = target;
	if (iommu_hpm->irq > 0)
		WARN_ON(irq_set_affinity(iommu_hpm->irq, cpumask_of(target)));

	return 0;
}

static void riscv_iommu_hpm_reset(struct riscv_iommu_hpm *iommu_hpm)
{
	u64 counter_present_mask = (1ULL << iommu_hpm->num_counters) - 1;

	/* Disable all counters */
	riscv_iommu_hpm_writel(iommu_hpm, RISCV_IOMMU_REG_IOCOUNTINH,
			       counter_present_mask);
	/* Clear interrupt pending status */
	riscv_iommu_hpm_interrupt_clear(iommu_hpm);
}

static bool riscv_iommu_hpm_is_identifier_compat(const char *compat)
{
	return !strcmp(compat, "riscv,iommu");
}

static const char *riscv_iommu_hpm_get_identifier(struct device *dev)
{
	struct device_node *np = dev->of_node;
	const char *compat;
	int count, i;

	if (!np)
		return NULL;

	count = of_property_count_strings(np, "compatible");
	if (count <= 0)
		return NULL;

	for (i = 0; i < count; i++) {
		if (of_property_read_string_index(np, "compatible",
						  i, &compat))
			continue;

		if (riscv_iommu_hpm_is_identifier_compat(compat))
			return devm_kstrdup(dev, compat, GFP_KERNEL);
	}

	return NULL;
}

static void riscv_iommu_hpm_set_standard_events(struct riscv_iommu_hpm *iommu_hpm)
{
	/* Cycles counter is always supported */
	set_bit(RISCV_IOMMU_HPMEVENT_CYCLES, iommu_hpm->supported_events);

	/* Standard RISC-V IOMMU HPM events */
	set_bit(RISCV_IOMMU_HPMEVENT_URQ, iommu_hpm->supported_events);
	set_bit(RISCV_IOMMU_HPMEVENT_TRQ, iommu_hpm->supported_events);
	set_bit(RISCV_IOMMU_HPMEVENT_ATS_RQ, iommu_hpm->supported_events);
	set_bit(RISCV_IOMMU_HPMEVENT_TLB_MISS, iommu_hpm->supported_events);
	set_bit(RISCV_IOMMU_HPMEVENT_DD_WALK, iommu_hpm->supported_events);
	set_bit(RISCV_IOMMU_HPMEVENT_PD_WALK, iommu_hpm->supported_events);
	set_bit(RISCV_IOMMU_HPMEVENT_S_VS_WALKS, iommu_hpm->supported_events);
	set_bit(RISCV_IOMMU_HPMEVENT_G_WALKS, iommu_hpm->supported_events);
}

static void riscv_iommu_hpm_remove(void *data)
{
	struct riscv_iommu_hpm *iommu_hpm = data;

	riscv_iommu_remove_hpm(iommu_hpm->iommu);
}

static int riscv_iommu_hpm_register_unit(struct riscv_iommu_device *iommu,
					 struct riscv_iommu_hpm *iommu_hpm,
					 u32 offset, int irq,
					 const char *identifier,
					 const struct attribute_group **attr_groups,
					 const char *prefix)
{
	struct device *dev = iommu->dev;
	const char *pmu_name;
	u32 val;
	int err;
	int unique_id;
	void __iomem *base;

	unique_id = atomic_fetch_inc(&riscv_iommu_hpm_ids);
	memset(iommu_hpm, 0, sizeof(*iommu_hpm));
	iommu_hpm->iommu = iommu;
	iommu_hpm->identifier = identifier;

	if (offset + RISCV_IOMMU_REG_SIZE <= iommu->reg_size)
		base = iommu->reg + offset;
	else
		base = devm_ioremap(dev, iommu->reg_phys + offset,
				    RISCV_IOMMU_REG_SIZE);
	if (!base)
		return -ENOMEM;

	iommu_hpm->base = base;
	bitmap_zero(iommu_hpm->used_counters, RISCV_IOMMU_HPMCOUNTER_MAX);
	bitmap_zero(iommu_hpm->supported_events, RISCV_IOMMU_HPMEVENT_MAX);

	iommu_hpm->global_filter = of_device_is_compatible(dev->of_node,
							   "spacemit,t100");
	riscv_iommu_hpm_writel(iommu_hpm,
			       RISCV_IOMMU_REG_IOCOUNTINH, 0xFFFFFFFF);
	val = riscv_iommu_hpm_readl(iommu_hpm,
				    RISCV_IOMMU_REG_IOCOUNTINH);
	iommu_hpm->num_counters = hweight32(val & RISCV_IOMMU_IOCOUNTINH_HPM);
	if (!iommu_hpm->num_counters)
		return -ENODEV;

	iommu_hpm->on_cpu = raw_smp_processor_id();
	iommu_hpm->irq = irq;

	riscv_iommu_hpm_reset(iommu_hpm);

	riscv_iommu_hpm_set_standard_events(iommu_hpm);
	pmu_name = devm_kasprintf(dev, GFP_KERNEL, "%s_%02x",
				  prefix, (u8)unique_id);
	if (!pmu_name)
		return -ENOMEM;

	err = devm_request_threaded_irq(dev, iommu_hpm->irq, NULL,
					riscv_iommu_hpm_handle_irq,
					IRQF_SHARED | IRQF_ONESHOT,
					pmu_name, iommu_hpm);
	if (err)
		return err;
	WARN_ON(irq_set_affinity(iommu_hpm->irq,
				 cpumask_of(iommu_hpm->on_cpu)));

	iommu_hpm->pmu = (struct pmu) {
		.name = pmu_name,
		.module = THIS_MODULE,
		.task_ctx_nr = perf_invalid_context,
		.event_init = riscv_iommu_hpm_event_init,
		.add = riscv_iommu_hpm_event_add,
		.del = riscv_iommu_hpm_event_del,
		.start = riscv_iommu_hpm_event_start,
		.stop = riscv_iommu_hpm_event_stop,
		.read = riscv_iommu_hpm_event_update,
		.attr_groups = attr_groups,
		.capabilities = PERF_PMU_CAP_NO_EXCLUDE,
	};

	err = perf_pmu_register(&iommu_hpm->pmu, pmu_name, -1);
	if (err)
		goto err_exit;

	dev_set_drvdata(iommu_hpm->pmu.dev, &iommu_hpm->pmu);

	mutex_lock(&riscv_iommu_hpm_lock);
	err = cpuhp_state_add_instance_nocalls(cpuhp_state_num,
					       &iommu_hpm->node);
	if (err) {
		mutex_unlock(&riscv_iommu_hpm_lock);
		goto err_perf;
	}
	cpuhp_refcnt++;
	mutex_unlock(&riscv_iommu_hpm_lock);

	err = devm_add_action_or_reset(dev, riscv_iommu_hpm_remove,
				       iommu_hpm);
	if (err)
		goto err_cpuhp;

	dev_info(dev, "HPM: Registered %s (%d counters, IRQ %d, %s filter)\n",
		 pmu_name, iommu_hpm->num_counters, iommu_hpm->irq,
		 iommu_hpm->global_filter ? "global" : "per-counter");
	return 0;

err_cpuhp:
	mutex_lock(&riscv_iommu_hpm_lock);
	cpuhp_state_remove_instance_nocalls(cpuhp_state_num,
					    &iommu_hpm->node);
	mutex_unlock(&riscv_iommu_hpm_lock);
err_perf:
	perf_pmu_unregister(&iommu_hpm->pmu);
err_exit:
	return err;
}

static int riscv_iommu_hpm_init(void)
{
	int ret = 0;

	mutex_lock(&riscv_iommu_hpm_lock);
	if (cpuhp_state_num < 0) {
		cpuhp_state_num = cpuhp_setup_state_multi(CPUHP_AP_ONLINE_DYN,
							  "perf/riscv/iommu:online",
							  NULL,
							  riscv_iommu_hpm_offline_cpu);
		if (cpuhp_state_num < 0)
			ret = -EINVAL;
	}
	mutex_unlock(&riscv_iommu_hpm_lock);

	return ret;
}

static void riscv_iommu_hpm_exit(void)
{
	mutex_lock(&riscv_iommu_hpm_lock);
	cpuhp_remove_multi_state(cpuhp_state_num);
	cpuhp_state_num = -1;
	mutex_unlock(&riscv_iommu_hpm_lock);
}

/**
 * riscv_iommu_add_hpm() - Add HPM support for RISC-V IOMMU
 *
 * @iommu: IOMMU device instance
 *
 * This API can be invoked from RISC-V IOMMU driver to probe and
 * initialize the feature of HPM support.
 */
int riscv_iommu_add_hpm(struct riscv_iommu_device *iommu)
{
	struct device *dev = iommu->dev;
	const char *identifier;
	int irq, rc;

	if (!FIELD_GET(RISCV_IOMMU_CAPABILITIES_HPM, iommu->caps)) {
		dev_dbg(dev, "HPM: Not supported\n");
		return 0;
	}
	irq = iommu->irqs[FIELD_GET(RISCV_IOMMU_ICVEC_PMIV, iommu->icvec)];
	if (irq <= 0) {
		dev_err(dev, "HPM: No IRQ available (vector=%llu)\n",
			(unsigned long long)FIELD_GET(RISCV_IOMMU_ICVEC_PMIV,
						      iommu->icvec));
		return -EINVAL;
	}

	rc = riscv_iommu_hpm_init();
	if (rc < 0)
		return rc;

	identifier = riscv_iommu_hpm_get_identifier(dev);
	if (identifier)
		dev_info(dev, "HPM: Vendor identifier: %s\n", identifier);

	rc = riscv_iommu_hpm_register_unit(iommu, &iommu->hpm, 0, irq,
					   identifier,
					   riscv_iommu_hpm_attr_grps,
					   "riscv_iommu_hpm");
	if (rc < 0)
		goto err_module;
	return 0;

err_module:
	riscv_iommu_hpm_exit();
	return rc;
}

/**
 * riscv_iommu_remove_hpm() - Remove HPM support for RISC-V IOMMU.
 *
 * @iommu: IOMMU device instance
 *
 * This API can be invoked from RISC-V IOMMU driver to finalize the
 * feature of HPM support.
 */
void riscv_iommu_remove_hpm(struct riscv_iommu_device *iommu)
{
	mutex_lock(&riscv_iommu_hpm_lock);
	if (cpuhp_state_num >= 0) {
		cpuhp_refcnt--;
		cpuhp_state_remove_instance_nocalls(cpuhp_state_num,
						    &iommu->hpm.node);
	}
	mutex_unlock(&riscv_iommu_hpm_lock);
	perf_pmu_unregister(&iommu->hpm.pmu);
	riscv_iommu_hpm_exit();
}
