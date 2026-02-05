/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright © 2022-2024 Rivos Inc.
 * Copyright © 2023 FORTH-ICS/CARV
 *
 * Authors
 *	Tomasz Jeznach <tjeznach@rivosinc.com>
 *	Nick Kossifidis <mick@ics.forth.gr>
 */

#ifndef _RISCV_IOMMU_H_
#define _RISCV_IOMMU_H_

#include <linux/iommu.h>
#include <linux/types.h>
#include <linux/iopoll.h>
#include <linux/perf_event.h>

#include "iommu-bits.h"

struct riscv_iommu_device;

struct riscv_iommu_queue {
	atomic_t prod;				/* unbounded producer allocation index */
	atomic_t head;				/* unbounded shadow ring buffer consumer index */
	atomic_t tail;				/* unbounded shadow ring buffer producer index */
	unsigned int mask;			/* index mask, queue length - 1 */
	unsigned int irq;			/* allocated interrupt number */
	struct riscv_iommu_device *iommu;	/* iommu device handling the queue when active */
	void *base;				/* ring buffer kernel pointer */
	dma_addr_t phys;			/* ring buffer physical address */
	u16 qbr;				/* base register offset, head and tail reference */
	u16 qcr;				/* control and status register offset */
	u8 qid;					/* queue identifier, same as RISCV_IOMMU_INTR_XX */
};

struct riscv_iommu_hpm {
	struct riscv_iommu_device *iommu;
	struct pmu pmu;
	void __iomem *base;
	int irq;
	int on_cpu;
	struct hlist_node node;
	/*
	 * Layout of events:
	 * 0       -> HPMCYCLES
	 * 1...n-1 -> HPMEVENTS
	 */
	struct perf_event *events[RISCV_IOMMU_HPMCOUNTER_MAX];
	DECLARE_BITMAP(supported_events, RISCV_IOMMU_HPMCOUNTER_MAX);
	/*
	 * Layout of counters:
	 * 0...min(MAX,n)-2 -> HPMEVENTS
	 * MAX-1            -> HPMCYCLES
	 */
	DECLARE_BITMAP(used_counters, RISCV_IOMMU_HPMCOUNTER_MAX);
	unsigned int num_counters;
};

struct riscv_iommu_device {
	/* iommu core interface */
	struct iommu_device iommu;

	/* iommu hardware */
	struct device *dev;

	/* hardware control register space */
	void __iomem *reg;
	phys_addr_t reg_phys;
	resource_size_t reg_size;

	/* supported and enabled hardware capabilities */
	u64 caps;
	u32 fctl;

	/* available interrupt numbers, MSI or WSI */
	unsigned int irqs[RISCV_IOMMU_INTR_COUNT];
	unsigned int irqs_count;
	unsigned int icvec;

	/* hardware queues */
	struct riscv_iommu_queue cmdq;
	struct riscv_iommu_queue fltq;

	/* device directory */
	unsigned int ddt_mode;
	dma_addr_t ddt_phys;
	u64 *ddt_root;

	struct riscv_iommu_hpm hpm;
};

int riscv_iommu_init(struct riscv_iommu_device *iommu);
void riscv_iommu_remove(struct riscv_iommu_device *iommu);
void riscv_iommu_disable(struct riscv_iommu_device *iommu);

#ifdef CONFIG_RISCV_IOMMU_HPM
int riscv_iommu_add_hpm(struct riscv_iommu_device *iommu);
void riscv_iommu_remove_hpm(struct riscv_iommu_device *iommu);
#else
static inline int riscv_iommu_add_hpm(struct riscv_iommu_device *iommu)
{
	return -ENODEV;
}

static inline void riscv_iommu_remove_hpm(struct riscv_iommu_device *iommu)
{
}
#endif

#define riscv_iommu_readl(iommu, addr) \
	readl_relaxed((iommu)->reg + (addr))

#define riscv_iommu_readq(iommu, addr) \
	readq_relaxed((iommu)->reg + (addr))

#define riscv_iommu_writel(iommu, addr, val) \
	writel_relaxed((val), (iommu)->reg + (addr))

#define riscv_iommu_writeq(iommu, addr, val) \
	writeq_relaxed((val), (iommu)->reg + (addr))

#define riscv_iommu_readq_timeout(iommu, addr, val, cond, delay_us, timeout_us) \
	readx_poll_timeout(readq_relaxed, (iommu)->reg + (addr), val, cond, \
			   delay_us, timeout_us)

#define riscv_iommu_readl_timeout(iommu, addr, val, cond, delay_us, timeout_us) \
	readx_poll_timeout(readl_relaxed, (iommu)->reg + (addr), val, cond, \
			   delay_us, timeout_us)

#endif
