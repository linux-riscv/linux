/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * RISC-V IOMMU Common Interface
 *
 * This header provides a common interface for sharing resources between
 * the RISC-V IOMMU driver and its auxiliary bus child drivers.
 *
 * Copyright (C) 2026 SpacemiT Technologies Inc.
 *   Author: 2026 Jingyu Li <joey.li@spacemit.com>
 *                Lv Zheng <lv.zheng@spacemit.com>
 */

#ifndef _LINUX_RISCV_IOMMU_H_
#define _LINUX_RISCV_IOMMU_H_

#include <linux/auxiliary_bus.h>

struct riscv_iommu_device;

/**
 * struct riscv_iommu_subdev - RISC-V IOMMU auxiliary bus subdevice
 * @link: list node for iommu->subdev_list
 * @auxdev: auxiliary bus device ((use auxdev.id for unique id)
 * @base: PMU register base
 * @iommu: parent IOMMU (opaque)
 * @info: subdevice-specific info, freed in release
 */
struct riscv_iommu_subdev {
	struct list_head link;
	struct auxiliary_device auxdev;
	void __iomem *base;
	struct riscv_iommu_device *iommu;
	void *info;
};

/**
 * struct riscv_iommu_hpm_info - HPM info for IOATS (main IOMMU HPM)
 * @irq: interrupt number
 */
struct riscv_iommu_hpm_info {
	unsigned int irq;
};

/**
 * riscv_iommu_get_subdev - get riscv_iommu_subdev from device
 *
 * @dev: &device of the auxiliary device (auxdev->dev)
 *
 * Returns the riscv_iommu_subdev pointer, or NULL if @dev is NULL.
 */
static inline struct riscv_iommu_subdev *riscv_iommu_get_subdev(struct device *dev)
{
	if (!dev)
		return NULL;
	return container_of(container_of(dev, struct auxiliary_device, dev),
			    struct riscv_iommu_subdev, auxdev);
}

/**
 * riscv_iommu_pmip_status - test if PM interrupt is pending
 *
 * @subdev: subdevice with iommu
 *
 * Returns true if PM interrupt pending, false otherwise.
 */
bool riscv_iommu_pmip_status(struct riscv_iommu_subdev *subdev);

/**
 * riscv_iommu_clear_pmip - clear PMIP bit in IPSR to ack PMU interrupt
 *
 * @subdev: subdevice with iommu
 */
void riscv_iommu_clear_pmip(struct riscv_iommu_subdev *subdev);

#endif /* _LINUX_RISCV_IOMMU_H_ */
