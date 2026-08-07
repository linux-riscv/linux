// SPDX-License-Identifier: GPL-2.0
/*
 * Bao Hypervisor I/O Dispatcher Kernel Driver
 *
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 */

#include <linux/platform_device.h>
#include <linux/of_irq.h>
#include "bao_drv.h"

static int bao_io_dispatcher_driver_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct bao_dm_info dm_info;
	struct bao_dm *dm;
	struct resource *r;
	int irq;
	u32 id;
	int ret;

	r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!r) {
		dev_err(dev, "missing shared memory resource\n");
		return -ENODEV;
	}

	ret = of_property_read_u32(dev->of_node, "bao,id", &id);
	if (ret) {
		dev_err(dev, "missing or invalid 'bao,id' property\n");
		return ret;
	}

	if (id >= BAO_IO_MAX_DMS) {
		dev_err(dev, "'bao,id' %u out of range (max %u)\n", id,
			BAO_IO_MAX_DMS - 1);
		return -EINVAL;
	}

	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return irq;

	dm_info.id = id;
	dm_info.shmem_addr = r->start;
	dm_info.shmem_size = resource_size(r);
	dm_info.irq = irq;

	dm = bao_dm_create(&dm_info, dev);
	if (!dm)
		return -EINVAL;

	ret = bao_intc_init(dm);
	if (ret) {
		dev_err(dev, "failed to register interrupt %d for DM %u\n", irq,
			id);
		bao_dm_destroy(dm);
		return ret;
	}

	platform_set_drvdata(pdev, dm);

	return 0;
}

static void bao_io_dispatcher_driver_remove(struct platform_device *pdev)
{
	struct bao_dm *dm = platform_get_drvdata(pdev);

	bao_intc_destroy(dm);
	bao_dm_destroy(dm);
}

static const struct of_device_id bao_io_dispatcher_driver_dt_ids[] = {
	{ .compatible = "bao,io-dispatcher" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, bao_io_dispatcher_driver_dt_ids);

static struct platform_driver bao_io_dispatcher_driver = {
	.probe = bao_io_dispatcher_driver_probe,
	.remove = bao_io_dispatcher_driver_remove,
	.driver = {
		.name = "bao-io-dispatcher",
		.of_match_table = bao_io_dispatcher_driver_dt_ids,
	},
};

module_platform_driver(bao_io_dispatcher_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("João Peixoto <jpeixoto@osyx.tech>");
MODULE_AUTHOR("David Cerdeira <davidmcerdeira@osyx.tech>");
MODULE_AUTHOR("José Martins <jose@osyx.tech>");
MODULE_DESCRIPTION("Bao Hypervisor I/O Dispatcher Kernel Driver");
