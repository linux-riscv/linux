// SPDX-License-Identifier: GPL-2.0
/*
 * Bao Hypervisor I/O Dispatcher Interrupt Controller
 *
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 *
 * Authors:
 *	João Peixoto <jpeixoto@osyx.tech>
 *	José Martins <jose@osyx.tech>
 *	David Cerdeira <davidmcerdeira@osyx.tech>
 */

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <dt-bindings/interrupt-controller/arm-gic.h>
#include "bao_drv.h"

/**
 * bao_interrupt_handler - Top-level interrupt handler for Bao DM
 * @irq: Interrupt number
 * @dev: Pointer to the Bao device model (struct bao_dm)
 *
 * Invokes the DM's registered interrupt controller handler, if any.
 *
 * Return: IRQ_HANDLED
 */
static irqreturn_t bao_interrupt_handler(int irq, void *dev)
{
	struct bao_dm *dm = dev;
	bao_intc_handler_t handler = READ_ONCE(dm->intc_handler);

	if (handler)
		handler(dm);

	return IRQ_HANDLED;
}

void bao_intc_setup_handler(struct bao_dm *dm, bao_intc_handler_t handler)
{
	if (WARN_ON_ONCE(!dm))
		return;

	WRITE_ONCE(dm->intc_handler, handler);
}

void bao_intc_remove_handler(struct bao_dm *dm)
{
	if (WARN_ON_ONCE(!dm))
		return;

	WRITE_ONCE(dm->intc_handler, NULL);
}

/**
 * bao_intc_map_irq - Map the hypervisor notification line to a Linux IRQ
 * @line: Line of the system's root interrupt controller (e.g. a GIC SPI on
 *        arm64, a PLIC source on riscv)
 *
 * The I/O dispatcher is not a device-tree device, so its notification
 * interrupt cannot be resolved from an "interrupts" property. Resolve it
 * against the root interrupt parent instead, i.e. the controller the device
 * tree's root node points at, which is the one any device without an explicit
 * interrupt-parent would use. Only the controller's "#interrupt-cells" is
 * needed to build the specifier: a single-cell controller (e.g. a PLIC) takes
 * the line directly, a two-cell one (e.g. an APLIC) the line and the trigger
 * type, and a GIC-style three-cell one an edge-triggered SPI.
 *
 * Return: A Linux virtual IRQ number on success, negative error code on failure.
 */
static int bao_intc_map_irq(u32 line)
{
	struct of_phandle_args oirq = {};
	struct device_node *parent;
	unsigned int virq;
	u32 cells;
	int ret;

	parent = of_irq_find_parent(of_root);
	if (!parent) {
		pr_err("bao: no root interrupt-parent in the device tree\n");
		return -ENODEV;
	}

	ret = of_property_read_u32(parent, "#interrupt-cells", &cells);
	if (ret)
		goto out_put;

	oirq.np = parent;
	oirq.args_count = cells;

	switch (cells) {
	case 1:
		oirq.args[0] = line;
		break;
	case 2:
		oirq.args[0] = line;
		oirq.args[1] = IRQ_TYPE_EDGE_RISING;
		break;
	case 3:
	case 4:
		oirq.args[0] = GIC_SPI;
		oirq.args[1] = line;
		oirq.args[2] = IRQ_TYPE_EDGE_RISING;
		break;
	default:
		pr_err("bao: unsupported #interrupt-cells = %u on %pOF\n",
		       cells, parent);
		ret = -EINVAL;
		goto out_put;
	}

	virq = irq_create_of_mapping(&oirq);
	ret = virq ? (int)virq : -EINVAL;

out_put:
	of_node_put(parent);
	return ret;
}

int bao_intc_init(struct bao_dm *dm)
{
	int virq;

	if (WARN_ON_ONCE(!dm))
		return -EINVAL;

	virq = bao_intc_map_irq(dm->info.irq);
	if (virq < 0)
		return virq;

	dm->virq = virq;

	scnprintf(dm->intc_name, sizeof(dm->intc_name), "bao-iodintc%u",
		  dm->info.id);

	return request_irq(dm->virq, bao_interrupt_handler, 0, dm->intc_name,
			   dm);
}

void bao_intc_destroy(struct bao_dm *dm)
{
	if (WARN_ON_ONCE(!dm))
		return;

	free_irq(dm->virq, dm);
	irq_dispose_mapping(dm->virq);
}
