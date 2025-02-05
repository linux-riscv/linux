// SPDX-License-Identifier: GPL-2.0
/*
 * Allwinner V853 SoC pinctrl driver.
 *
 * Copyright (c) 2025 Andras Szemzo <szemzo.andras@gmail.com>
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/pinctrl/pinctrl.h>

#include "pinctrl-sunxi.h"

static const u8 v853_nr_bank_pins[SUNXI_PINCTRL_MAX_BANKS] =
/*	  PA  PB  PC  PD  PE  PF  PG  PH  PI  */
	{ 22,  0, 12, 23, 18,  7,  8, 16,  5 };

static const unsigned int v853_irq_bank_map[] = { 0, 2, 3, 4, 5, 6, 7, 8 };

static const u8 v853_irq_bank_muxes[SUNXI_PINCTRL_MAX_BANKS] =
/*	  PA  PB  PC  PD  PE  PF  PG  PH  PI */
	{ 14,  0, 14, 14, 14, 14, 14, 14, 14 };

static struct sunxi_pinctrl_desc v853_pinctrl_data = {
	.irq_banks = ARRAY_SIZE(v853_irq_bank_map),
	.irq_bank_map = v853_irq_bank_map,
	.io_bias_cfg_variant = BIAS_VOLTAGE_PIO_POW_MODE_SEL,
};

static int v853_pinctrl_probe(struct platform_device *pdev)
{
	return sunxi_pinctrl_dt_table_init(pdev, v853_nr_bank_pins,
					   v853_irq_bank_muxes,
					   &v853_pinctrl_data,
					   SUNXI_PINCTRL_NEW_REG_LAYOUT |
					   SUNXI_PINCTRL_ELEVEN_BANKS);
}

static const struct of_device_id v853_pinctrl_match[] = {
	{ .compatible = "allwinner,sun8i-v853-pinctrl", },
	{}
};

static struct platform_driver v853_pinctrl_driver = {
	.probe	= v853_pinctrl_probe,
	.driver	= {
		.name		= "sun8i-v853-pinctrl",
		.of_match_table	= v853_pinctrl_match,
	},
};
builtin_platform_driver(v853_pinctrl_driver);
