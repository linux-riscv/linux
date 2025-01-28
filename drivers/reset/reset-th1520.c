// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2024 Samsung Electronics Co., Ltd.
 * Author: Michal Wilczynski <m.wilczynski@samsung.com>
 */

#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/reset-controller.h>
#include <linux/regmap.h>

#include <dt-bindings/reset/thead,th1520-reset.h>

 /* register offset in VOSYS_REGMAP */
#define TH1520_GPU_RST_CFG		0x0
#define TH1520_GPU_RST_CFG_MASK		GENMASK(2, 0)

/* register values */
#define TH1520_GPU_SW_GPU_RST		BIT(0)
#define TH1520_GPU_SW_CLKGEN_RST	BIT(1)

struct th1520_reset_priv {
	struct reset_controller_dev rcdev;
	struct regmap *map;
	struct mutex gpu_seq_lock;  /* protects gpu assert/deassert sequence */
};

static inline struct th1520_reset_priv *
to_th1520_reset(struct reset_controller_dev *rcdev)
{
	return container_of(rcdev, struct th1520_reset_priv, rcdev);
}

static void th1520_rst_gpu_enable(struct regmap *reg,
				  struct mutex *gpu_seq_lock)
{
	int val;

	mutex_lock(gpu_seq_lock);

	/* if the GPU is not in a reset state it, put it into one */
	regmap_read(reg, TH1520_GPU_RST_CFG, &val);
	if (val)
		regmap_update_bits(reg, TH1520_GPU_RST_CFG,
				   TH1520_GPU_RST_CFG_MASK, 0x0);

	/* rst gpu clkgen */
	regmap_set_bits(reg, TH1520_GPU_RST_CFG, TH1520_GPU_SW_CLKGEN_RST);

	/*
	 * According to the hardware manual, a delay of at least 32 clock
	 * cycles is required between de-asserting the clkgen reset and
	 * de-asserting the GPU reset. Assuming a worst-case scenario with
	 * a very high GPU clock frequency, a delay of 1 microsecond is
	 * sufficient to ensure this requirement is met across all
	 * feasible GPU clock speeds.
	 */
	udelay(1);

	/* rst gpu */
	regmap_set_bits(reg, TH1520_GPU_RST_CFG, TH1520_GPU_SW_GPU_RST);

	mutex_unlock(gpu_seq_lock);
}

static void th1520_rst_gpu_disable(struct regmap *reg,
				   struct mutex *gpu_seq_lock)
{
	mutex_lock(gpu_seq_lock);

	regmap_update_bits(reg, TH1520_GPU_RST_CFG, TH1520_GPU_RST_CFG_MASK, 0x0);

	mutex_unlock(gpu_seq_lock);
}

static int th1520_reset_assert(struct reset_controller_dev *rcdev, unsigned long id)
{
	struct th1520_reset_priv *priv = to_th1520_reset(rcdev);

	switch (id) {
	case TH1520_RESET_ID_GPU:
		th1520_rst_gpu_disable(priv->map, &priv->gpu_seq_lock);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int th1520_reset_deassert(struct reset_controller_dev *rcdev, unsigned long id)
{
	struct th1520_reset_priv *priv = to_th1520_reset(rcdev);

	switch (id) {
	case TH1520_RESET_ID_GPU:
		th1520_rst_gpu_enable(priv->map, &priv->gpu_seq_lock);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int th1520_reset_xlate(struct reset_controller_dev *rcdev,
			      const struct of_phandle_args *reset_spec)
{
	unsigned int index = reset_spec->args[0];

	/* currently, only GPU reset is implemented in this driver */
	if (index == TH1520_RESET_ID_GPU)
		return index;

	return -EOPNOTSUPP;
}

static const struct reset_control_ops th1520_reset_ops = {
	.assert	= th1520_reset_assert,
	.deassert = th1520_reset_deassert,
};

static const struct regmap_config th1520_reset_regmap_config = {
	.reg_bits = 32,
	.val_bits = 32,
	.reg_stride = 4,
	.fast_io = true,
};

static int th1520_reset_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct th1520_reset_priv *priv;
	void __iomem *base;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(base))
		return PTR_ERR(base);

	priv->map = devm_regmap_init_mmio(dev, base,
					  &th1520_reset_regmap_config);
	if (IS_ERR(priv->map))
		return PTR_ERR(priv->map);

	mutex_init(&priv->gpu_seq_lock);

	priv->rcdev.owner = THIS_MODULE;
	priv->rcdev.nr_resets = 1;
	priv->rcdev.ops = &th1520_reset_ops;
	priv->rcdev.of_node = dev->of_node;
	priv->rcdev.of_xlate = th1520_reset_xlate;
	priv->rcdev.of_reset_n_cells = 1;

	return devm_reset_controller_register(dev, &priv->rcdev);
}

static const struct of_device_id th1520_reset_match[] = {
	{ .compatible = "thead,th1520-reset" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, th1520_reset_match);

static struct platform_driver th1520_reset_driver = {
	.driver = {
		.name = "th1520-reset",
		.of_match_table = th1520_reset_match,
	},
	.probe = th1520_reset_probe,
};
module_platform_driver(th1520_reset_driver);

MODULE_AUTHOR("Michal Wilczynski <m.wilczynski@samsung.com>");
MODULE_DESCRIPTION("T-HEAD TH1520 SoC reset controller");
MODULE_LICENSE("GPL");
