// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Platform Driver Entry and Exit
 *
 * Responsibilities:
 *   - Match "rambus,cmh-v1030" DT node via platform_driver
 *   - Parse device-tree properties via cmh_config_init()
 *   - ioremap the SIC region
 *   - Verify CMH boot status (sanity check)
 *   - Compute per-instance register bases
 *   - Initialize MBX queues (MQI)
 *   - Start Transaction Manager kthread
 *   - Register Response Handler IRQ
 *   - Register Kernel Crypto API hash algorithms
 *   - Clean up in reverse order on exit or error
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/clk.h>
#include <linux/gpio/consumer.h>
#include <linux/dma-mapping.h>
#include <linux/platform_device.h>
#include <linux/of.h>

#include "cmh.h"
#include "cmh_dma.h"
#include "cmh_mqi.h"
#include "cmh_txn.h"
#include "cmh_rh.h"
#include "cmh_hash.h"
#include "cmh_hmac.h"
#include "cmh_cshake.h"
#include "cmh_kmac.h"
#include "cmh_mgmt.h"
#include "cmh_registers.h"
#include "cmh_debugfs.h"
#include "cmh_sysfs.h"

#include <linux/iopoll.h>

#ifdef CONFIG_CRYPTO_DEV_CMH_DEBUG
static bool skip_fw_check;
module_param(skip_fw_check, bool, 0444);
MODULE_PARM_DESC(skip_fw_check,
		 "[debug] Skip eSW boot status check at probe (default: false)");
#else
#define skip_fw_check false
#endif

/* SIC Sanity Check */

static int cmh_check_sic(struct cmh_config *cfg)
{
	const u32 ready = SIC_SW_BOOT_STATUS_MISSION |
			  SIC_SW_BOOT_STATUS_MISSION2;
	u32 boot_status;
	u32 sw_boot;
	int ret;

	boot_status = cmh_reg_read32(cfg->sic_mapped, R_SIC_BOOT_STATUS);

	if ((boot_status & SIC_BOOT_STATUS_MASK) != SIC_BOOT_STATUS_PASS) {
		dev_err(cmh_dev(), "SIC boot status check failed (0x%02x != 0x%02x)\n",
			boot_status & SIC_BOOT_STATUS_MASK, SIC_BOOT_STATUS_PASS);
		return -EIO;
	}

	/*
	 * Wait for eSW readiness: MISSION signals the primary VCQ engine,
	 * MISSION2 the sidecar engine (set asynchronously).  The driver
	 * uses both, so require both bits.
	 */
	ret = read_poll_timeout(ioread32, sw_boot,
				(sw_boot & ready) == ready,
				1000,
				(unsigned long)cfg->fw_ready_timeout_ms * 1000UL,
				false,
				cfg->sic_mapped + R_SIC_SW_BOOT_STATUS);
	if (ret) {
		sw_boot = cmh_reg_read32(cfg->sic_mapped, R_SIC_SW_BOOT_STATUS);
		dev_err(cmh_dev(), "CMH eSW not ready (sw_boot_status=0x%08x, timeout=%ums)\n",
			sw_boot, cfg->fw_ready_timeout_ms);
		return -ETIMEDOUT;
	}

	return 0;
}

/* Module Init -- platform driver probe */

static int cmh_probe(struct platform_device *pdev)
{
	struct cmh_device *dev;
	struct cmh_config *cfg;
	struct clk_bulk_data *clks;
	struct gpio_desc *reset;
	unsigned int i;
	int ret;

	dev = devm_kzalloc(&pdev->dev, sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	dev->dev = &pdev->dev;
	cfg = &dev->config;

	/* Declare DMA addressing capability */
	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (ret) {
		ret = dev_err_probe(&pdev->dev, ret,
				    "dma_set_mask_and_coherent failed\n");
		goto err_free_dev;
	}

	/* Initialize DMA backend (standard API or FPGA pool) */
	ret = cmh_dma_init(pdev);
	if (ret) {
		ret = dev_err_probe(&pdev->dev, ret, "DMA init failed\n");
		goto err_free_dev;
	}

	/* Step 1: Parse and validate configuration (DT + module params) */
	ret = cmh_config_init(cfg, pdev);
	if (ret)
		goto err_dma_init;

	/*
	 * Enable functional clocks and release reset.  Both are optional --
	 * integrations where a separate management/power controller owns the
	 * clock and reset lines describe neither, and these calls are
	 * no-ops.  The hub gates its clocks internally, but
	 * clk_disable_unused() would otherwise gate an always-on input the
	 * driver never claimed, so the driver enables whatever clocks the
	 * device tree provides.  Clocks come up before reset is released (a
	 * hard reset requires an active clock) and before any SIC register
	 * access.  The reset line is acquired already deasserted; the driver
	 * does not drive a reset pulse -- the eSW boots independently and its
	 * mission-mode readiness is verified separately below, and no in-tree
	 * platform wires this line for a reset sequence to be exercised.
	 * devm unwinds both on remove or probe error.
	 */
	ret = devm_clk_bulk_get_all_enabled(&pdev->dev, &clks);
	if (ret < 0) {
		ret = dev_err_probe(&pdev->dev, ret,
				    "failed to enable clocks\n");
		goto err_dma_init;
	}

	reset = devm_gpiod_get_optional(&pdev->dev, "reset", GPIOD_OUT_LOW);
	if (IS_ERR(reset)) {
		ret = dev_err_probe(&pdev->dev, PTR_ERR(reset),
				    "failed to acquire reset GPIO\n");
		goto err_dma_init;
	}

	/* Step 2: ioremap the SIC region */
	cfg->sic_mapped = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(cfg->sic_mapped)) {
		ret = dev_err_probe(&pdev->dev, PTR_ERR(cfg->sic_mapped),
				    "ioremap failed for SIC region\n");
		cfg->sic_mapped = NULL;
		goto err_dma_init;
	}

	/* Step 3: Verify CMH is alive */
	if (!skip_fw_check) {
		ret = cmh_check_sic(cfg);
		if (ret)
			goto err_dma_init;
	}

	/* Step 3.5: Discover crypto cores from the SIC CORE_ENABLE register */
	ret = cmh_config_discover_cores(cfg);
	if (ret)
		goto err_dma_init;

	/* Step 4: Compute per-instance register bases */
	for (i = 0; i < cfg->mbx_count; i++) {
		struct cmh_mbx_config *m = &cfg->mailboxes[i];

		m->reg_base = cmh_mbx_instance_base(cfg->sic_mapped,
						    m->instance);

		dev_dbg(cmh_dev(), "mbx[%u] instance=%u reg_base=%p\n",
			i, m->instance, m->reg_base);
	}

	cmh_debugfs_init(cfg);

	/* Initialise mailbox queue interface */
	ret = cmh_mqi_init(cfg);
	if (ret)
		goto err_mqi_init;

	/* Initialise transaction manager */
	ret = cmh_tm_init(cfg);
	if (ret)
		goto err_tm_init;

	/* Initialise response handler */
	ret = cmh_rh_init(cfg);
	if (ret)
		goto err_rh_init;

	/* Register hash algorithms with the kernel crypto API */
	ret = cmh_hash_register();
	if (ret)
		goto err_hash_register;

	/* Register HMAC hash algorithms */
	ret = cmh_hmac_register();
	if (ret)
		goto err_hmac_register;

	/* Register CSHAKE hash algorithms */
	ret = cmh_cshake_register();
	if (ret)
		goto err_cshake_register;

	/* Register KMAC hash algorithms */
	ret = cmh_kmac_register();
	if (ret)
		goto err_kmac_register;

	/* Register key management device (/dev/cmh_mgmt) */
	ret = cmh_mgmt_register();
	if (ret)
		goto err_mgmt_register;

	platform_set_drvdata(pdev, dev);

	return 0;

err_mgmt_register:
	cmh_kmac_unregister();
err_kmac_register:
	cmh_cshake_unregister();
err_cshake_register:
	cmh_hmac_unregister();
err_hmac_register:
	cmh_hash_unregister();
err_hash_register:
	cmh_rh_cleanup(cfg);
err_rh_init:
	cmh_tm_cleanup();
err_tm_init:
	cmh_mqi_cleanup(cfg);
err_mqi_init:
	cmh_debugfs_cleanup();
err_dma_init:
	cmh_dma_cleanup();
err_free_dev:
	return ret;
}

/* Module Exit -- platform driver remove */

static void cmh_remove(struct platform_device *pdev)
{
	struct cmh_device *dev = platform_get_drvdata(pdev);
	struct cmh_config *cfg;

	if (!dev)
		return;

	cfg = &dev->config;

	cmh_mgmt_unregister();
	cmh_kmac_unregister();
	cmh_cshake_unregister();
	cmh_hmac_unregister();
	cmh_hash_unregister();
	cmh_rh_cleanup(cfg);
	cmh_tm_cleanup();
	cmh_mqi_cleanup(cfg);
	cmh_debugfs_cleanup();
	cmh_dma_cleanup();
}

static const struct of_device_id cmh_of_match[] = {
	{ .compatible = "rambus,cmh-v1030" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, cmh_of_match);

/*
 * PM suspend/resume.
 *
 * Suspend: drain the TM first (while the RH is still active and can
 * deliver completions for in-flight transactions), then quiesce the
 * RH (cancel watchdog, mask HW interrupts).  This ordering ensures
 * the drain_timeout_ms wait in cmh_tm_quiesce() can actually succeed
 * -- if we suspended RH first, no completions would be delivered and
 * the drain would always hit the force-cancel path.
 *
 * IRQ handlers remain registered (standard PM pattern: the kernel
 * disables the IRQ lines during suspend, no need to free/re-request).
 *
 * Resume: re-check the SIC/SW boot status, re-synchronise the RH
 * with hardware (head positions, interrupt masks, watchdog), then
 * restart the TM kthread.
 */

static int cmh_suspend(struct device *dev)
{
	struct cmh_device *cmh = dev_get_drvdata(dev);

	if (!cmh)
		return 0;

	cmh_tm_quiesce();
	cmh_rh_suspend(&cmh->config);
	return 0;
}

static int cmh_resume(struct device *dev)
{
	struct cmh_device *cmh = dev_get_drvdata(dev);
	int ret;

	if (!cmh)
		return 0;

	ret = cmh_check_sic(&cmh->config);
	if (ret) {
		dev_err(dev, "resume: CMH eSW health check failed (%d)\n",
			ret);
		return ret;
	}

	/*
	 * cmh_rh_resume() is void: it only re-syncs MMIO head pointers,
	 * clears stale interrupt status bits (W1C), re-enables interrupt
	 * masks, and re-arms the watchdog timer -- none of which can fail
	 * after the SIC health check above has confirmed HW accessibility.
	 */
	cmh_rh_resume(&cmh->config);

	ret = cmh_tm_resume();
	if (ret) {
		dev_err(dev, "resume: TM restart failed (%d)\n", ret);
		return ret;
	}
	return 0;
}

static DEFINE_SIMPLE_DEV_PM_OPS(cmh_pm_ops,
				cmh_suspend,
				cmh_resume);

/*
 * Runtime PM is intentionally not implemented.  The CMH hardware does
 * not expose HLOS-accessible clock gates or power domains -- the eSW
 * firmware manages HW power state independently.  There is no mechanism
 * for the kernel to idle, gate clocks, or power down the accelerator
 * block from HLOS.  If a future platform variant exposes power control
 * to HLOS (e.g. via a SCMI power domain), runtime PM support can be
 * added at that time using SET_RUNTIME_PM_OPS and pm_runtime_get/put
 * around VCQ submission paths.
 *
 * System sleep (suspend/resume) is supported via DEFINE_SIMPLE_DEV_PM_OPS
 * above: suspend quiesces the TM and masks IRQs; resume re-verifies
 * eSW health (SIC status) and restarts the TM thread.
 */

static struct platform_driver cmh_driver = {
	.probe      = cmh_probe,
	.remove     = cmh_remove,
	.driver = {
		.name           = "cmh",
		.of_match_table = cmh_of_match,
		.dev_groups     = cmh_sysfs_groups,
		.pm             = pm_sleep_ptr(&cmh_pm_ops),
	},
};

module_platform_driver(cmh_driver);

MODULE_DESCRIPTION("Rambus CryptoManager Hub (CMH) hardware crypto accelerator");
MODULE_AUTHOR("Alex Ousherovitch <aousherovitch@rambus.com>");
MODULE_AUTHOR("Saravanakrishnan Krishnamoorthy <skrishnamoorthy@rambus.com>");
MODULE_AUTHOR("Joel Wittenauer <Joel.Wittenauer@cryptography.com>");
MODULE_IMPORT_NS("CRYPTO_INTERNAL");
MODULE_LICENSE("GPL");
