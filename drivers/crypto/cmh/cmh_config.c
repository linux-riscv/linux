// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Configuration from Device Tree
 *
 * The CMH device tree node provides:
 *   - reg: SIC base + size (mandatory)
 *   - interrupts: per-MBX IRQs (mandatory for IRQ mode)
 *   - cri,mbx-instances: array of MBX instance IDs
 *   - cri,mbx-slots-log2: per-MBX slot count as log2
 *   - cri,mbx-strides-log2: per-MBX stride as log2
 *
 * Per-core-type child nodes (e.g. aes@3, pke@a):
 *   - reg: hardware core ID (CORE_ID_* from cmh_vcq.h)
 *   - cri,mbx: (optional) pin to a specific MBX index
 *
 * Module parameters (non-topology):
 *   - fw_ready_timeout_ms: CMH eSW mission-mode boot timeout
 *   (hwrng_quality, cmq_max_depth, backlog_max_depth live in other files)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/of.h>

#include "cmh_config.h"
#include "cmh_dma.h"

/* -- Module parameters ------------------------------------------------- */

static unsigned int fw_ready_timeout_ms = CMH_DEFAULT_FW_READY_TIMEOUT_MS;
module_param(fw_ready_timeout_ms, uint, 0444);
MODULE_PARM_DESC(fw_ready_timeout_ms,
		 "Timeout in ms to wait for CMH eSW mission mode (default 5000)");

/*
 * Debug-only MBX overrides for stress testing.
 * When non-zero, these override the corresponding DT values, enabling
 * contention stress tests to force a minimal MBX config
 * (e.g. mbx_count_override=1 mbx_slots_override=1 for 1 MBX, 2 slots).
 */
#ifdef CONFIG_CRYPTO_DEV_CMH_DEBUG
static unsigned int mbx_count_override;
module_param(mbx_count_override, uint, 0444);
MODULE_PARM_DESC(mbx_count_override,
		 "[debug] Override DT MBX count (0 = use DT, default: 0)");

static unsigned int mbx_slots_override;
module_param(mbx_slots_override, uint, 0444);
MODULE_PARM_DESC(mbx_slots_override,
		 "[debug] Override all MBX slots_log2 (0 = use DT, default: 0)");

static bool mbx_round_robin;
module_param(mbx_round_robin, bool, 0444);
MODULE_PARM_DESC(mbx_round_robin,
		 "[debug] Ignore DT cri,mbx pins and round-robin all cores across MBXes (0 = use DT affinity, default: 0)");
#endif

/* -- Core ID -> core_type lookup --------------------------------------- */

/*
 * Map hardware core IDs (from DT child "reg") to enum cmh_core_type.
 *
 * Entries set to -1 are not dispatchable crypto cores: system cores
 * (SYS, DMA, KIC, TIC, MPU, EMC, EAC) and the DRBG singleton
 * (handled separately in cmh_rng.c).
 */
static const int core_id_to_type[CORE_ID_NUM] = {
	[0 ... CORE_ID_NUM - 1] = -1,
	[CORE_ID_HC]  = CMH_CORE_HC,
	[CORE_ID_AES] = CMH_CORE_AES,
	[CORE_ID_SM4] = CMH_CORE_SM4,
	[CORE_ID_SM3] = CMH_CORE_SM3,
	[CORE_ID_CCP] = CMH_CORE_CCP,
	[CORE_ID_PKE] = CMH_CORE_PKE,
	[CORE_ID_QSE] = CMH_CORE_QSE,
	[CORE_ID_HCQ] = CMH_CORE_HCQ,
};

/* Human-readable names for error messages */
static const char * const core_type_names[CMH_NUM_CORE_TYPES] = {
	[CMH_CORE_HC]  = "hc",
	[CMH_CORE_AES] = "aes",
	[CMH_CORE_SM4] = "sm4",
	[CMH_CORE_SM3] = "sm3",
	[CMH_CORE_CCP] = "ccp",
	[CMH_CORE_PKE] = "pke",
	[CMH_CORE_QSE] = "qse",
	[CMH_CORE_HCQ] = "hcq",
};

/* -- DT child node enumeration ----------------------------------------- */

static int cmh_config_populate_cores(struct cmh_config *cfg,
				     struct device_node *np)
{
	struct device_node *child;
	u32 core_id, mbx_val;
	int type, ret;

	for_each_child_of_node(np, child) {
		ret = of_property_read_u32(child, "reg", &core_id);
		if (ret) {
			dev_warn(cmh_dev(),
				 "DT child %pOFn: missing 'reg', skipping\n",
				 child);
			continue;
		}

		if (core_id >= CORE_ID_NUM) {
			dev_info(cmh_dev(),
				 "DT child %pOFn: core_id 0x%02x unknown, skipping\n",
				 child, core_id);
			continue;
		}

		type = core_id_to_type[core_id];
		if (type < 0) {
			/* Not a dispatchable crypto core (DRBG, SYS, etc.) */
			dev_dbg(cmh_dev(),
				"DT child %pOFn: core_id 0x%02x not dispatchable\n",
				child, core_id);
			continue;
		}

		if (cfg->core_types[type].num_instances >=
		    CMH_MAX_CORE_INSTANCES) {
			dev_err(cmh_dev(),
				"DT: too many instances for %s (max %u)\n",
				core_type_names[type],
				CMH_MAX_CORE_INSTANCES);
			of_node_put(child);
			return -EINVAL;
		}

		{
			struct cmh_core_type_cfg *ct = &cfg->core_types[type];
			u32 idx = ct->num_instances;

			ct->core_ids[idx] = core_id;
			ret = of_property_read_u32(child, "cri,mbx", &mbx_val);
			ct->mbx[idx] = ret ? -1 : (s32)mbx_val;
#ifdef CONFIG_CRYPTO_DEV_CMH_DEBUG
			/*
			 * Debug knob for the cross-core stress test: drop the
			 * DT MBX pin so cmh_core_select_instance() round-robins
			 * this core across all configured MBXes (the unpinned
			 * dispatch behaviour exercised before cri,mbx affinity
			 * was added to the baseline device tree).
			 */
			if (mbx_round_robin)
				ct->mbx[idx] = -1;
#endif
			ct->num_instances++;
		}
	}

	return 0;
}

/* -- Validation -------------------------------------------------------- */

static int cmh_config_validate_core_types(struct cmh_config *cfg)
{
	unsigned int i, j, k;

	for (i = 0; i < CMH_NUM_CORE_TYPES; i++) {
		struct cmh_core_type_cfg *ct = &cfg->core_types[i];
		const char *name = core_type_names[i];

		/* Zero instances is valid -- core absent from DT */
		if (ct->num_instances == 0)
			continue;

		if (ct->num_instances > CMH_MAX_CORE_INSTANCES) {
			dev_err(cmh_dev(), "%s: num_instances %u > max %u\n",
				name, ct->num_instances,
				CMH_MAX_CORE_INSTANCES);
			return -EINVAL;
		}

		/* Validate MBX indices */
		for (j = 0; j < ct->num_instances; j++) {
			if (ct->mbx[j] >= 0 &&
			    (u32)ct->mbx[j] >= cfg->mbx_count) {
#ifdef CONFIG_CRYPTO_DEV_CMH_DEBUG
				if (mbx_count_override > 0) {
					dev_info(cmh_dev(),
						 "%s: mbx[%u]=%d >= overridden mbx_count %u, auto-assigning\n",
						 name, j, ct->mbx[j],
						 cfg->mbx_count);
					ct->mbx[j] = -1;
					continue;
				}
#endif
				dev_err(cmh_dev(), "%s: mbx[%u]=%d >= mbx_count %u\n",
					name, j, ct->mbx[j],
					cfg->mbx_count);
				return -EINVAL;
			}
		}

		/* No duplicate core IDs within this type */
		for (j = 1; j < ct->num_instances; j++) {
			for (k = 0; k < j; k++) {
				if (ct->core_ids[j] == ct->core_ids[k]) {
					dev_err(cmh_dev(),
						"%s: duplicate core_id 0x%02x at [%u] and [%u]\n",
						name, ct->core_ids[j],
						k, j);
					return -EINVAL;
				}
			}
		}

		/* No duplicate MBX within this type (if explicit) */
		for (j = 1; j < ct->num_instances; j++) {
			if (ct->mbx[j] < 0)
				continue;
			for (k = 0; k < j; k++) {
				if (ct->mbx[k] == ct->mbx[j]) {
					dev_err(cmh_dev(),
						"%s: duplicate mbx %d at [%u] and [%u]\n",
						name, ct->mbx[j], k, j);
					return -EINVAL;
				}
			}
		}

		/* All core IDs must fit in VCQ 8-bit field */
		for (j = 0; j < ct->num_instances; j++) {
			if (ct->core_ids[j] > CORE_ID_MAX) {
				dev_err(cmh_dev(),
					"%s: core_ids[%u]=0x%02x > CORE_ID_MAX\n",
					name, j, ct->core_ids[j]);
				return -EINVAL;
			}
		}
	}

	/* Cross-type: no core ID used by more than one type */
	for (i = 0; i < CMH_NUM_CORE_TYPES; i++) {
		struct cmh_core_type_cfg *ct_i = &cfg->core_types[i];

		for (j = i + 1; j < CMH_NUM_CORE_TYPES; j++) {
			struct cmh_core_type_cfg *ct_j = &cfg->core_types[j];

			for (k = 0; k < ct_i->num_instances; k++) {
				unsigned int m;

				for (m = 0; m < ct_j->num_instances; m++) {
					if (ct_i->core_ids[k] !=
					    ct_j->core_ids[m])
						continue;
					dev_err(cmh_dev(),
						"core_id 0x%02x conflict: %s[%u] and %s[%u]\n",
						ct_i->core_ids[k],
						core_type_names[i], k,
						core_type_names[j], m);
					return -EINVAL;
				}
			}
		}
	}

	return 0;
}

static int cmh_config_validate(struct cmh_config *cfg)
{
	unsigned int i, j;
	unsigned long max_instance_end;

	if (cfg->mbx_count == 0 || cfg->mbx_count > CMH_MAX_CONFIGURED_MBX) {
		dev_err(cmh_dev(), "mbx_count %u out of range (1..%u)\n",
			cfg->mbx_count, CMH_MAX_CONFIGURED_MBX);
		return -EINVAL;
	}

	for (i = 0; i < cfg->mbx_count; i++) {
		struct cmh_mbx_config *m = &cfg->mailboxes[i];

		if (m->instance >= CMH_MAX_MBX_INSTANCES) {
			dev_err(cmh_dev(), "mbx_instances[%u]=%u >= %u\n",
				i, m->instance, CMH_MAX_MBX_INSTANCES);
			return -EINVAL;
		}

		if (m->slots_log2 < CMH_MBX_SLOTS_LOG2_MIN ||
		    m->slots_log2 > CMH_MBX_SLOTS_LOG2_MAX) {
			dev_err(cmh_dev(), "mbx_slots[%u]=%u out of range (%u..%u)\n",
				i, m->slots_log2,
			       CMH_MBX_SLOTS_LOG2_MIN, CMH_MBX_SLOTS_LOG2_MAX);
			return -EINVAL;
		}

		if (m->stride_log2 < CMH_MBX_STRIDE_LOG2_MIN ||
		    m->stride_log2 > CMH_MBX_STRIDE_LOG2_MAX) {
			dev_err(cmh_dev(), "mbx_strides[%u]=%u out of range (%u..%u)\n",
				i, m->stride_log2,
			       CMH_MBX_STRIDE_LOG2_MIN, CMH_MBX_STRIDE_LOG2_MAX);
			return -EINVAL;
		}

		/* Check for duplicate instance indices */
		for (j = 0; j < i; j++) {
			if (cfg->mailboxes[j].instance == m->instance) {
				dev_err(cmh_dev(), "duplicate instance %u at indices %u and %u\n",
					m->instance, j, i);
				return -EINVAL;
			}
		}
	}

	/* Ensure SIC region is large enough for all requested instances */
	max_instance_end = 0;
	for (i = 0; i < cfg->mbx_count; i++) {
		unsigned long end = ((unsigned long)cfg->mailboxes[i].instance + 1)
				    << CMH_MBX_INSTANCE_SHIFT;
		if (end > max_instance_end)
			max_instance_end = end;
	}

	if (max_instance_end > cfg->sic_size) {
		dev_err(cmh_dev(), "sic_size 0x%zx too small for instance requiring 0x%lx\n",
			cfg->sic_size, max_instance_end);
		return -EINVAL;
	}

	return 0;
}

/* -- Public Interface -------------------------------------------------- */

/**
 * cmh_config_init() - Initialize device configuration from platform/DT data
 * @cfg: Configuration structure to populate
 * @pdev: Platform device providing DT node and resources
 *
 * Parse the "cri,cmh" device tree node for MMIO base address, interrupt
 * specifiers, and per-mailbox properties (instance indices, slot counts,
 * strides).  When DT properties are absent, fall back to module parameter
 * arrays.  Populate per-core-type instance configuration from module
 * parameters, then validate the complete configuration.
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_config_init(struct cmh_config *cfg, struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	struct resource *res;
	unsigned int i;
	int ret, irq, nr;

	if (!np) {
		dev_err(&pdev->dev, "device tree node required\n");
		return -ENODEV;
	}

	cfg->of_node = np;

	/* SIC base + size from DT "reg" property (mandatory) */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(cmh_dev(), "missing DT reg resource\n");
		return -EINVAL;
	}
	cfg->sic_base = res->start;
	cfg->sic_size = resource_size(res);

	/*
	 * IRQ resolution order:
	 *   1. Platform-level IRQ from the first DT "interrupts" entry.
	 *   2. If absent (cfg->irq == -1), cmh_rh_resolve_irqs() tries
	 *      per-MBX of_irq_get() for per-mailbox interrupt routing.
	 *   3. If no IRQs are available at all, the response handler
	 *      falls back to watchdog-timer polling (200 ms default).
	 */
	irq = platform_get_irq_optional(pdev, 0);
	cfg->irq = (irq >= 0) ? irq : -1;

	cfg->sic_mapped = NULL;
	cfg->fw_ready_timeout_ms = fw_ready_timeout_ms;

	/* -- MBX configuration from DT --------------------------------- */

	nr = of_property_count_u32_elems(np, "cri,mbx-instances");
	if (nr <= 0) {
		dev_err(cmh_dev(), "missing or empty cri,mbx-instances in DT\n");
		return -EINVAL;
	}
	if ((unsigned int)nr > CMH_MAX_CONFIGURED_MBX) {
		dev_err(cmh_dev(), "too many MBX instances in DT (%d > %u)\n",
			nr, CMH_MAX_CONFIGURED_MBX);
		return -EINVAL;
	}
	cfg->mbx_count = nr;

#ifdef CONFIG_CRYPTO_DEV_CMH_DEBUG
	if (mbx_count_override > 0) {
		if (mbx_count_override > cfg->mbx_count) {
			dev_err(cmh_dev(),
				"mbx_count_override %u > DT count %u\n",
				mbx_count_override, cfg->mbx_count);
			return -EINVAL;
		}
		dev_info(cmh_dev(), "[debug] overriding mbx_count: %u -> %u\n",
			 cfg->mbx_count, mbx_count_override);
		cfg->mbx_count = mbx_count_override;
	}
#endif

	for (i = 0; i < cfg->mbx_count; i++) {
		struct cmh_mbx_config *m = &cfg->mailboxes[i];
		u32 val;

		ret = of_property_read_u32_index(np, "cri,mbx-instances",
						 i, &val);
		if (ret) {
			dev_err(cmh_dev(), "missing cri,mbx-instances[%u] in DT\n",
				i);
			return ret;
		}
		m->instance = val;

		ret = of_property_read_u32_index(np, "cri,mbx-slots-log2",
						 i, &val);
		if (ret) {
			m->slots_log2 = CMH_DEFAULT_SLOTS_LOG2;
			dev_info(cmh_dev(),
				 "MBX[%u]: cri,mbx-slots-log2 absent, using default %u\n",
				 i, CMH_DEFAULT_SLOTS_LOG2);
		} else {
			m->slots_log2 = val;
		}

		ret = of_property_read_u32_index(np, "cri,mbx-strides-log2",
						 i, &val);
		if (ret) {
			m->stride_log2 = CMH_DEFAULT_STRIDE_LOG2;
			dev_info(cmh_dev(),
				 "MBX[%u]: cri,mbx-strides-log2 absent, using default %u\n",
				 i, CMH_DEFAULT_STRIDE_LOG2);
		} else {
			m->stride_log2 = val;
		}

#ifdef CONFIG_CRYPTO_DEV_CMH_DEBUG
		if (mbx_slots_override > 0) {
			m->slots_log2 = mbx_slots_override;
			if (i == 0)
				dev_info(cmh_dev(),
					 "[debug] overriding slots_log2 -> %u\n",
					 mbx_slots_override);
		}
#endif

		m->queue_size = (1UL << m->slots_log2) << m->stride_log2;
		m->dma_handle = 0;
		m->virt_addr = NULL;
		m->reg_base = NULL;
	}

	/* -- Core-type enumeration from DT child nodes ----------------- */

	ret = cmh_config_populate_cores(cfg, np);
	if (ret)
		return ret;

	ret = cmh_config_validate(cfg);
	if (ret)
		return ret;

	return cmh_config_validate_core_types(cfg);
}
