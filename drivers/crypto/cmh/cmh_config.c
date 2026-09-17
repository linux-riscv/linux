// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Configuration from Device Tree
 *
 * The CMH device tree node provides:
 *   - reg: SIC base + size (mandatory)
 *
 * Per-mailbox child nodes (queue@N):
 *   - reg: 0-based MBX instance index (mandatory)
 *   - interrupts: (optional) per-MBX completion IRQ; absent => polling
 *   - rambus,num-slots / rambus,slot-stride-bytes: (optional) VCQ ring
 *     geometry (slot count / per-slot stride in bytes, both powers of two)
 *   - rambus,cores: (optional) crypto core names pinned to this mailbox
 *
 * Crypto cores are discovered from the SIC CORE_ENABLE register at probe
 * (cmh_config_discover_cores), not described in the device tree.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/log2.h>
#include <linux/string.h>

#include "cmh_config.h"
#include "cmh_dma.h"

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
		 "[debug] Ignore DT rambus,cores affinity and round-robin all cores across MBXes (0 = use DT affinity, default: 0)");
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

/* -- Hardware core discovery ------------------------------------------ */

/*
 * Per-core-type discovery descriptor: the dual-rail CORE_ENABLE mask and
 * the canonical hardware core ID for that type.  DRBG is intentionally
 * absent -- it is not a dispatchable crypto core (handled by cmh_rng.c).
 */
struct cmh_core_desc {
	u32 enable_mask;
	u32 core_id;
};

static const struct cmh_core_desc cmh_core_descs[CMH_NUM_CORE_TYPES] = {
	[CMH_CORE_HC]  = { SIC_CORE_ENABLE_HC,  CORE_ID_HC  },
	[CMH_CORE_AES] = { SIC_CORE_ENABLE_AES, CORE_ID_AES },
	[CMH_CORE_SM4] = { SIC_CORE_ENABLE_SM4, CORE_ID_SM4 },
	[CMH_CORE_SM3] = { SIC_CORE_ENABLE_SM3, CORE_ID_SM3 },
	[CMH_CORE_CCP] = { SIC_CORE_ENABLE_CCP, CORE_ID_CCP },
	[CMH_CORE_PKE] = { SIC_CORE_ENABLE_PKE, CORE_ID_PKE },
	[CMH_CORE_QSE] = { SIC_CORE_ENABLE_QSE, CORE_ID_QSE },
	[CMH_CORE_HCQ] = { SIC_CORE_ENABLE_HCQ, CORE_ID_HCQ },
};

/* Dual-rail encoding: 0b01 (low bit set, high bit clear) means enabled. */
static bool cmh_core_enabled(u32 core_enable, u32 mask)
{
	return (core_enable & (mask | (mask << 1))) == mask;
}

/* rambus,cores DT names -> hardware core IDs (see cmh_vcq.h). */
static const struct cmh_dt_core_name {
	const char *name;
	u32 id;
} cmh_dt_core_names[] = {
	{ "hc",  CORE_ID_HC },
	{ "aes", CORE_ID_AES },
	{ "sm4", CORE_ID_SM4 },
	{ "sm3", CORE_ID_SM3 },
	{ "hcq", CORE_ID_HCQ },
	{ "qse", CORE_ID_QSE },
	{ "pke", CORE_ID_PKE },
	{ "ccp", CORE_ID_CCP },
};

static int cmh_dt_core_id(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cmh_dt_core_names); i++)
		if (!strcmp(name, cmh_dt_core_names[i].name))
			return (int)cmh_dt_core_names[i].id;
	return -1;
}

/*
 * Read a power-of-two DT geometry property (a slot count or a byte stride)
 * and return its log2 -- the encoding the mailbox QUEUE registers use.  An
 * absent property yields @def_log2; a present value must be a power of two
 * whose log2 lies in [@min_log2, @max_log2], otherwise -EINVAL.
 */
static int cmh_dt_read_geom_log2(const struct device_node *child,
				 const char *prop, u32 def_log2,
				 u32 min_log2, u32 max_log2, u32 *out_log2)
{
	u32 val;

	if (of_property_read_u32(child, prop, &val)) {
		*out_log2 = def_log2;
		return 0;
	}
	if (!is_power_of_2(val) ||
	    ilog2(val) < min_log2 || ilog2(val) > max_log2)
		return -EINVAL;
	*out_log2 = ilog2(val);
	return 0;
}

/*
 * Apply the per-mailbox rambus,cores affinity to the discovered cores.  Each
 * core ID listed on a mailbox pins that core's instance to the mailbox; a
 * core listed on no mailbox keeps mbx = -1 (round-robin across mailboxes).
 */
static int cmh_config_apply_affinity(struct cmh_config *cfg)
{
	unsigned int mi, ci, inst;

	for (mi = 0; mi < cfg->mbx_count; mi++) {
		struct cmh_mbx_config *m = &cfg->mailboxes[mi];

		for (ci = 0; ci < m->num_cores; ci++) {
			u32 core_id = m->cores[ci];
			struct cmh_core_type_cfg *ct;
			int type;

			if (core_id >= CORE_ID_NUM ||
			    core_id_to_type[core_id] < 0) {
				dev_err(cmh_dev(),
					"mbx[%u]: rambus,cores 0x%02x is not a dispatchable core\n",
					mi, core_id);
				return -EINVAL;
			}

			type = core_id_to_type[core_id];
			ct = &cfg->core_types[type];

			for (inst = 0; inst < ct->num_instances; inst++) {
				if (ct->core_ids[inst] != core_id)
					continue;
				if (ct->mbx[inst] >= 0) {
					dev_err(cmh_dev(),
						"core 0x%02x pinned to more than one mailbox\n",
						core_id);
					return -EINVAL;
				}
				ct->mbx[inst] = (s32)mi;
				break;
			}
		}
	}

#ifdef CONFIG_CRYPTO_DEV_CMH_DEBUG
	if (mbx_round_robin) {
		unsigned int t, j;

		for (t = 0; t < CMH_NUM_CORE_TYPES; t++)
			for (j = 0; j < cfg->core_types[t].num_instances; j++)
				cfg->core_types[t].mbx[j] = -1;
		dev_info(cmh_dev(),
			 "[debug] mbx_round_robin: dropped all rambus,cores affinity\n");
	}
#endif

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
 * Parse the "rambus,cmh-v1030" device tree node for MMIO base address,
 * interrupt specifiers, and per-mailbox properties (instance indices, slot counts,
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
	struct device_node *child;
	int ret;

	if (!np) {
		dev_err(&pdev->dev, "device tree node required\n");
		return -ENODEV;
	}

	/* SIC base + size from DT "reg" property (mandatory) */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(cmh_dev(), "missing DT reg resource\n");
		return -EINVAL;
	}
	cfg->sic_base = res->start;
	cfg->sic_size = resource_size(res);

	/*
	 * Interrupts are per-mailbox (declared in each mailbox child node)
	 * and resolved per MBX by cmh_rh_resolve_irqs().  There is no
	 * top-level interrupt; if no mailbox has one the response handler
	 * falls back to watchdog-timer polling.
	 */
	cfg->sic_mapped = NULL;
	cfg->fw_ready_timeout_ms = CMH_FW_READY_TIMEOUT_MS;

	/* -- Mailbox configuration from DT child nodes ----------------- */

	cfg->mbx_count = 0;
	for_each_child_of_node(np, child) {
		struct cmh_mbx_config *m;
		int nc, ci;

		if (!of_node_name_eq(child, "queue"))
			continue;

		if (cfg->mbx_count >= CMH_MAX_CONFIGURED_MBX) {
			dev_err(cmh_dev(),
				"too many mailbox nodes in DT (max %u)\n",
				CMH_MAX_CONFIGURED_MBX);
			of_node_put(child);
			return -EINVAL;
		}
		m = &cfg->mailboxes[cfg->mbx_count];

		ret = of_property_read_u32(child, "reg", &m->instance);
		if (ret) {
			dev_err(cmh_dev(), "mailbox %pOFn: missing 'reg'\n",
				child);
			of_node_put(child);
			return ret;
		}

		ret = cmh_dt_read_geom_log2(child, "rambus,num-slots",
					    CMH_DEFAULT_SLOTS_LOG2,
					    CMH_MBX_SLOTS_LOG2_MIN,
					    CMH_MBX_SLOTS_LOG2_MAX,
					    &m->slots_log2);
		if (ret) {
			dev_err(cmh_dev(),
				"mailbox %u: rambus,num-slots not power-of-2 in %u..%u\n",
				m->instance, 1U << CMH_MBX_SLOTS_LOG2_MIN,
				1U << CMH_MBX_SLOTS_LOG2_MAX);
			of_node_put(child);
			return ret;
		}

		ret = cmh_dt_read_geom_log2(child, "rambus,slot-stride-bytes",
					    CMH_DEFAULT_STRIDE_LOG2,
					    CMH_MBX_STRIDE_LOG2_MIN,
					    CMH_MBX_STRIDE_LOG2_MAX,
					    &m->stride_log2);
		if (ret) {
			dev_err(cmh_dev(),
				"mailbox %u: rambus,slot-stride-bytes not power-of-2 in %u..%u\n",
				m->instance, 1U << CMH_MBX_STRIDE_LOG2_MIN,
				1U << CMH_MBX_STRIDE_LOG2_MAX);
			of_node_put(child);
			return ret;
		}

#ifdef CONFIG_CRYPTO_DEV_CMH_DEBUG
		if (mbx_slots_override > 0)
			m->slots_log2 = mbx_slots_override;
#endif

		/* Optional per-mailbox interrupt (absent => polling). */
		m->irq = of_irq_get(child, 0);
		if (m->irq == -EPROBE_DEFER) {
			of_node_put(child);
			return -EPROBE_DEFER;
		}
		if (m->irq < 0)
			m->irq = -1;

		/* Optional rambus,cores affinity list (core-name strings). */
		m->num_cores = 0;
		nc = of_property_count_strings(child, "rambus,cores");
		if (nc > 0) {
			if (nc > CMH_NUM_CORE_TYPES) {
				dev_err(cmh_dev(),
					"mailbox %u: too many rambus,cores (%d > %u)\n",
					m->instance, nc, CMH_NUM_CORE_TYPES);
				of_node_put(child);
				return -EINVAL;
			}
			for (ci = 0; ci < nc; ci++) {
				const char *cname;
				int cid;

				of_property_read_string_index(child,
							      "rambus,cores",
							      ci, &cname);
				cid = cmh_dt_core_id(cname);
				if (cid < 0) {
					dev_err(cmh_dev(),
						"mailbox %u: unknown rambus,cores core '%s'\n",
						m->instance, cname);
					of_node_put(child);
					return -EINVAL;
				}
				m->cores[ci] = (u32)cid;
			}
			m->num_cores = nc;
		}

		m->queue_size = (1UL << m->slots_log2) << m->stride_log2;
		m->dma_handle = 0;
		m->virt_addr = NULL;
		m->reg_base = NULL;
		cfg->mbx_count++;
	}

	if (cfg->mbx_count == 0) {
		dev_err(cmh_dev(), "no mailbox child nodes in DT\n");
		return -EINVAL;
	}

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

	/*
	 * Cores are discovered later (cmh_config_discover_cores) once the
	 * SIC region is mapped and CORE_ENABLE is readable.  Here we only
	 * validate the mailbox configuration.
	 */
	return cmh_config_validate(cfg);
}

/**
 * cmh_config_discover_cores() - Enumerate cores from the CORE_ENABLE register
 * @cfg: Configuration structure (SIC must already be mapped)
 *
 * Reads the SIC CORE_ENABLE register to determine which crypto core types
 * the silicon build provides, populates cfg->core_types[], applies the
 * per-mailbox rambus,cores affinity, and validates the result.  Called after
 * the SIC ioremap.
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_config_discover_cores(struct cmh_config *cfg)
{
	u32 core_enable;
	unsigned int type;
	int ret;

	if (!cfg->sic_mapped) {
		dev_err(cmh_dev(), "discover_cores: SIC not mapped\n");
		return -EINVAL;
	}

	core_enable = cmh_reg_read32(cfg->sic_mapped, R_SIC_CORE_ENABLE);
	dev_dbg(cmh_dev(), "CORE_ENABLE=0x%08x\n", core_enable);

	for (type = 0; type < CMH_NUM_CORE_TYPES; type++) {
		const struct cmh_core_desc *d = &cmh_core_descs[type];
		struct cmh_core_type_cfg *ct = &cfg->core_types[type];

		if (!d->enable_mask)
			continue;
		if (!cmh_core_enabled(core_enable, d->enable_mask))
			continue;

		ct->core_ids[0] = d->core_id;
		ct->mbx[0] = -1;
		ct->num_instances = 1;
		dev_dbg(cmh_dev(), "core %s (0x%02x) present\n",
			core_type_names[type], d->core_id);
	}

	ret = cmh_config_apply_affinity(cfg);
	if (ret)
		return ret;

	return cmh_config_validate_core_types(cfg);
}
