/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Configuration Structures and Defaults
 */

#ifndef CMH_CONFIG_H
#define CMH_CONFIG_H

#include <linux/types.h>
#include <linux/dma-mapping.h>

#include "cmh_registers.h"
#include "cmh_vcq.h"

/* Limits */

/*
 * Max mailboxes the driver manages simultaneously.  The hardware address
 * space supports CMH_MAX_MBX_INSTANCES (64) instance indices, but this
 * compile-time constant caps how many the driver allocates DMA queues,
 * IRQ slots, and per-transform cache entries for.  To manage more
 * mailboxes (up to the HW max), increase this value and rebuild the LKM
 * -- it cannot be changed via module parameters at runtime.
 */
#define CMH_MAX_CONFIGURED_MBX    16
#define CMH_MAX_CORE_INSTANCES    8

/* MBX setup parameter ranges (per CMH hardware specification) */
#define CMH_MBX_SLOTS_LOG2_MIN        1
#define CMH_MBX_SLOTS_LOG2_MAX        15
#define CMH_MBX_STRIDE_LOG2_MIN       7
#define CMH_MBX_STRIDE_LOG2_MAX       10

/* Default Configuration Values */

#define CMH_DEFAULT_MBX_COUNT         2
#define CMH_DEFAULT_SLOTS_LOG2        5   /* 2^5 = 32 slots */
#define CMH_DEFAULT_STRIDE_LOG2       7   /* 2^7 = 128 bytes per slot */
#define CMH_DEFAULT_IRQ               (-1) /* polling mode */
#define CMH_DEFAULT_FW_READY_TIMEOUT_MS  5000 /* 5s for mission mode */

/* Per-Core-Type Instance Configuration */

struct cmh_core_type_cfg {
	u32	num_instances;
	u32	core_ids[CMH_MAX_CORE_INSTANCES];
	s32	mbx[CMH_MAX_CORE_INSTANCES]; /* -1 = auto-assign */
};

/* Per-Mailbox Configuration */

struct cmh_mbx_config {
	u32             instance;       /* 0-based MBX instance index (0..63) */
	u32             slots_log2;     /* log2(slot count), range 1..15 */
	u32             stride_log2;    /* log2(bytes per slot), range 7..10 */
	u32             lock_val;       /* MBX lock token (non-zero while held) */
	dma_addr_t      dma_handle;     /* DMA bus address from dma_alloc_coherent */
	void           *virt_addr;      /* kernel virtual address of MBXQ buffer */
	size_t          queue_size;     /* total queue buffer size in bytes */
	void __iomem   *reg_base;       /* ioremap'd register base for this instance */
};

/* Global Device Configuration */

struct cmh_config {
	phys_addr_t                 sic_base;
	size_t                      sic_size;
	void __iomem               *sic_mapped;    /* ioremap'd SIC region */
	struct device_node         *of_node;       /* DT node (may be NULL) */
	u32                         mbx_count;
	struct cmh_mbx_config       mailboxes[CMH_MAX_CONFIGURED_MBX];
	int                         irq;           /* -1 = poll, else IRQ line */
	unsigned int                fw_ready_timeout_ms; /* FW mission-mode timeout */
	struct cmh_core_type_cfg    core_types[CMH_NUM_CORE_TYPES];
};

/* Module Parameter Interface */

struct platform_device;

/**
 * cmh_config_init() - Populate config from module params and device-tree
 * @cfg: Configuration structure to fill
 * @pdev: Platform device (for DT properties and IRQ lookup)
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_config_init(struct cmh_config *cfg, struct platform_device *pdev);

#endif /* CMH_CONFIG_H */
