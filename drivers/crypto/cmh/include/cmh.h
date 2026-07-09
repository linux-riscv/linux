/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Top-level Device Structure
 */

#ifndef CMH_H
#define CMH_H

#include <linux/device.h>

#include "cmh_config.h"

#define CMH_DRV_NAME   "cmh"
#define CMH_VERSION    "1.0.0"

/**
 * struct cmh_device - Top-level driver state for a CMH hardware instance
 * @config: Hardware configuration (core mappings, MBX layout, feature flags)
 * @dev:    Platform or parent device used for DMA and logging
 */
struct cmh_device {
	struct cmh_config       config;
	struct device          *dev;
};

#endif /* CMH_H */
