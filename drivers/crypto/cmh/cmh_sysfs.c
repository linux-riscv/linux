// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- sysfs Device Attributes
 *
 * Exposes hardware identity and status as read-only sysfs attributes
 * under /sys/devices/platform/cmh/.  Wired via .dev_groups in the
 * platform_driver struct -- the driver core creates and removes these
 * automatically around .probe() / .remove().
 *
 * Because .dev_groups is used (not manual sysfs_create_group), the
 * driver core guarantees that attributes are created after .probe()
 * sets drvdata and removed before .remove() clears it.  Therefore
 * platform_get_drvdata() cannot return NULL in any show callback and
 * no NULL check is needed.  Same pattern as caam/ctrl.c and
 * ccree/cc_sysfs.c.
 */

#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/sysfs.h>

#include "cmh.h"
#include "cmh_registers.h"
#include "cmh_sysfs.h"

static ssize_t fw_version_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct cmh_device *cmh = platform_get_drvdata(to_platform_device(dev));
	struct cmh_config *cfg = &cmh->config;

	if (!cfg->sic_mapped)
		return -ENODEV;

	return sysfs_emit(buf, "0x%08x\n",
			  cmh_reg_read32(cfg->sic_mapped, R_SIC_SW_VERSION));
}
static DEVICE_ATTR_RO(fw_version);

static ssize_t hw_version_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct cmh_device *cmh = platform_get_drvdata(to_platform_device(dev));
	struct cmh_config *cfg = &cmh->config;

	if (!cfg->sic_mapped)
		return -ENODEV;

	return sysfs_emit(buf, "0x%08x\n",
			  cmh_reg_read32(cfg->sic_mapped, R_SIC_HW_VERSION0));
}
static DEVICE_ATTR_RO(hw_version);

static ssize_t boot_status_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct cmh_device *cmh = platform_get_drvdata(to_platform_device(dev));
	struct cmh_config *cfg = &cmh->config;

	if (!cfg->sic_mapped)
		return -ENODEV;

	return sysfs_emit(buf, "0x%08x\n",
			  cmh_reg_read32(cfg->sic_mapped, R_SIC_BOOT_STATUS));
}
static DEVICE_ATTR_RO(boot_status);

static ssize_t mbx_available_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct cmh_device *cmh = platform_get_drvdata(to_platform_device(dev));
	struct cmh_config *cfg = &cmh->config;

	if (!cfg->sic_mapped)
		return -ENODEV;

	return sysfs_emit(buf, "0x%08x\n",
			  cmh_reg_read32(cfg->sic_mapped, R_SIC_MBX_AVAILABILITY));
}
static DEVICE_ATTR_RO(mbx_available);

static ssize_t mbx_count_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	struct cmh_device *cmh = platform_get_drvdata(to_platform_device(dev));

	return sysfs_emit(buf, "%u\n", cmh->config.mbx_count);
}
static DEVICE_ATTR_RO(mbx_count);

static struct attribute *cmh_sysfs_attrs[] = {
	&dev_attr_fw_version.attr,
	&dev_attr_hw_version.attr,
	&dev_attr_boot_status.attr,
	&dev_attr_mbx_available.attr,
	&dev_attr_mbx_count.attr,
	NULL,
};

static const struct attribute_group cmh_sysfs_group = {
	.attrs = cmh_sysfs_attrs,
};

const struct attribute_group *cmh_sysfs_groups[] = {
	&cmh_sysfs_group,
	NULL,
};
