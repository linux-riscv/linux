/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * phy.h -- Generic PHY consumer API
 *
 * Copyright (C) 2013 Texas Instruments Incorporated - http://www.ti.com
 *
 * Author: Kishon Vijay Abraham I <kishon@ti.com>
 */

#ifndef __PHY_CONSUMER_H
#define __PHY_CONSUMER_H

#include <linux/phy/phy-props.h>

#include "../../../drivers/phy/phy-provider.h"

struct device;
struct device_node;
struct phy;

#if IS_ENABLED(CONFIG_GENERIC_PHY)
struct phy *phy_get(struct device *dev, const char *string);
struct phy *devm_phy_get(struct device *dev, const char *string);
struct phy *devm_phy_optional_get(struct device *dev, const char *string);
struct phy *devm_of_phy_get(struct device *dev, struct device_node *np,
			    const char *con_id);
struct phy *devm_of_phy_optional_get(struct device *dev, struct device_node *np,
				     const char *con_id);
struct phy *devm_of_phy_get_by_index(struct device *dev, struct device_node *np,
				     int index);
void of_phy_put(struct phy *phy);
void phy_put(struct device *dev, struct phy *phy);
void devm_phy_put(struct device *dev, struct phy *phy);
struct phy *of_phy_get(struct device_node *np, const char *con_id);

int phy_pm_runtime_get(struct phy *phy);
int phy_pm_runtime_get_sync(struct phy *phy);
void phy_pm_runtime_put(struct phy *phy);
int phy_pm_runtime_put_sync(struct phy *phy);
int phy_init(struct phy *phy);
int phy_exit(struct phy *phy);
int phy_power_on(struct phy *phy);
int phy_power_off(struct phy *phy);
int phy_set_mode_ext(struct phy *phy, enum phy_mode mode, int submode);
#define phy_set_mode(phy, mode) \
	phy_set_mode_ext(phy, mode, 0)
int phy_set_media(struct phy *phy, enum phy_media media);
int phy_set_speed(struct phy *phy, int speed);
int phy_configure(struct phy *phy, union phy_configure_opts *opts);
int phy_validate(struct phy *phy, enum phy_mode mode, int submode,
		 union phy_configure_opts *opts);
enum phy_mode phy_get_mode(struct phy *phy);
int phy_reset(struct phy *phy);
int phy_calibrate(struct phy *phy);
int phy_notify_connect(struct phy *phy, int port);
int phy_notify_disconnect(struct phy *phy, int port);
int phy_notify_state(struct phy *phy, union phy_notify state);
int phy_get_bus_width(struct phy *phy);
void phy_set_bus_width(struct phy *phy, int bus_width);
u32 phy_get_max_link_rate(struct phy *phy);
#else
static inline struct phy *phy_get(struct device *dev, const char *string)
{
	return ERR_PTR(-ENOSYS);
}

static inline struct phy *devm_phy_get(struct device *dev, const char *string)
{
	return ERR_PTR(-ENOSYS);
}

static inline struct phy *devm_phy_optional_get(struct device *dev,
						const char *string)
{
	return NULL;
}

static inline struct phy *devm_of_phy_get(struct device *dev,
					  struct device_node *np,
					  const char *con_id)
{
	return ERR_PTR(-ENOSYS);
}

static inline struct phy *devm_of_phy_optional_get(struct device *dev,
						   struct device_node *np,
						   const char *con_id)
{
	return NULL;
}

static inline struct phy *devm_of_phy_get_by_index(struct device *dev,
						   struct device_node *np,
						   int index)
{
	return ERR_PTR(-ENOSYS);
}

static inline void of_phy_put(struct phy *phy)
{
}

static inline void phy_put(struct device *dev, struct phy *phy)
{
}

static inline void devm_phy_put(struct device *dev, struct phy *phy)
{
}

static inline struct phy *of_phy_get(struct device_node *np, const char *con_id)
{
	return ERR_PTR(-ENOSYS);
}

static inline int phy_pm_runtime_get(struct phy *phy)
{
	if (!phy)
		return 0;
	return -ENOSYS;
}

static inline int phy_pm_runtime_get_sync(struct phy *phy)
{
	if (!phy)
		return 0;
	return -ENOSYS;
}

static inline void phy_pm_runtime_put(struct phy *phy)
{
}

static inline int phy_pm_runtime_put_sync(struct phy *phy)
{
	if (!phy)
		return 0;
	return -ENOSYS;
}

static inline int phy_init(struct phy *phy)
{
	if (!phy)
		return 0;
	return -ENOSYS;
}

static inline int phy_exit(struct phy *phy)
{
	if (!phy)
		return 0;
	return -ENOSYS;
}

static inline int phy_power_on(struct phy *phy)
{
	if (!phy)
		return 0;
	return -ENOSYS;
}

static inline int phy_power_off(struct phy *phy)
{
	if (!phy)
		return 0;
	return -ENOSYS;
}

static inline int phy_set_mode_ext(struct phy *phy, enum phy_mode mode,
				   int submode)
{
	if (!phy)
		return 0;
	return -ENOSYS;
}

#define phy_set_mode(phy, mode) \
	phy_set_mode_ext(phy, mode, 0)

static inline int phy_set_media(struct phy *phy, enum phy_media media)
{
	if (!phy)
		return 0;
	return -ENODEV;
}

static inline int phy_set_speed(struct phy *phy, int speed)
{
	if (!phy)
		return 0;
	return -ENODEV;
}

static inline int phy_configure(struct phy *phy,
				union phy_configure_opts *opts)
{
	if (!phy)
		return 0;
	return -ENOSYS;
}

static inline int phy_validate(struct phy *phy, enum phy_mode mode, int submode,
			       union phy_configure_opts *opts)
{
	if (!phy)
		return 0;
	return -ENOSYS;
}

static inline enum phy_mode phy_get_mode(struct phy *phy)
{
	return PHY_MODE_INVALID;
}

static inline int phy_reset(struct phy *phy)
{
	if (!phy)
		return 0;
	return -ENOSYS;
}

static inline int phy_calibrate(struct phy *phy)
{
	if (!phy)
		return 0;
	return -ENOSYS;
}

static inline int phy_notify_connect(struct phy *phy, int index)
{
	if (!phy)
		return 0;
	return -ENOSYS;
}

static inline int phy_notify_disconnect(struct phy *phy, int index)
{
	if (!phy)
		return 0;
	return -ENOSYS;
}

static inline int phy_notify_state(struct phy *phy, union phy_notify state)
{
	if (!phy)
		return 0;
	return -ENOSYS;
}

static inline int phy_get_bus_width(struct phy *phy)
{
	if (!phy)
		return 0;
	return -ENOSYS;
}

static inline void phy_set_bus_width(struct phy *phy, int bus_width)
{
}

static inline u32 phy_get_max_link_rate(struct phy *phy)
{
	return 0;
}
#endif /* IS_ENABLED(CONFIG_GENERIC_PHY) */

#endif /* __PHY_CONSUMER_H */
