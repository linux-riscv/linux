/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * phy-provider.h -- Generic PHY properties
 *
 * Copyright (C) 2013 Texas Instruments Incorporated - http://www.ti.com
 *
 * Author: Kishon Vijay Abraham I <kishon@ti.com>
 */
#ifndef __PHY_PROPS_H
#define __PHY_PROPS_H

#include <linux/phy/phy-dp.h>
#include <linux/phy/phy-hdmi.h>
#include <linux/phy/phy-lvds.h>
#include <linux/phy/phy-mipi-dphy.h>

enum phy_mode {
	PHY_MODE_INVALID,
	PHY_MODE_USB_HOST,
	PHY_MODE_USB_HOST_LS,
	PHY_MODE_USB_HOST_FS,
	PHY_MODE_USB_HOST_HS,
	PHY_MODE_USB_HOST_SS,
	PHY_MODE_USB_DEVICE,
	PHY_MODE_USB_DEVICE_LS,
	PHY_MODE_USB_DEVICE_FS,
	PHY_MODE_USB_DEVICE_HS,
	PHY_MODE_USB_DEVICE_SS,
	PHY_MODE_USB_OTG,
	PHY_MODE_UFS_HS_A,
	PHY_MODE_UFS_HS_B,
	PHY_MODE_PCIE,
	PHY_MODE_ETHERNET,
	PHY_MODE_MIPI_DPHY,
	PHY_MODE_SATA,
	PHY_MODE_LVDS,
	PHY_MODE_DP,
	PHY_MODE_HDMI,
};

enum phy_media {
	PHY_MEDIA_DEFAULT,
	PHY_MEDIA_SR,
	PHY_MEDIA_DAC,
};

enum phy_ufs_state {
	PHY_UFS_HIBERN8_ENTER,
	PHY_UFS_HIBERN8_EXIT,
};

union phy_notify {
	enum phy_ufs_state ufs_state;
};

/**
 * union phy_configure_opts - Opaque generic phy configuration
 *
 * @mipi_dphy:	Configuration set applicable for phys supporting
 *		the MIPI_DPHY phy mode.
 * @dp:		Configuration set applicable for phys supporting
 *		the DisplayPort protocol.
 * @lvds:	Configuration set applicable for phys supporting
 *		the LVDS phy mode.
 * @hdmi:	Configuration set applicable for phys supporting
 *		the HDMI phy mode.
 */
union phy_configure_opts {
	struct phy_configure_opts_mipi_dphy	mipi_dphy;
	struct phy_configure_opts_dp		dp;
	struct phy_configure_opts_lvds		lvds;
	struct phy_configure_opts_hdmi		hdmi;
};

#endif /* __PHY_PROPS_H */
