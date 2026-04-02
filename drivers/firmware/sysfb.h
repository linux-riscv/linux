/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef FIRMWARE_SYSFB_H
#define FIRMWARE_SYSFB_H

#include <linux/types.h>

struct pci_dev;

#ifdef CONFIG_PCI
int sysfb_apply_screen_info_fixups(void);
bool sysfb_pci_dev_is_enabled(struct pci_dev *pdev);
#else
static inline int sysfb_apply_screen_info_fixups(void)
{
	return 0;
}
static inline bool sysfb_pci_dev_is_enabled(struct pci_dev *pdev)
{
	return false;
}
#endif

#endif
