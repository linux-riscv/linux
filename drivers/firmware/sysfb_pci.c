// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/pci.h>

#include "sysfb.h"

bool sysfb_pci_dev_is_enabled(struct pci_dev *pdev)
{
	/*
	 * TODO: Try to integrate this code into the PCI subsystem
	 */
	int ret;
	u16 command;

	ret = pci_read_config_word(pdev, PCI_COMMAND, &command);
	if (ret != PCIBIOS_SUCCESSFUL)
		return false;
	if (!(command & PCI_COMMAND_MEMORY))
		return false;
	return true;
}
