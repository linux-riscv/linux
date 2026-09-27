// SPDX-License-Identifier: GPL-2.0
/*
 * Bao Hypervisor I/O Dispatcher Kernel Driver
 *
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 *
 * Authors:
 *	João Peixoto <jpeixoto@osyx.tech>
 *	José Martins <jose@osyx.tech>
 *	David Cerdeira <davidmcerdeira@osyx.tech>
 *
 * The set of device models a backend guest serves is a pure software contract
 * between the Bao hypervisor and its userspace VMM, so it is not described in
 * the device tree. Following the model used by other hypervisor drivers (e.g.
 * drivers/virt/acrn), the driver exposes a single /dev/bao control device and
 * the VMM instantiates each device model from its own configuration through the
 * BAO_IOCTL_CREATE_DM ioctl, which returns a per-DM file descriptor.
 */

#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include "bao_drv.h"

static long bao_ctl_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long arg)
{
	struct bao_dm_info info;

	switch (cmd) {
	case BAO_IOCTL_CREATE_DM:
		if (copy_from_user(&info, (void __user *)arg, sizeof(info)))
			return -EFAULT;

		return bao_dm_create_fd(&info);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations bao_ctl_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = bao_ctl_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice bao_ctl_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "bao",
	.fops = &bao_ctl_fops,
};

static int __init bao_io_dispatcher_driver_init(void)
{
	return misc_register(&bao_ctl_dev);
}

static void __exit bao_io_dispatcher_driver_exit(void)
{
	misc_deregister(&bao_ctl_dev);
}

module_init(bao_io_dispatcher_driver_init);
module_exit(bao_io_dispatcher_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("João Peixoto <jpeixoto@osyx.tech>");
MODULE_AUTHOR("David Cerdeira <davidmcerdeira@osyx.tech>");
MODULE_AUTHOR("José Martins <jose@osyx.tech>");
MODULE_DESCRIPTION("Bao Hypervisor I/O Dispatcher Kernel Driver");
