// SPDX-License-Identifier: GPL-2.0
/*
 * Bao Hypervisor IPC Through Shared-memory Driver
 *
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 *
 * The IPC shared-memory channels are a pure software contract between the Bao
 * hypervisor and its guests, so they are not described in the device tree.
 * Each channel is instead declared on the kernel command line:
 *
 *   bao_ipcshmem.channels=<channel>[;<channel>...]
 *
 * where each <channel> is
 *
 *   <id>,<read_base>,<read_size>,<write_base>,<write_size>
 *
 * Addresses and sizes are parsed with kstrtoull() (so "0x" hex is accepted)
 * and must be page-aligned.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/io.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/wordpart.h>
#include "../bao_hypercall.h"

/* "baoipc" + up to 10 digits of a u32 + NUL. */
#define BAO_IPCSHMEM_NAME_LEN 24

static char *channels;
module_param(channels, charp, 0444);
MODULE_PARM_DESC(channels,
		 "Bao IPC channels: <id>,<read_base>,<read_size>,<write_base>,<write_size>[;...]");

/**
 * struct bao_ipcshmem - a single Bao IPC shared-memory channel
 * @list: entry in the global channel list
 * @miscdev: character device exposing the channel to userspace
 * @id: hypervisor-assigned channel identifier, passed to the notify hypercall
 * @label: backing storage for @miscdev.name
 * @read_base: kernel mapping of the region this guest reads from
 * @read_phys: physical base of the read region
 * @read_size: size of the read region
 * @write_base: kernel mapping of the region this guest writes to
 * @write_phys: physical base of the write region
 * @write_size: size of the write region
 */
struct bao_ipcshmem {
	struct list_head list;
	struct miscdevice miscdev;
	u32 id;
	char label[BAO_IPCSHMEM_NAME_LEN];
	void *read_base;
	phys_addr_t read_phys;
	size_t read_size;
	void *write_base;
	phys_addr_t write_phys;
	size_t write_size;
};

static LIST_HEAD(bao_ipcshmem_devices);

static int bao_ipcshmem_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct bao_ipcshmem *bao = filp->private_data;
	unsigned long vsize = vma->vm_end - vma->vm_start;
	u64 offset = (u64)vma->vm_pgoff << PAGE_SHIFT;
	phys_addr_t region_phys;
	size_t region_size;
	bool read_region;

	if (!vsize)
		return -EINVAL;

	/*
	 * The read region is exposed at offset 0 and the write region right
	 * after it. A single mapping cannot span both regions, since they are
	 * not guaranteed to be physically contiguous.
	 */
	if (offset < bao->read_size) {
		region_phys = bao->read_phys;
		region_size = bao->read_size;
		read_region = true;
	} else if (offset < (u64)bao->read_size + bao->write_size) {
		offset -= bao->read_size;
		region_phys = bao->write_phys;
		region_size = bao->write_size;
		read_region = false;
	} else {
		return -EINVAL;
	}

	/*
	 * The read region is written by the peer and is read-only for this
	 * guest; the hypervisor maps it read-only at stage 2, so refuse a
	 * writable mapping rather than let userspace take a stage-2 fault,
	 * and make sure a later mprotect(PROT_WRITE) cannot re-enable it.
	 */
	if (read_region) {
		if (vma->vm_flags & VM_WRITE)
			return -EACCES;
		vm_flags_clear(vma, VM_MAYWRITE);
	}

	if (vsize > region_size - offset)
		return -EINVAL;

	region_phys += offset;
	if (!PAGE_ALIGNED(region_phys))
		return -EINVAL;

	return remap_pfn_range(vma, vma->vm_start, region_phys >> PAGE_SHIFT,
			       vsize, vma->vm_page_prot);
}

static ssize_t bao_ipcshmem_read(struct file *filp, char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct bao_ipcshmem *bao = filp->private_data;
	size_t available;

	if (*ppos >= bao->read_size)
		return 0;

	available = bao->read_size - *ppos;
	count = min(count, available);

	if (copy_to_user(buf, bao->read_base + *ppos, count))
		return -EFAULT;

	*ppos += count;
	return count;
}

static ssize_t bao_ipcshmem_write(struct file *filp, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	struct bao_ipcshmem *bao = filp->private_data;
	size_t available;

	if (*ppos >= bao->write_size)
		return 0;

	available = bao->write_size - *ppos;
	count = min(count, available);

	if (copy_from_user(bao->write_base + *ppos, buf, count))
		return -EFAULT;

	*ppos += count;

	/*
	 * Ensure the data written above is globally visible before the
	 * hypercall notifies the peer guest (SMCCC requires the caller to make
	 * memory updates visible before the SMC/HVC).
	 */
	wmb();

	/* Notify Bao hypervisor */
	bao_ipcshmem_hypercall(bao->id);

	return count;
}

static int bao_ipcshmem_open(struct inode *inode, struct file *filp)
{
	struct bao_ipcshmem *bao;

	bao = container_of(filp->private_data, struct bao_ipcshmem, miscdev);
	filp->private_data = bao;

	return 0;
}

static int bao_ipcshmem_release(struct inode *inode, struct file *filp)
{
	filp->private_data = NULL;
	return 0;
}

static const struct file_operations bao_ipcshmem_fops = {
	.owner = THIS_MODULE,
	.read = bao_ipcshmem_read,
	.write = bao_ipcshmem_write,
	.mmap = bao_ipcshmem_mmap,
	.open = bao_ipcshmem_open,
	.release = bao_ipcshmem_release,
	.llseek = default_llseek,
};

static void bao_ipcshmem_free(struct bao_ipcshmem *bao)
{
	if (bao->write_base)
		memunmap(bao->write_base);
	if (bao->read_base)
		memunmap(bao->read_base);
	kfree(bao);
}

/*
 * A region must be non-empty and page-aligned, must not wrap around and must
 * be addressable on this architecture (the command line values are 64-bit).
 */
static bool bao_ipcshmem_region_valid(u64 base, u64 size)
{
	u64 end;

	if (!size || !PAGE_ALIGNED(base) || !PAGE_ALIGNED(size))
		return false;

	end = base + size - 1;
	if (end < base)
		return false;

	if (sizeof(phys_addr_t) < sizeof(u64) && upper_32_bits(end))
		return false;

	if (sizeof(size_t) < sizeof(u64) && upper_32_bits(size))
		return false;

	return true;
}

static int bao_ipcshmem_add(u32 id, u64 read_base, u64 read_size,
			    u64 write_base, u64 write_size)
{
	struct bao_ipcshmem *bao;
	int ret;

	if (!bao_ipcshmem_region_valid(read_base, read_size) ||
	    !bao_ipcshmem_region_valid(write_base, write_size)) {
		pr_err("channel %u: invalid region\n", id);
		return -EINVAL;
	}

	bao = kzalloc(sizeof(*bao), GFP_KERNEL);
	if (!bao)
		return -ENOMEM;

	bao->id = id;
	bao->read_phys = read_base;
	bao->read_size = read_size;
	bao->write_phys = write_base;
	bao->write_size = write_size;

	bao->read_base = memremap(bao->read_phys, bao->read_size, MEMREMAP_WB);
	if (!bao->read_base) {
		ret = -ENOMEM;
		goto err_free;
	}

	bao->write_base = memremap(bao->write_phys, bao->write_size,
				   MEMREMAP_WB);
	if (!bao->write_base) {
		ret = -ENOMEM;
		goto err_free;
	}

	scnprintf(bao->label, sizeof(bao->label), "baoipc%u", id);
	bao->miscdev.minor = MISC_DYNAMIC_MINOR;
	bao->miscdev.name = bao->label;
	bao->miscdev.fops = &bao_ipcshmem_fops;

	ret = misc_register(&bao->miscdev);
	if (ret) {
		pr_err("channel %u: misc_register failed: %d\n", id, ret);
		goto err_free;
	}

	list_add_tail(&bao->list, &bao_ipcshmem_devices);
	return 0;

err_free:
	bao_ipcshmem_free(bao);
	return ret;
}

static void bao_ipcshmem_remove_all(void)
{
	struct bao_ipcshmem *bao, *tmp;

	list_for_each_entry_safe(bao, tmp, &bao_ipcshmem_devices, list) {
		list_del(&bao->list);
		misc_deregister(&bao->miscdev);
		bao_ipcshmem_free(bao);
	}
}

/* Parse one "<id>,<rbase>,<rsize>,<wbase>,<wsize>" channel descriptor. */
static int bao_ipcshmem_parse_one(char *desc)
{
	u64 vals[4];
	char *tok;
	u32 id;
	int i;

	tok = strsep(&desc, ",");
	if (!tok || kstrtou32(tok, 0, &id))
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(vals); i++) {
		tok = strsep(&desc, ",");
		if (!tok || kstrtoull(tok, 0, &vals[i]))
			return -EINVAL;
	}

	if (desc && *desc)
		return -EINVAL;

	return bao_ipcshmem_add(id, vals[0], vals[1], vals[2], vals[3]);
}

static int __init bao_ipcshmem_init(void)
{
	char *buf, *p, *desc;
	int ret = 0;

	if (!channels || !*channels)
		return 0;

	buf = kstrdup(channels, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	p = buf;
	while ((desc = strsep(&p, ";")) != NULL) {
		if (!*desc)
			continue;
		ret = bao_ipcshmem_parse_one(desc);
		if (ret) {
			pr_err("bad 'channels' descriptor\n");
			bao_ipcshmem_remove_all();
			break;
		}
	}

	kfree(buf);
	return ret;
}

static void __exit bao_ipcshmem_exit(void)
{
	bao_ipcshmem_remove_all();
}

module_init(bao_ipcshmem_init);
module_exit(bao_ipcshmem_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("David Cerdeira <davidmcerdeira@osyx.tech>");
MODULE_AUTHOR("José Martins <jose@osyx.tech>");
MODULE_AUTHOR("João Peixoto <jpeixoto@osyx.tech>");
MODULE_DESCRIPTION("Bao Hypervisor IPC Through Shared-memory Driver");
