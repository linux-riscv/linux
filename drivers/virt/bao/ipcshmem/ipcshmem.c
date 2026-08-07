// SPDX-License-Identifier: GPL-2.0
/*
 * Bao Hypervisor IPC Through Shared-memory Driver
 *
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 */

#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/of.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <asm/bao.h>

#define BAO_IPCSHMEM_NAME_LEN 16

struct bao_ipcshmem {
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

static int bao_ipcshmem_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct bao_ipcshmem *bao = filp->private_data;
	unsigned long vsize = vma->vm_end - vma->vm_start;
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	phys_addr_t region_phys;
	size_t region_size;

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
	} else if (offset < bao->read_size + bao->write_size) {
		offset -= bao->read_size;
		region_phys = bao->write_phys;
		region_size = bao->write_size;
	} else {
		return -EINVAL;
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
};

static int bao_ipcshmem_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	struct resource *read_res;
	struct resource *write_res;
	struct bao_ipcshmem *bao;
	u32 id;
	int ret;

	read_res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "read");
	if (!read_res) {
		dev_err(dev, "missing 'read' shared memory region\n");
		return -ENODEV;
	}

	write_res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "write");
	if (!write_res) {
		dev_err(dev, "missing 'write' shared memory region\n");
		return -ENODEV;
	}

	ret = of_property_read_u32(np, "bao,id", &id);
	if (ret) {
		dev_err(dev, "missing or invalid 'bao,id' property\n");
		return ret;
	}

	bao = devm_kzalloc(dev, sizeof(*bao), GFP_KERNEL);
	if (!bao)
		return -ENOMEM;

	bao->read_base = devm_memremap(dev, read_res->start,
				       resource_size(read_res), MEMREMAP_WB);
	if (IS_ERR(bao->read_base))
		return PTR_ERR(bao->read_base);

	bao->write_base = devm_memremap(dev, write_res->start,
					resource_size(write_res), MEMREMAP_WB);
	if (IS_ERR(bao->write_base))
		return PTR_ERR(bao->write_base);

	bao->id = id;
	bao->read_phys = read_res->start;
	bao->read_size = resource_size(read_res);
	bao->write_phys = write_res->start;
	bao->write_size = resource_size(write_res);

	scnprintf(bao->label, BAO_IPCSHMEM_NAME_LEN, "baoipc%u", id);

	bao->miscdev.minor = MISC_DYNAMIC_MINOR;
	bao->miscdev.name = bao->label;
	bao->miscdev.fops = &bao_ipcshmem_fops;
	bao->miscdev.parent = dev;

	ret = misc_register(&bao->miscdev);
	if (ret) {
		dev_err(dev, "failed to register misc device: %d\n", ret);
		return ret;
	}

	platform_set_drvdata(pdev, bao);

	return 0;
}

static void bao_ipcshmem_remove(struct platform_device *pdev)
{
	struct bao_ipcshmem *bao = platform_get_drvdata(pdev);

	misc_deregister(&bao->miscdev);
}

static const struct of_device_id of_bao_ipcshmem_match[] = {
	{ .compatible = "bao,ipcshmem" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, of_bao_ipcshmem_match);

static struct platform_driver bao_ipcshmem_driver = {
	.probe = bao_ipcshmem_probe,
	.remove = bao_ipcshmem_remove,
	.driver = {
		.name = "baoipc",
		.of_match_table = of_bao_ipcshmem_match,
	},
};

module_platform_driver(bao_ipcshmem_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("David Cerdeira <davidmcerdeira@osyx.tech>");
MODULE_AUTHOR("José Martins <jose@osyx.tech>");
MODULE_AUTHOR("João Peixoto <jpeixoto@osyx.tech>");
MODULE_DESCRIPTION("Bao Hypervisor IPC Through Shared-memory Driver");
