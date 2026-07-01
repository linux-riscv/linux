// SPDX-License-Identifier: GPL-2.0-only
/*
 * Debug helper used to dump the gstage pagetables of the system.
 */
#include <linux/debugfs.h>
#include <linux/kvm_host.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <asm/ptdump.h>
#include <asm/pgtable.h>

static const struct ptdump_prot_bits gstage_pte_bits[] = {
	{
		.mask = _PAGE_SOFT,
		.set = "RSW(%d)",
		.clear = "  ..  ",
	}, {
		.mask = _PAGE_DIRTY,
		.set = "D",
		.clear = ".",
	}, {
		.mask = _PAGE_ACCESSED,
		.set = "A",
		.clear = ".",
	}, {
		.mask = _PAGE_USER,
		.set = "U",
		.clear = ".",
	}, {
		.mask = _PAGE_EXEC,
		.set = "X",
		.clear = ".",
	}, {
		.mask = _PAGE_WRITE,
		.set = "W",
		.clear = ".",
	}, {
		.mask = _PAGE_READ,
		.set = "R",
		.clear = ".",
	}, {
		.mask = _PAGE_PRESENT,
		.set = "V",
		.clear = ".",
	}
};

static struct ptdump_pg_level gstage_pg_levels[] = {
	{ .name = "PGD" },
	{ .name = "P4D" },
	{ .name = "PUD" },
	{ .name = "PMD" },
	{ .name = "PTE" },
};

struct kvm_ptdump_state {
	struct kvm *kvm;
	struct ptdump_pg_state parser_state;
	struct addr_marker marker[2];
	struct ptdump_range range[2];
};

static void kvm_ptdump_walk_level(struct ptdump_state *pt_st,
				  unsigned long *tbl, int level,
				  unsigned long start_addr)
{
	unsigned long addr = start_addr;
	unsigned long next, virt_addr;
	int i;
	unsigned long step = 1UL << (PAGE_SHIFT + (4 - level) * 9);

	for (i = 0; i < PTRS_PER_PTE; i++, addr += step) {
		unsigned long val = tbl[i];

		next = addr + step;

		if (level == 4 || (val & _PAGE_LEAF) || !(val & _PAGE_PRESENT)) {
			note_page(pt_st, addr, level, val);
		} else {
			unsigned long pa = (val >> _PAGE_PFN_SHIFT) << PAGE_SHIFT;

			virt_addr = (unsigned long)phys_to_virt(pa);

			kvm_ptdump_walk_level(pt_st, (unsigned long *)virt_addr,
					      level + 1, addr);
		}
	}
}

static int kvm_ptdump_visitor(struct seq_file *m, void *v)
{
	struct kvm_ptdump_state *st = m->private;
	struct kvm *kvm = st->kvm;
	unsigned long *pgd = (unsigned long *)kvm->arch.pgd;
	int start_level = 5 - kvm->arch.pgd_levels;
	int i, j;

	st->parser_state.level = -1;
	st->parser_state.start_address = 0;
	st->parser_state.seq = m;

	for (i = 0; i < ARRAY_SIZE(gstage_pg_levels); i++) {
		gstage_pg_levels[i].bits = gstage_pte_bits;
		gstage_pg_levels[i].num = ARRAY_SIZE(gstage_pte_bits);
		gstage_pg_levels[i].mask = 0;
		for (j = 0; j < ARRAY_SIZE(gstage_pte_bits); j++)
			gstage_pg_levels[i].mask |= gstage_pte_bits[j].mask;
	}

	read_lock(&kvm->mmu_lock);
	if (pgd) {
		kvm_ptdump_walk_level(&st->parser_state.ptdump, pgd,
			start_level, 0);
	}
	read_unlock(&kvm->mmu_lock);

	note_page(&st->parser_state.ptdump, 0, -1, 0);
	return 0;
}

static int kvm_ptdump_open(struct inode *inode, struct file *file)
{
	struct kvm *kvm = inode->i_private;
	struct kvm_ptdump_state *st;
	int ret;

	if (!kvm_get_kvm_safe(kvm))
		return -ENOENT;

	st = kzalloc(sizeof(*st), GFP_KERNEL);
	if (!st) {
		kvm_put_kvm(kvm);
		return -ENOMEM;
	}

	st->kvm = kvm;
	st->marker[0].name = "Guest IPA";
	st->marker[0].start_address = 0;
	st->marker[1].start_address = -1UL;
	st->range[0].start = 0;
	st->range[0].end = -1UL;

	st->parser_state.marker = st->marker;
	st->parser_state.pg_level = gstage_pg_levels;
	st->parser_state.ptdump.range = st->range;

	ret = single_open(file, kvm_ptdump_visitor, st);
	if (ret) {
		kfree(st);
		kvm_put_kvm(kvm);
	}
	return ret;
}

static int kvm_ptdump_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct kvm_ptdump_state *st = seq->private;
	struct kvm *kvm = st->kvm;

	kfree(st);
	kvm_put_kvm(kvm);
	return single_release(inode, file);
}

static const struct file_operations kvm_gstage_fops = {
	.owner		= THIS_MODULE,
	.open		= kvm_ptdump_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= kvm_ptdump_release,
};

void kvm_s2_ptdump_create_debugfs(struct kvm *kvm)
{
	debugfs_create_file("gstage_page_tables", 0400, kvm->debugfs_dentry, kvm,
			    &kvm_gstage_fops);
}
