// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 Sifive.
 */

#include <linux/kernel.h>
#include <linux/memory.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/bug.h>
#include <linux/of.h>
#include <asm/text-patching.h>
#include <asm/alternative.h>
#include <asm/vendorid_list.h>
#include <asm/errata_list.h>
#include <asm/vendor_extensions.h>
#include <asm/cacheflush.h>
#include <asm/sbi.h>

#define SIFIVE_SBI_EXT_SIFIVE		0x09000489
#define SIFIVE_SBI_EXT_XPBMTUC_PRESENT	0x50425543 // PBUC

#ifdef CONFIG_ERRATA_SIFIVE_XPBMTUC

u64 riscv_xpbmtuc_mask;
EXPORT_SYMBOL(riscv_xpbmtuc_mask);

static const struct {
	const char *machine;
	int xpbmtuc_bit;
} xpbmtuc_platforms[] = {
	{
		.machine = "starfive,jh7110",
		.xpbmtuc_bit = 32
	},
	{
		.machine = "eswin,eic7700",
		.xpbmtuc_bit = -1 // detect
	},
};
#endif

struct errata_info_t {
	char name[32];
	bool (*check_func)(unsigned long  arch_id, unsigned long impid);
};

static bool errata_cip_453_check_func(unsigned long  arch_id, unsigned long impid)
{
	/*
	 * Affected cores:
	 * Architecture ID: 0x8000000000000007
	 * Implement ID: 0x20181004 <= impid <= 0x20191105
	 */
	if (arch_id != 0x8000000000000007 ||
	    (impid < 0x20181004 || impid > 0x20191105))
		return false;
	return true;
}

static bool errata_cip_1200_check_func(unsigned long  arch_id, unsigned long impid)
{
	/*
	 * Affected cores:
	 * Architecture ID: 0x8000000000000007 or 0x1
	 * Implement ID: mimpid[23:0] <= 0x200630 and mimpid != 0x01200626
	 */
	if (arch_id != 0x8000000000000007 && arch_id != 0x1)
		return false;
	if ((impid & 0xffffff) > 0x200630 || impid == 0x1200626)
		return false;

#ifdef CONFIG_MMU
	tlb_flush_all_threshold = 0;
#endif

	return true;
}

#ifdef CONFIG_ERRATA_SIFIVE_XPBMTUC
static void detect_xpbmtuc(void)
{
	int riscv_xpbmtuc_bit = -1, i;
	struct sbiret ret;

	for (i = 0; i < ARRAY_SIZE(xpbmtuc_platforms); i++) {
		if (!of_machine_is_compatible(xpbmtuc_platforms[i].machine))
			continue;

		riscv_xpbmtuc_bit = xpbmtuc_platforms[i].xpbmtuc_bit;
		if (riscv_xpbmtuc_bit >= 0)
			break;

		ret = sbi_ecall(SIFIVE_SBI_EXT_SIFIVE,
				SIFIVE_SBI_EXT_XPBMTUC_PRESENT,
				0, 0, 0, 0, 0, 0);
		riscv_xpbmtuc_bit = ret.error ? -1 : ret.value;
		break;
	}
	if (riscv_xpbmtuc_bit < 0)
		return;

	riscv_xpbmtuc_mask = 1UL << riscv_xpbmtuc_bit;
	pr_info("Using XPbmtUC bit %d\n", riscv_xpbmtuc_bit);
}

static bool errata_xpbmtuc_check_func(unsigned long arch_id, unsigned long impid)
{
	return riscv_xpbmtuc_mask != 0;
}
#else
static void detect_xpbmtuc(void) { }

static bool errata_xpbmtuc_check_func(unsigned long arch_id, unsigned long impid)
{
	return false;
}
#endif

static struct errata_info_t errata_list[ERRATA_SIFIVE_NUMBER] = {
	{
		.name = "cip-453",
		.check_func = errata_cip_453_check_func
	},
	{
		.name = "cip-1200",
		.check_func = errata_cip_1200_check_func
	},
	{
		.name = "xpbmtuc",
		.check_func = errata_xpbmtuc_check_func
	},
};

static u32 __init_or_module sifive_errata_probe(unsigned long archid,
						unsigned long impid)
{
	int idx;
	u32 cpu_req_errata = 0;

	for (idx = 0; idx < ERRATA_SIFIVE_NUMBER; idx++)
		if (errata_list[idx].check_func(archid, impid))
			cpu_req_errata |= (1U << idx);

	return cpu_req_errata;
}

void sifive_errata_patch_func(struct alt_entry *begin, struct alt_entry *end,
			      unsigned long archid, unsigned long impid,
			      unsigned int stage)
{
	struct alt_entry *alt;
	void *oldptr, *altptr;
	u32 cpu_req_errata;
	u32 tmp;

	BUILD_BUG_ON(ERRATA_SIFIVE_NUMBER >= RISCV_VENDOR_EXT_ALTERNATIVES_BASE);

	if (stage == RISCV_ALTERNATIVES_EARLY_BOOT)
		return;
	else if (stage == RISCV_ALTERNATIVES_BOOT)
		detect_xpbmtuc();

	cpu_req_errata = sifive_errata_probe(archid, impid);

	for (alt = begin; alt < end; alt++) {
		if (alt->vendor_id != SIFIVE_VENDOR_ID)
			continue;
		if (alt->patch_id >= ERRATA_SIFIVE_NUMBER) {
			WARN(1, "This errata id:%d is not in kernel errata list", alt->patch_id);
			continue;
		}

		tmp = (1U << alt->patch_id);
		if (cpu_req_errata & tmp) {
			oldptr = ALT_OLD_PTR(alt);
			altptr = ALT_ALT_PTR(alt);

			mutex_lock(&text_mutex);
			patch_text_nosync(oldptr, altptr, alt->alt_len);
			riscv_alternative_fix_offsets(oldptr, alt->alt_len, oldptr - altptr);
			mutex_unlock(&text_mutex);
		}
	}
}
