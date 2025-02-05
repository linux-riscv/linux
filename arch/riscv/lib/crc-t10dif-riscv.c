// SPDX-License-Identifier: GPL-2.0-only
/*
 * Accelerated CRC-T10DIF implementation with RISC-V Zbc extension.
 *
 * Copyright (C) 2024 Institute of Software, CAS.
 */

#include <asm/alternative-macros.h>
#include <asm/byteorder.h>
#include <asm/hwcap.h>

#include <linux/byteorder/generic.h>
#include <linux/crc-t10dif.h>
#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/types.h>

#define CRCT10DIF_POLY 0x8bb7

#if __riscv_xlen == 64
#define STEP_ORDER 3

#define CRCT10DIF_POLY_QT_BE 0xf65a57f81d33a48a

static inline u64 crct10dif_prep(u16 crc, unsigned long const *ptr)
{
	return ((u64)crc << 48) ^ (__force u64)__cpu_to_be64(*ptr);
}

#elif __riscv_xlen == 32
#define STEP_ORDER 2
#define CRCT10DIF_POLY_QT_BE 0xf65a57f8

static inline u32 crct10dif_prep(u16 crc, unsigned long const *ptr)
{
	return ((u32)crc << 16) ^ (__force u32)__cpu_to_be32(*ptr);
}

#else
#error "Unexpected __riscv_xlen"
#endif

static inline u16 crct10dif_zbc(unsigned long s)
{
	u16 crc;

	asm volatile   (".option push\n"
			".option arch,+zbc\n"
			"clmulh %0, %1, %2\n"
			"xor    %0, %0, %1\n"
			"clmul  %0, %0, %3\n"
			".option pop\n"
			: "=&r" (crc)
			: "r"(s),
			  "r"(CRCT10DIF_POLY_QT_BE),
			  "r"(CRCT10DIF_POLY)
			:);

	return crc;
}

#define STEP (1 << STEP_ORDER)
#define OFFSET_MASK (STEP - 1)

static inline u16 crct10dif_unaligned(u16 crc, const u8 *p, size_t len)
{
	size_t bits = len * 8;
	unsigned long s = 0;
	u16 crc_low = 0;

	for (int i = 0; i < len; i++)
		s = *p++ | (s << 8);

	if (len < sizeof(u16)) {
		s ^= crc >> (16 - bits);
		crc_low = crc << bits;
	} else {
		s ^= (unsigned long)crc << (bits - 16);
	}

	crc = crct10dif_zbc(s);
	crc ^= crc_low;

	return crc;
}

u16 crc_t10dif_arch(u16 crc, const u8 *p, size_t len)
{
	size_t offset, head_len, tail_len;
	unsigned long const *p_ul;
	unsigned long s;

	asm goto(ALTERNATIVE("j %l[legacy]", "nop", 0,
			     RISCV_ISA_EXT_ZBC, 1)
		 : : : : legacy);

	offset = (unsigned long)p & OFFSET_MASK;
	if (offset && len) {
		head_len = min(STEP - offset, len);
		crc = crct10dif_unaligned(crc, p, head_len);
		p += head_len;
		len -= head_len;
	}

	tail_len = len & OFFSET_MASK;
	len = len >> STEP_ORDER;
	p_ul = (unsigned long const *)p;

	for (int i = 0; i < len; i++) {
		s = crct10dif_prep(crc, p_ul);
		crc = crct10dif_zbc(s);
		p_ul++;
	}

	p = (unsigned char const *)p_ul;
	if (tail_len)
		crc = crct10dif_unaligned(crc, p, tail_len);

	return crc;
legacy:
	return crc_t10dif_generic(crc, p, len);
}
EXPORT_SYMBOL(crc_t10dif_arch);

bool crc_t10dif_is_optimized(void)
{
	return riscv_has_extension_likely(RISCV_ISA_EXT_ZBC);
}
EXPORT_SYMBOL(crc_t10dif_is_optimized);

MODULE_DESCRIPTION("CRC-T10DIF using RISC-V ZBC Extension");
MODULE_LICENSE("GPL");
