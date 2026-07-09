/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Hardware Register Definitions
 *
 * Derived from the CMH hardware register specification.
 * All offsets are taken directly from the hardware documentation.
 */

#ifndef CMH_REGISTERS_H
#define CMH_REGISTERS_H

#include <linux/io.h>
#include <linux/types.h>

/* MBX Instance Addressing */

#define CMH_MBX_INSTANCE_SHIFT        12
#define CMH_MBX_INSTANCE_SIZE         BIT(CMH_MBX_INSTANCE_SHIFT) /* 0x1000 */
#define CMH_MAX_MBX_INSTANCES         64U

/* MBX Per-Instance Register Offsets */

#define R_MBX_LOCK                    0x000U
#define R_MBX_HOST_INFO               0x004U
#define R_MBX_QUEUE_LO                0x008U
#define R_MBX_QUEUE_HI                0x00CU
#define R_MBX_QUEUE_SLOTS             0x010U
#define R_MBX_QUEUE_STRIDE            0x014U
#define R_MBX_QUEUE_HEAD              0x018U
#define R_MBX_QUEUE_TAIL              0x01CU
#define R_MBX_INTERRUPT               0x020U
#define R_MBX_INTERRUPT_MASK          0x024U
#define R_MBX_COMMAND                 0x028U
#define R_MBX_STATUS                  0x02CU
#define R_MBX_CHILD                   0x030U
#define R_MBX_ID                      0x034U
#define R_MBX_HOST_CONFIG             0x038U
#define R_MBX_SCRATCH                 0x03CU

#define MBX_QUEUE_ALIGNMENT           0x4U

/* MBX Interrupt Bits */

#define MBX_DONE_IRQ                  BIT(0)
#define MBX_ERROR_IRQ                 BIT(1)
#define MBX_IRQ_MASK                  (MBX_DONE_IRQ | MBX_ERROR_IRQ)

/* MBX Command Values */

#define MBX_COMMAND_RUN               0x000U
#define MBX_COMMAND_PAUSE             0xC2FU
#define MBX_COMMAND_CONTINUE          0x5DBU
#define MBX_COMMAND_RESTART           0xB78U
#define MBX_COMMAND_ABORT             0x6F6U
#define MBX_COMMAND_FLUSH             0x3A5U

/* MBX Status Values */

#define MBX_STATUS_IDLE               0x01U
#define MBX_STATUS_BUSY               0x10U
#define MBX_STATUS_HOLD               0x20U
#define MBX_STATUS_PAUSED             0x28U
#define MBX_STATUS_SUCCESS            0x40U
#define MBX_STATUS_ERROR              0x80U
#define MBX_STATUS_OFFLINE            0x88U  /* ERROR | 0x08: offline/stopped */

#define MBX_MASK_DONE                 (MBX_STATUS_IDLE | MBX_STATUS_SUCCESS)
#define MBX_MASK_RUNNING              (MBX_STATUS_BUSY | MBX_STATUS_HOLD)
#define MBX_MASK_STOPPED              MBX_STATUS_OFFLINE

/* MBX Status Field Extraction */

#define MBX_STATUS_CODE(v)            ((v) & 0xFFU)
#define MBX_STATUS_CORE_ID(v)         (((v) >> 8) & 0xFFU)
#define MBX_STATUS_ERROR_CODE(v)      (((v) >> 16) & 0xFFU)
#define MBX_STATUS_CMD_INDEX(v)       (((v) >> 24) & 0xFFU)

/* SIC Register Offsets (relative to SIC base / instance 0 base) */

#define R_SIC_BOOT_STATUS             0x100U
#define SIC_BOOT_STATUS_MASK          0x77U
#define SIC_BOOT_STATUS_PASS          0x66U

#define R_SIC_MBX_AVAILABILITY        0x104U
#define R_SIC_MBX_AVAILABILITY2       0x108U

#define R_SIC_SW_BOOT_STATUS          0x12CU
#define SIC_SW_BOOT_STATUS_STARTED    BIT(0)
#define SIC_SW_BOOT_STATUS_READY      BIT(1)
#define SIC_SW_BOOT_STATUS_MISSION    BIT(6)
#define SIC_SW_BOOT_STATUS_MISSION2   BIT(7)

#define R_SIC_SW_ERROR_INFO           0x130U
#define R_SIC_SW_HEARTBEAT            0x154U

#define R_SIC_GPINTERRUPT             0x160U

#define R_SIC_HW_VERSION0             0x200U
#define R_SIC_SW_VERSION              0x218U
#define R_SIC_CORE_ENABLE             0x22CU

/* Register Access Helpers */

static inline u32 cmh_reg_read32(void __iomem *base, u32 offset)
{
	return ioread32((u8 __iomem *)base + offset);
}

static inline void cmh_reg_write32(u32 value, void __iomem *base, u32 offset)
{
	iowrite32(value, (u8 __iomem *)base + offset);
}

/*
 * 64-bit register access via two 32-bit reads/writes.  Only correct for
 * register pairs where split access is defined (e.g. QUEUE_LO/HI).
 * Do not use for registers requiring atomic 64-bit access.
 *
 * No explicit barrier between the two halves is needed: ioread32/iowrite32
 * include implicit ordering guarantees on all supported architectures
 * (MMIO accessors are strongly ordered with respect to each other).
 */
static inline u64 cmh_reg_read64(void __iomem *base, u32 offset)
{
	u32 lo = ioread32((u8 __iomem *)base + offset);
	u32 hi = ioread32((u8 __iomem *)base + offset + 4);

	return ((u64)hi << 32) | lo;
}

static inline void cmh_reg_write64(u64 value, void __iomem *base, u32 offset)
{
	iowrite32((u32)value, (u8 __iomem *)base + offset);
	iowrite32((u32)(value >> 32), (u8 __iomem *)base + offset + 4);
}

/* Return the ioremap'd base for MBX instance N within the SIC region */
static inline void __iomem *cmh_mbx_instance_base(void __iomem *sic_mapped,
						  u32 instance)
{
	return (u8 __iomem *)sic_mapped +
	       ((unsigned long)instance << CMH_MBX_INSTANCE_SHIFT);
}

#endif /* CMH_REGISTERS_H */
