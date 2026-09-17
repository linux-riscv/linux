/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- EAC (Error and Alarm Controller) ABI Definitions
 *
 * Kernel-side definitions for the CMH EAC ABI.
 * All constants and layouts derived from the CMH eSW ABI.
 */

#ifndef CMH_EAC_ABI_H
#define CMH_EAC_ABI_H

#include <linux/types.h>

/* EAC Commands */

#define EAC_CMD_READ		0x01U

/* EAC Read Response -- eSW writes this to the DMA destination buffer */

struct eac_read_rsp {
	u64 mailbox_notification; /* bitmask: MBX that raised safety notif */
	u32 hw_error;             /* bitmask: HWC that raised error */
	u32 hw_nmi;               /* bitmask: HWC that raised NMI */
	u32 hw_panic;             /* bitmask: HWC that raised HW panic */
	u32 safety_fatal;         /* bitmask: HWC that raised fatal safety */
	u32 safety_notification;  /* bitmask: HWC that raised safety notif */
	u32 sw_info0;             /* eSW tracing information */
	u32 sw_info1;             /* eSW tracing information */
	u32 sram_bank_errors[4];  /* correctable ECC error counts per bank */
};

/* EAC Command Structures */

struct eac_cmd_read {
	u64 dst;	/* DMA destination for eac_read_rsp */
	u32 len;	/* must be >= sizeof(struct eac_read_rsp) */
};

union eac_cmd {
	struct eac_cmd_read cmd_read;
};

#endif /* CMH_EAC_ABI_H */
