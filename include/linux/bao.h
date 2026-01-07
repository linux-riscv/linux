/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Bao Hypervisor Linux Kernel Header file
 *
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 *
 * Authors:
 *	João Peixoto <joaopeixoto@osyx.tech>
 *	José Martins <jose@osyx.tech>
 *	David Cerdeira <davidmcerdeira@osyx.tech>
 */

#ifndef _LINUX_BAO_H
#define _LINUX_BAO_H

#include <linux/types.h>

/* IPC through shared-memory hypercall ID */
#define BAO_IPCSHMEM_HYPERCALL_ID 0x1

/* Remote I/O Hypercall ID */
#define BAO_REMIO_HYPERCALL_ID 0x2

/**
 * struct bao_remio_hypercall_ctx - REMIO hypercall context
 * @dm_id: Device model identifier
 * @addr: Target address
 * @op: Operation code
 * @value: Value to read/write
 * @access_width: Access width in bytes
 * @request_id: Request identifier
 * @npend_req: Number of pending requests
 */
struct bao_remio_hypercall_ctx {
	u64 dm_id;
	u64 addr;
	u64 op;
	u64 value;
	u64 access_width;
	u64 request_id;
	u64 npend_req;
};

#endif /* _LINUX_BAO_H */
