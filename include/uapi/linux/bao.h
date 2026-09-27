/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Provides the Bao Hypervisor IOCTLs and global structures
 *
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 *
 * Authors:
 *	João Peixoto <jpeixoto@osyx.tech>
 *	José Martins <jose@osyx.tech>
 *	David Cerdeira <davidmcerdeira@osyx.tech>
 */

#ifndef _UAPI_BAO_H
#define _UAPI_BAO_H

#include <linux/ioctl.h>
#include <linux/types.h>

/**
 * struct bao_virtio_request - Parameters of a Bao VirtIO request
 * @dm_id: Device model ID
 * @addr: MMIO register address accessed
 * @op: Operation type (WRITE = 0, READ, ASK, NOTIFY)
 * @value: Value to write or read
 * @access_width: Access width (VirtIO MMIO supports 4-byte aligned accesses)
 * @request_id: Request ID of the I/O request
 */
struct bao_virtio_request {
	__u64 dm_id;
	__u64 addr;
	__u64 op;
	__u64 value;
	__u64 access_width;
	__u64 request_id;
};

/**
 * struct bao_ioeventfd - Parameters of an ioeventfd request
 * @fd: Eventfd file descriptor associated with the I/O request
 * @flags: Logical OR of BAO_IOEVENTFD_FLAG_*
 * @addr: Start address of the I/O range
 * @len: Length of the I/O range
 * @reserved: Reserved, must be 0
 * @data: Data for matching (used if data matching is enabled)
 */
struct bao_ioeventfd {
	__s32 fd;
	__u32 flags;
	__u64 addr;
	__u32 len;
	__u32 reserved;
	__u64 data;
};

/* Only signal the eventfd when the written value equals bao_ioeventfd.data */
#define BAO_IOEVENTFD_FLAG_DATAMATCH (1U << 1)
/* Remove the ioeventfd instead of adding it */
#define BAO_IOEVENTFD_FLAG_DEASSIGN (1U << 2)

/**
 * struct bao_irqfd - Parameters of an IRQFD request
 * @fd: File descriptor of the eventfd
 * @flags: Logical OR of BAO_IRQFD_FLAG_*
 */
struct bao_irqfd {
	__s32 fd;
	__u32 flags;
};

/* Remove the irqfd instead of adding it */
#define BAO_IRQFD_FLAG_DEASSIGN (1U << 0)

/**
 * struct bao_dm_info - Parameters of a Bao device model
 * @shmem_addr: Base address of the shared memory
 * @shmem_size: Size of the shared memory
 * @id: Virtual ID of the DM
 * @irq: Hypervisor notification line, as a line of the system's root
 *       interrupt controller (e.g. a GIC SPI on arm64, a PLIC source on
 *       riscv), which the driver maps and uses as the backend I/O doorbell
 *
 * The layout is free of implicit padding so it is identical on every
 * architecture.
 */
struct bao_dm_info {
	__u64 shmem_addr;
	__u64 shmem_size;
	__u32 id;
	__u32 irq;
};

/*
 * The ioctl type for Bao, documented in
 * Documentation/userspace-api/ioctl/ioctl-number.rst
 */
#define BAO_IOCTL_TYPE 0xA7

/*
 * Bao userspace IOCTL commands
 * Follows Linux kernel convention, see Documentation/driver-api/ioctl.rst
 */
/*
 * Issued on the /dev/bao control device by the userspace VMM to instantiate a
 * device model from its own configuration. On success returns a new file
 * descriptor bound to that DM; all other commands below operate on that fd.
 */
#define BAO_IOCTL_CREATE_DM _IOW(BAO_IOCTL_TYPE, 0x00, struct bao_dm_info)
#define BAO_IOCTL_DM_GET_INFO _IOWR(BAO_IOCTL_TYPE, 0x01, struct bao_dm_info)
#define BAO_IOCTL_IO_CLIENT_ATTACH \
	_IOWR(BAO_IOCTL_TYPE, 0x02, struct bao_virtio_request)
#define BAO_IOCTL_IO_REQUEST_COMPLETE \
	_IOW(BAO_IOCTL_TYPE, 0x03, struct bao_virtio_request)
#define BAO_IOCTL_IOEVENTFD _IOW(BAO_IOCTL_TYPE, 0x04, struct bao_ioeventfd)
#define BAO_IOCTL_IRQFD _IOW(BAO_IOCTL_TYPE, 0x05, struct bao_irqfd)

#endif /* _UAPI_BAO_H */
