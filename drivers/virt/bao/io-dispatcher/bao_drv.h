/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Provides some definitions for the Bao Hypervisor modules
 *
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 *
 * Authors:
 *	João Peixoto <jpeixoto@osyx.tech>
 *	José Martins <jose@osyx.tech>
 *	David Cerdeira <davidmcerdeira@osyx.tech>
 */

#ifndef __BAO_DRV_H
#define __BAO_DRV_H

#include <linux/bao.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include "../bao_hypercall.h"

/* Room for a "bao-" prefixed name and a full u32 DM id. */
#define BAO_NAME_MAX_LEN 32

/*
 * Upper bound on I/O requests queued but not yet consumed by a client. Caps the
 * memory a misbehaving frontend can pin by flooding the backend with requests.
 */
#define BAO_IO_CLIENT_MAX_REQUESTS 1024

/* Bit in &bao_io_client.flags: the client is being torn down. */
#define BAO_IO_CLIENT_DESTROYING 0U

struct bao_dm;
struct bao_io_client;

typedef int (*bao_io_client_handler_t)(struct bao_io_client *client,
				       struct bao_virtio_request *req);
typedef void (*bao_intc_handler_t)(struct bao_dm *dm);

/**
 * enum bao_io_op - Bao hypervisor I/O operation types
 * @BAO_IO_WRITE:   Write operation
 * @BAO_IO_READ:    Read operation
 * @BAO_IO_ASK:     Request operation information (e.g., MMIO address)
 * @BAO_IO_NOTIFY:  Notify I/O completion
 */
enum bao_io_op {
	BAO_IO_WRITE = 0,
	BAO_IO_READ,
	BAO_IO_ASK,
	BAO_IO_NOTIFY,
};

/**
 * struct bao_io_client - Bao I/O client
 * @name: Client name
 * @dm: The DM that the client belongs to
 * @list: List node for this bao_io_client
 * @is_control: If this client is the control client
 * @flags: Flags (BAO_IO_CLIENT_*)
 * @virtio_requests: List of pending I/O requests
 * @nr_requests: Number of entries in @virtio_requests
 * @virtio_requests_lock: Protects @virtio_requests and @nr_requests
 * @range_list: I/O ranges
 * @range_lock: Protects @range_list
 * @handler: I/O request handler for this client
 * @thread: Kernel thread executing the handler
 * @wq: Wait queue used for thread parking
 * @priv: Private data for the handler
 */
struct bao_io_client {
	char name[BAO_NAME_MAX_LEN];
	struct bao_dm *dm;
	struct list_head list;
	bool is_control;
	unsigned long flags;
	struct list_head virtio_requests;
	unsigned int nr_requests;
	/* protects virtio_requests and nr_requests */
	struct mutex virtio_requests_lock;
	struct list_head range_list;
	/* protects range_list */
	struct rw_semaphore range_lock;
	bao_io_client_handler_t handler;
	struct task_struct *thread;
	wait_queue_head_t wq;
	void *priv;
};

/**
 * struct bao_dm - Bao backend device model (DM)
 * @info: DM information (id, shmem_addr, shmem_size, irq)
 * @name: Backing storage for the control client name
 * @ioeventfds: List of all ioeventfds
 * @ioeventfds_lock: Protects @ioeventfds
 * @ioeventfd_client: Ioeventfd client
 * @irqfds: List of all irqfds
 * @irqfds_lock: Protects @irqfds
 * @irqfd_server: Workqueue responsible for irqfd handling
 * @io_clients_lock: Protects @io_clients
 * @io_clients: List of all bao_io_client
 * @control_client: Control client
 * @io_wq: Workqueue dispatching the I/O requests of this DM
 * @io_work: Work item queued on @io_wq by the notification interrupt
 * @intc_handler: Per-DM interrupt controller dispatch callback
 * @intc_name: Backing storage for the request_irq() name
 * @virq: Linux interrupt number of the hypervisor notification line
 */
struct bao_dm {
	struct bao_dm_info info;
	char name[BAO_NAME_MAX_LEN];

	struct list_head ioeventfds;
	/* protects ioeventfds */
	struct mutex ioeventfds_lock;
	struct bao_io_client *ioeventfd_client;

	struct list_head irqfds;
	/* protects irqfds */
	struct mutex irqfds_lock;
	struct workqueue_struct *irqfd_server;

	/* protects io_clients */
	struct rw_semaphore io_clients_lock;
	struct list_head io_clients;
	struct bao_io_client *control_client;

	struct workqueue_struct *io_wq;
	struct work_struct io_work;

	bao_intc_handler_t intc_handler;
	char intc_name[BAO_NAME_MAX_LEN];
	unsigned int virq;
};

/**
 * struct bao_io_range - Represents a range of I/O addresses
 * @list: List node for linking multiple ranges
 * @start: Start address of the range
 * @end: End address of the range (inclusive)
 */
struct bao_io_range {
	struct list_head list;
	u64 start;
	u64 end;
};

/**
 * bao_dm_create - Create a backend device model (DM)
 * @info: DM information (id, shmem_addr, shmem_size, irq)
 *
 * Return: Pointer to the created DM on success, ERR_PTR() on error.
 */
struct bao_dm *bao_dm_create(struct bao_dm_info *info);

/**
 * bao_dm_create_fd - Create a DM and bind it to a new file descriptor
 * @info: DM information (id, shmem_addr, shmem_size, irq)
 *
 * Instantiates a DM, registers its interrupt and installs an anonymous inode so
 * the DM lives exactly as long as the returned descriptor is open. Invoked from
 * the /dev/bao control device on BAO_IOCTL_CREATE_DM.
 *
 * Return: A new file descriptor on success, negative error code on failure.
 */
int bao_dm_create_fd(struct bao_dm_info *info);

/**
 * bao_dm_destroy - Destroy a backend device model (DM)
 * @dm: DM to be destroyed
 */
void bao_dm_destroy(struct bao_dm *dm);

/**
 * bao_io_client_create - Create a backend I/O client
 * @dm: DM this client belongs to
 * @handler: I/O client handler for requests
 * @data: Private data passed to the handler
 * @is_control: True if this is the control client
 * @name: Name of the I/O client
 *
 * Return: Pointer to the created I/O client, NULL on failure.
 */
struct bao_io_client *bao_io_client_create(struct bao_dm *dm,
					   bao_io_client_handler_t handler,
					   void *data, bool is_control,
					   const char *name);

/**
 * bao_io_clients_destroy - Destroy all I/O clients of a DM
 * @dm: DM whose I/O clients are to be destroyed
 */
void bao_io_clients_destroy(struct bao_dm *dm);

/**
 * bao_io_client_attach - Wait until an I/O client has requests to process
 * @client: I/O client to attach
 *
 * Sleeps until a request is queued on @client, the client is being destroyed
 * or, for a kernel client, its thread is asked to stop.
 *
 * Return: 0 when requests are pending, -ERESTARTSYS if interrupted by a
 * signal, -EPERM if the client is going away.
 */
int bao_io_client_attach(struct bao_io_client *client);

/**
 * bao_io_client_range_add - Add an I/O range to monitor in a client
 * @client: I/O client
 * @start: Start address of the range
 * @end: End address of the range (inclusive)
 *
 * Return: 0 on success, negative error code on failure.
 */
int bao_io_client_range_add(struct bao_io_client *client, u64 start, u64 end);

/**
 * bao_io_client_range_del - Remove an I/O range from a client
 * @client: I/O client
 * @start: Start address of the range
 * @end: End address of the range (inclusive)
 */
void bao_io_client_range_del(struct bao_io_client *client, u64 start, u64 end);

/**
 * bao_io_client_request - Retrieve the oldest I/O request from a client
 * @client: I/O client
 * @req: Pointer to virtio request structure to fill
 *
 * Return: 0 on success, -EAGAIN if no request is available.
 */
int bao_io_client_request(struct bao_io_client *client,
			  struct bao_virtio_request *req);

/**
 * bao_io_client_push_request - Push an I/O request into a client
 * @client: I/O client
 * @req: I/O request to push
 *
 * Return: True if a request was pushed, false otherwise.
 */
bool bao_io_client_push_request(struct bao_io_client *client,
				struct bao_virtio_request *req);

/**
 * bao_io_client_pop_request - Pop the oldest I/O request from a client
 * @client: I/O client
 * @req: Buffer to store the popped request
 *
 * Return: True if a request was popped, false if the list was empty.
 */
bool bao_io_client_pop_request(struct bao_io_client *client,
			       struct bao_virtio_request *req);

/**
 * bao_io_client_find - Find the I/O client for a given request
 * @dm: DM that the I/O request belongs to
 * @req: I/O request to locate
 *
 * Return: Pointer to the I/O client handling the request, NULL if none found.
 */
struct bao_io_client *bao_io_client_find(struct bao_dm *dm,
					 struct bao_virtio_request *req);

/**
 * bao_ioeventfd_client_init - Initialize the Ioeventfd client for a DM
 * @dm: DM that the Ioeventfd client belongs to
 *
 * Return: 0 on success, negative error code on failure.
 */
int bao_ioeventfd_client_init(struct bao_dm *dm);

/**
 * bao_ioeventfd_client_destroy - Destroy the Ioeventfd client for a DM
 * @dm: DM that the Ioeventfd client belongs to
 */
void bao_ioeventfd_client_destroy(struct bao_dm *dm);

/**
 * bao_ioeventfd_client_config - Configure an Ioeventfd client
 * @dm: DM that the Ioeventfd client belongs to
 * @config: Ioeventfd configuration to apply
 *
 * Return: 0 on success, negative error code on failure.
 */
int bao_ioeventfd_client_config(struct bao_dm *dm,
				struct bao_ioeventfd *config);

/**
 * bao_irqfd_server_init - Initialize the Irqfd server for a DM
 * @dm: DM that the Irqfd server belongs to
 *
 * Return: 0 on success, negative error code on failure.
 */
int bao_irqfd_server_init(struct bao_dm *dm);

/**
 * bao_irqfd_server_destroy - Destroy the Irqfd server for a DM
 * @dm: DM that the Irqfd server belongs to
 */
void bao_irqfd_server_destroy(struct bao_dm *dm);

/**
 * bao_irqfd_server_config - Configure an Irqfd server
 * @dm: DM that the Irqfd server belongs to
 * @config: Irqfd configuration to apply
 *
 * Return: 0 on success, negative error code on failure.
 */
int bao_irqfd_server_config(struct bao_dm *dm, struct bao_irqfd *config);

/**
 * bao_io_dispatcher_init - Initialize the I/O Dispatcher for a DM
 * @dm: DM to initialize on the I/O Dispatcher
 *
 * Return: 0 on success, negative error code on failure.
 */
int bao_io_dispatcher_init(struct bao_dm *dm);

/**
 * bao_io_dispatcher_destroy - Destroy the I/O Dispatcher for a DM
 * @dm: DM to destroy on the I/O Dispatcher
 */
void bao_io_dispatcher_destroy(struct bao_dm *dm);

/**
 * bao_dispatch_io - Acquire and dispatch I/O requests from the Bao Hypervisor
 * @dm: DM whose I/O clients will handle the requests
 *
 * Return: The number of requests still pending on success, negative error
 * code on failure.
 */
int bao_dispatch_io(struct bao_dm *dm);

/**
 * bao_io_request_complete_error - Complete a request the backend cannot serve
 * @dm: DM owning the request
 * @req: The request that could not be handed to userspace or a handler
 *
 * Completes @req back to the hypervisor with a zero value so the frontend
 * making the I/O access is resumed instead of hanging forever.
 */
void bao_io_request_complete_error(struct bao_dm *dm,
				   struct bao_virtio_request *req);

/**
 * bao_io_dispatcher_pause - Pause the I/O Dispatcher for a DM
 * @dm: DM to pause
 */
void bao_io_dispatcher_pause(struct bao_dm *dm);

/**
 * bao_io_dispatcher_resume - Resume the I/O Dispatcher for a DM
 * @dm: DM to resume
 */
void bao_io_dispatcher_resume(struct bao_dm *dm);

/**
 * bao_intc_init - Register the interrupt controller for a DM
 * @dm: DM that the interrupt controller belongs to
 *
 * Return: 0 on success, negative error code on failure.
 */
int bao_intc_init(struct bao_dm *dm);

/**
 * bao_intc_destroy - Unregister the interrupt controller for a DM
 * @dm: DM that the interrupt controller belongs to
 */
void bao_intc_destroy(struct bao_dm *dm);

/**
 * bao_intc_setup_handler - Setup the interrupt controller handler
 * @dm: DM that the interrupt controller belongs to
 * @handler: Function pointer to the interrupt handler
 */
void bao_intc_setup_handler(struct bao_dm *dm, bao_intc_handler_t handler);

/**
 * bao_intc_remove_handler - Remove the interrupt controller handler
 * @dm: DM that the interrupt controller belongs to
 */
void bao_intc_remove_handler(struct bao_dm *dm);

#endif /* __BAO_DRV_H */
