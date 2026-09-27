// SPDX-License-Identifier: GPL-2.0
/*
 * Bao Hypervisor I/O Dispatcher
 *
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 *
 * Authors:
 *	João Peixoto <jpeixoto@osyx.tech>
 *	José Martins <jose@osyx.tech>
 *	David Cerdeira <davidmcerdeira@osyx.tech>
 */

#include <linux/workqueue.h>
#include "bao_drv.h"

void bao_io_dispatcher_destroy(struct bao_dm *dm)
{
	if (WARN_ON_ONCE(!dm))
		return;

	if (!dm->io_wq)
		return;

	bao_io_dispatcher_pause(dm);

	destroy_workqueue(dm->io_wq);
	dm->io_wq = NULL;
}

void bao_io_request_complete_error(struct bao_dm *dm,
				   struct bao_virtio_request *req)
{
	struct bao_remio_hypercall_ctx ctx = {
		.dm_id = dm->info.id,
		.op = req->op,
		.addr = req->addr,
		.value = 0,
		.access_width = req->access_width,
		.request_id = req->request_id,
	};

	bao_remio_hypercall(&ctx);
}

int bao_dispatch_io(struct bao_dm *dm)
{
	struct bao_io_client *client;
	struct bao_remio_hypercall_ctx ctx;
	struct bao_virtio_request req;

	if (WARN_ON_ONCE(!dm))
		return -EINVAL;

	ctx.dm_id = dm->info.id;
	ctx.op = BAO_IO_ASK;
	ctx.addr = 0;
	ctx.value = 0;
	ctx.request_id = 0;
	ctx.access_width = 0;
	ctx.npend_req = 0;

	if (bao_remio_hypercall(&ctx))
		return -EIO;

	req.dm_id = ctx.dm_id;
	req.op = ctx.op;
	req.addr = ctx.addr;
	req.value = ctx.value;
	req.access_width = ctx.access_width;
	req.request_id = ctx.request_id;

	down_read(&dm->io_clients_lock);
	client = bao_io_client_find(dm, &req);
	if (!client) {
		up_read(&dm->io_clients_lock);
		bao_io_request_complete_error(dm, &req);
		return -ENODEV;
	}

	if (!bao_io_client_push_request(client, &req)) {
		up_read(&dm->io_clients_lock);
		bao_io_request_complete_error(dm, &req);
		return -ENOMEM;
	}

	wake_up_interruptible(&client->wq);
	up_read(&dm->io_clients_lock);

	return ctx.npend_req;
}

/**
 * io_dispatcher - Workqueue handler for dispatching I/O
 * @work: Work struct representing this dispatch operation
 *
 * Handles all pending I/O requests for the associated Bao DM.
 * Executed in process context by the workqueue.
 */
static void io_dispatcher(struct work_struct *work)
{
	struct bao_dm *dm = container_of(work, struct bao_dm, io_work);

	while (bao_dispatch_io(dm) > 0)
		cpu_relax();
}

/**
 * io_dispatcher_intc_handler - Interrupt handler for I/O requests
 * @dm: Bao device model that triggered the interrupt
 *
 * Invoked by the interrupt controller when a new I/O request is available.
 * Queues the DM's work item onto its I/O dispatcher workqueue for processing
 * in process context.
 */
static void io_dispatcher_intc_handler(struct bao_dm *dm)
{
	queue_work(dm->io_wq, &dm->io_work);
}

void bao_io_dispatcher_pause(struct bao_dm *dm)
{
	if (WARN_ON_ONCE(!dm || !dm->io_wq))
		return;

	bao_intc_remove_handler(dm);

	drain_workqueue(dm->io_wq);
}

void bao_io_dispatcher_resume(struct bao_dm *dm)
{
	if (WARN_ON_ONCE(!dm || !dm->io_wq))
		return;

	bao_intc_setup_handler(dm, io_dispatcher_intc_handler);

	queue_work(dm->io_wq, &dm->io_work);
}

int bao_io_dispatcher_init(struct bao_dm *dm)
{
	if (WARN_ON_ONCE(!dm))
		return -EINVAL;

	if (dm->io_wq)
		return -EBUSY;

	dm->io_wq = alloc_workqueue("bao-iodwq%u",
				    WQ_HIGHPRI | WQ_MEM_RECLAIM | WQ_PERCPU, 1,
				    dm->info.id);
	if (!dm->io_wq)
		return -ENOMEM;

	INIT_WORK(&dm->io_work, io_dispatcher);

	bao_intc_setup_handler(dm, io_dispatcher_intc_handler);

	return 0;
}
