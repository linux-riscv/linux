/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright(C) 2026 Spacemit Limited. All rights reserved.
 */

#ifndef _RVTRACE_FUNNEL_H
#define _RVTRACE_FUNNEL_H

#include <linux/spinlock.h>
#include <linux/coresight.h>

/* Disable Individual Funnel Inputs */
#define RVTRACE_FUNNEL_DISINPUT_OFFSET			0x008
#define RVTRACE_FUNNEL_DISINPUT_MASK			0xffff

/**
 * struct funnel_data - specifics associated to a Trace Funnel component
 * @csdev:        Component vitals needed by the framework.
 * @spinlock:     Only one at a time pls.
 * @was_enabled:  Flag showing whether the Trace Funnel was enabled.
 * @input_refcnt: Record the number of funnel inputs
 */
struct funnel_data {
	struct coresight_device	*csdev;
	spinlock_t		spinlock;
	bool			was_enabled;
	u32			input_refcnt;
	u32			disintput;
};

#endif
