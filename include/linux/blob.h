/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Linkable blob API.
 *
 * Copyright (C) 2025, Linutronix GmbH.
 * Author: Thomas Weißschuh <thomas.weissschuh@linutronix.de>
 */

#ifndef _LINUX_BLOB_H
#define _LINUX_BLOB_H

#include <linux/args.h>
#include <linux/types.h>

struct blob {
	const char *const path;
	const u8 *data;
	const u8 *end;
};

#define BLOB(_symbol)	({					\
	extern const struct blob CONCATENATE(__blob_, _symbol);	\
	&CONCATENATE(__blob_, _symbol);				\
})

static inline size_t blob_size(const struct blob *blob)
{
	return blob->end - blob->data;
}

#endif /* _LINUX_BLOB_H */
