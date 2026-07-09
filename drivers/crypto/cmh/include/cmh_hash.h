/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Kernel Crypto API Hash Driver
 *
 * Registers ahash algorithms (SHA-2, SHA-3, and SHAKE families) with the
 * Linux crypto subsystem.  Uses an incremental HW update model:
 *
 *   .init()   -> software-only: zero per-request context
 *   .update() -> holdback partial blocks; submit full blocks via
 *                INIT [+ RESTORE] + UPDATE + SAVE + FLUSH
 *   .final()  -> INIT [+ RESTORE] [+ UPDATE(residual)] + FINAL + FLUSH
 *   .digest() -> INIT + UPDATE + FINAL + FLUSH (single-shot)
 *   .export() -> software-only: copy checkpoint + holdback
 *   .import() -> software-only: restore checkpoint + holdback
 */

#ifndef CMH_HASH_H
#define CMH_HASH_H

#include "cmh_config.h"

int  cmh_hash_register(void);
void cmh_hash_unregister(void);

#endif /* CMH_HASH_H */
