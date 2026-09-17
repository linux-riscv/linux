/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Kernel Crypto API Hash Driver
 *
 * Registers ahash algorithms (SHA-2, SHA-3, and SHAKE families) with the
 * Linux crypto subsystem.  These are CRYPTO_AHASH_ALG_BLOCK_ONLY drivers,
 * so the Crypto API buffers partial blocks and hands the driver only
 * whole-block-aligned data:
 *
 *   .init()   -> software-only: zero per-request context
 *   .update() -> INIT [+ RESTORE] + UPDATE(full blocks) + SAVE + FLUSH
 *                (also serves final: the API calls finup with nbytes == 0)
 *   .digest() -> INIT + UPDATE + FINAL + FLUSH (single-shot)
 *   .export() -> software-only: copy the HC checkpoint
 *   .import() -> software-only: restore the HC checkpoint
 */

#ifndef CMH_HASH_H
#define CMH_HASH_H

#include "cmh_config.h"

int  cmh_hash_register(void);
void cmh_hash_unregister(void);

#endif /* CMH_HASH_H */
