/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- SM3 Hash Driver
 *
 * Registers an ahash algorithm for SM3 (GB/T 32905-2016) with the
 * Linux crypto subsystem using the CMH SM3 core (CORE_ID_SM3).
 * This is a CRYPTO_AHASH_ALG_BLOCK_ONLY driver (same model as
 * cmh_hash.c), so the Crypto API buffers partial blocks and hands the
 * driver only whole-block-aligned data:
 *
 *   .init()   -> software-only: zero per-request context
 *   .update() -> SM3_CMD_INIT [+ RESTORE] + UPDATE(full blocks) + SAVE + FLUSH
 *                (also serves final: the API calls finup with nbytes == 0)
 *   .digest() -> INIT + UPDATE + FINAL + FLUSH (single-shot)
 *   .export() -> software-only: copy the SM3 checkpoint
 *   .import() -> software-only: restore the SM3 checkpoint
 */

#ifndef CMH_SM3_H
#define CMH_SM3_H

#include "cmh_config.h"

int  cmh_sm3_register(void);
void cmh_sm3_unregister(void);

#endif /* CMH_SM3_H */
