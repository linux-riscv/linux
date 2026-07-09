/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- SM3 Hash Driver
 *
 * Registers an ahash algorithm for SM3 (GB/T 32905-2016) with the
 * Linux crypto subsystem using the CMH SM3 core (CORE_ID_SM3).
 * Uses the same incremental HW update model as cmh_hash.c:
 *
 *   .init()   -> software-only: zero per-request context
 *   .update() -> holdback partial blocks; submit full blocks via
 *                SM3_CMD_INIT [+ RESTORE] + UPDATE + SAVE + FLUSH
 *   .final()  -> SM3_CMD_INIT [+ RESTORE] [+ UPDATE] + FINAL + FLUSH
 *   .digest() -> INIT + UPDATE + FINAL + FLUSH (single-shot)
 *   .export() -> software-only: copy checkpoint + holdback
 *   .import() -> software-only: restore checkpoint + holdback
 */

#ifndef CMH_SM3_H
#define CMH_SM3_H

#include "cmh_config.h"

int  cmh_sm3_register(void);
void cmh_sm3_unregister(void);

#endif /* CMH_SM3_H */
