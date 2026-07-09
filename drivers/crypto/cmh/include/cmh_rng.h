/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Hardware RNG (DRBG) Driver
 *
 * Registers a struct hwrng backed by the CMH DRBG core.
 * Each .read() builds a VCQ with DRBG_CMD_GENERATE and submits it
 * through the Transaction Manager for synchronous completion.
 *
 * The DRBG must be configured (CONFIG command) by the management host
 * before the LKM is loaded -- the LKM only issues GENERATE requests.
 *
 * CRNG seeding control:
 *   - Module param "hwrng_quality" (0=disabled, 1-1024=enable)
 *   - Default: 0 (conservative -- no automatic kernel CRNG seeding)
 */

#ifndef CMH_RNG_H
#define CMH_RNG_H

struct platform_device;

int  cmh_rng_register(struct platform_device *pdev);
void cmh_rng_unregister(void);

/* debugfs timeout accessor (debug builds only) */
#ifdef CONFIG_CRYPTO_DEV_CMH_DEBUG
unsigned int *cmh_rng_timeout_drbg_ptr(void);
#endif

#endif /* CMH_RNG_H */
