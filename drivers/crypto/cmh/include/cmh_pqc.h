/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- PQC Algorithm Registration
 *
 * Registration/unregistration functions for PQC akcipher algorithms:
 * ML-DSA, SLH-DSA, LMS, XMSS.
 */

#ifndef CMH_PQC_H
#define CMH_PQC_H

int cmh_pqc_mldsa_register(void);
void cmh_pqc_mldsa_unregister(void);

int cmh_pqc_slhdsa_register(void);
void cmh_pqc_slhdsa_unregister(void);

int cmh_pqc_lms_register(void);
void cmh_pqc_lms_unregister(void);

int cmh_pqc_xmss_register(void);
void cmh_pqc_xmss_unregister(void);

#endif /* CMH_PQC_H */
