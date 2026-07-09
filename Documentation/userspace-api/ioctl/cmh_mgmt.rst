.. SPDX-License-Identifier: GPL-2.0

=============================================
CMH Key Management ioctl Interface (cmh_mgmt)
=============================================

:Author: Cryptography Research, Inc. (CRI)
:Maintainer: linux-crypto@vger.kernel.org

Introduction
============

The ``/dev/cmh_mgmt`` character device provides user-space access to key
management, key derivation, public-key, and post-quantum cryptographic
operations on the CryptoManager Hub (CMH) hardware accelerator.

The device is created by the ``cmh`` kernel module as a ``misc_device``.
All operations are synchronous -- the ioctl blocks until the hardware
completes.  Opening the device requires ``CAP_SYS_ADMIN``.

All ioctl argument structures are versioned: user space sets the
``version`` field to ``CMH_MGMT_V1`` (currently 1).  This allows the
driver to extend structures in the future without breaking the ABI.

Data types and ioctl numbers are defined in
``<uapi/linux/cmh_mgmt_ioctl.h>``.  The ioctl type letter is ``'J'``
(0x4A).

Error Handling
==============

Unless otherwise noted, all ioctls return 0 on success and a negative
errno on failure.  Common error codes:

========== =============================================================
``EINVAL`` Invalid ``version`` field, unsupported parameter, or
           out-of-range length.
``EFAULT`` Failed to copy data to/from user space.
``ENOMEM`` Kernel memory allocation failed.
``EIO``    Hardware returned an error (eSW command failure).
``ENOENT`` Key not found (``KEY_FIND``, ``KEY_LIST``).
========== =============================================================

Datastore Concepts
==================

The CMH hardware maintains an embedded datastore managed by the eSW
firmware.  Objects in the datastore are identified by a 64-bit reference
(``ref``) and optionally by a 64-bit Content ID (``cid``).

Two storage classes exist:

**Temporary (SYS_REF_TEMP)**
  Lifetime is scoped to a single mailbox slot.  The eSW firmware
  reclaims the object when the slot is reused.  Used for raw-key
  provisioning via ``KEY_NEW`` + ``KEY_WRITE``.

**Persistent (SYS_REF_PERSIST)**
  Survives across mailbox slots.  Requires explicit deletion via
  ``KEY_DELETE``.  Identified by CID; resolved to a per-mailbox ref
  via ``KEY_FIND``.

Mailbox Dispatch
================

All ``/dev/cmh_mgmt`` ioctls are submitted on a single management
mailbox.  This is a structural requirement of the eSW datastore model,
not a tunable:

* Datastore access control is **per-mailbox**.  ``KEY_NEW`` grants the
  creating mailbox read/write/execute access; other mailboxes have none
  until granted.  The returned 64-bit ``ref`` encodes a randomised
  offset and does **not** carry the owning mailbox, so an operation that
  receives only a ``ref`` (``KEY_GRANT``, ``KEY_READ``, ``KEY_DELETE``,
  ``DS_EXPORT``) cannot itself determine which mailbox owns the object.
  Using one fixed management mailbox guarantees that a key's create,
  modify, grant, read and hardware-held-key compute steps all share the
  mailbox that holds its access rights, without exposing mailbox
  identity in the UABI.  User space may still widen a key's access to
  additional mailboxes via ``KEY_GRANT``.

* The eSW ``SYS_REF_TEMP`` scratch store is per-mailbox and persists
  across ioctl calls, so a multi-step flow that derives into
  ``SYS_REF_TEMP`` (for example a ``KIC_*`` derivation) and later
  consumes it (``DS_EXPORT`` with ``wrap_key = SYS_REF_TEMP``) requires
  both calls to use the same mailbox.

Per-core ``cri,mbx`` device-tree affinity applies to the *stateless*
in-kernel crypto API path, which carries no datastore state between
requests and is balanced across mailboxes by the driver.

Key Types
=========

The ``ds_type`` field in ``KEY_NEW`` and ``KEY_WRITE`` selects the
datastore object type.  Values are defined as ``CMH_DS_*`` constants:

=================================  =====  ==============================
Constant                           Value  Description
=================================  =====  ==============================
``CMH_DS_RAW_VALUE``               1      Raw byte array
``CMH_DS_AES_KEY``                 2      AES key (128/192/256-bit)
``CMH_DS_AES_XTS_KEY``             3      AES-XTS key (256/512-bit)
``CMH_DS_HMAC_KEY``                4      HMAC key
``CMH_DS_KMAC_KEY``                5      KMAC key
``CMH_DS_SM4_KEY``                 6      SM4 key (128-bit)
``CMH_DS_CHACHA20_KEY``            7      ChaCha20 key (256-bit)
``CMH_DS_RSA_PRIV_KEY``            10     RSA private key
``CMH_DS_RSA_PUB_KEY``             11     RSA public key
``CMH_DS_RSA_CRT_KEY``             12     RSA CRT private key
``CMH_DS_ECDSA_PRIV_KEY``          13     ECDSA private key
``CMH_DS_ECDSA_PUB_KEY``           14     ECDSA public key
``CMH_DS_ECDH_PRIV_KEY``           15     ECDH private key
``CMH_DS_EDDSA_PRIV_KEY``          16     EdDSA private key
``CMH_DS_SHARED_SECRET``           17     Shared secret
``CMH_DS_SM2_PRIV_KEY``            18     SM2 private key
``CMH_DS_ML_KEM_DK``               20     ML-KEM decapsulation key
``CMH_DS_ML_DSA_SK``               21     ML-DSA secret key
``CMH_DS_SLHDSA_SK``               25     SLH-DSA secret key
=================================  =====  ==============================

Key Flags
=========

The ``flags`` field in ``KEY_NEW`` and ``KEY_WRITE`` is a bitmask:

==================  ===========  ========================================
Flag                Bit          Description
==================  ===========  ========================================
``CMH_FLAG_PT``     16           Key can be read as plaintext
``CMH_FLAG_XC``     17           Key can be exported over XC bus
``CMH_FLAG_SCA``    18           SCA key stored in 2 shares
==================  ===========  ========================================

Elliptic Curve IDs
==================

Curve identifiers for PKE operations (``curve`` field):

==========================  =====
Constant                    Value
==========================  =====
``CMH_CURVE_P192``          0x01
``CMH_CURVE_P224``          0x02
``CMH_CURVE_P256``          0x03
``CMH_CURVE_P384``          0x04
``CMH_CURVE_P521``          0x05
``CMH_CURVE_SECP256K1``     0x07
``CMH_CURVE_BP192R1``       0x11
``CMH_CURVE_BP224R1``       0x12
``CMH_CURVE_BP256R1``       0x13
``CMH_CURVE_BP320R1``       0x14
``CMH_CURVE_BP384R1``       0x15
``CMH_CURVE_BP512R1``       0x16
``CMH_CURVE_SM2``           0x18
``CMH_CURVE_25519``         0x21
``CMH_CURVE_448``           0x22
==========================  =====

Key Management ioctls
=====================

CMH_IOCTL_KEY_NEW
-----------------

Create a new empty datastore object.

:Direction: ``_IOWR``
:Number: 0x01
:Argument: ``struct cmh_ioctl_key_new``

::

  struct cmh_ioctl_key_new {
      __u32 version;     /* must be CMH_MGMT_V1 */
      __u32 ds_type;     /* CMH_DS_* key type */
      __u32 len;         /* key length in bytes */
      __u32 flags;       /* CMH_FLAG_* */
      __u64 cid;         /* caller ID (name) for the key */
      __u64 ref;         /* [out] key reference */
  };

The returned ``ref`` is used in subsequent ``KEY_WRITE``, ``KEY_READ``,
and crypto operation ioctls.

CMH_IOCTL_KEY_NEW_RANDOM
------------------------

Create a new datastore object filled with hardware-generated random data.

:Direction: ``_IOWR``
:Number: 0x0B
:Argument: ``struct cmh_ioctl_key_new``

Same structure as ``KEY_NEW``.  The hardware DRBG fills the object with
``len`` random bytes.

CMH_IOCTL_KEY_WRITE
-------------------

Write key material into a previously created datastore object.

:Direction: ``_IOW``
:Number: 0x02
:Argument: ``struct cmh_ioctl_key_write``

::

  struct cmh_ioctl_key_write {
      __u32 version;
      __u32 len;         /* key data length */
      __u32 ds_type;     /* CMH_DS_* key type */
      __u32 flags;       /* CMH_FLAG_* */
      __u64 ref;         /* key reference from KEY_NEW */
      __u64 wrap_key;    /* wrapping key ref (CMH_REF_NONE = plaintext) */
      __u64 data;        /* user-space pointer to key material */
  };

If ``wrap_key`` is ``CMH_REF_NONE`` (0), key material is written in
plaintext.  Otherwise, the data is unwrapped using the specified
wrapping key.

CMH_IOCTL_KEY_READ
------------------

Read key material from a datastore object.

:Direction: ``_IOWR``
:Number: 0x03
:Argument: ``struct cmh_ioctl_key_read``

::

  struct cmh_ioctl_key_read {
      __u32 version;
      __u32 len;         /* buffer length */
      __u64 ref;         /* key reference */
      __u64 wrap_key;    /* wrapping key ref (CMH_REF_NONE = plaintext) */
      __u64 data;        /* user-space pointer to output buffer */
      __u32 out_len;     /* [out] actual bytes written */
      __u32 __reserved;
  };

Plaintext reads require the ``CMH_FLAG_PT`` attribute on the key.
The eSW prepends a 16-byte header (``CMH_SYS_WRAP_HDR_SIZE``) even
for plaintext reads; the output buffer must accommodate this.  The
output overhead is ``CMH_DS_EXPORT_OVERHEAD_PLAIN`` (16 bytes) for
plaintext reads and ``CMH_DS_EXPORT_OVERHEAD_WRAPPED`` (48 bytes:
16-byte header + 16-byte nonce + 16-byte tag) for wrapped reads.

CMH_IOCTL_KEY_FIND
------------------

Resolve a Content ID to a datastore reference.

:Direction: ``_IOWR``
:Number: 0x04
:Argument: ``struct cmh_ioctl_key_find``

::

  struct cmh_ioctl_key_find {
      __u32 version;
      __u32 __reserved;
      __u64 cid;         /* caller ID to search for */
      __u64 ref;         /* [out] resolved key reference */
      __u32 len;         /* [out] key length */
      __u32 type;        /* [out] key type */
  };

Returns ``-ENOENT`` if no object with the given CID exists.

CMH_IOCTL_KEY_LIST
------------------

Iterate datastore objects.

:Direction: ``_IOWR``
:Number: 0x0E
:Argument: ``struct cmh_ioctl_key_list``

::

  struct cmh_ioctl_key_list {
      __u32 version;
      __u32 __reserved;
      __u64 start_ref;   /* starting DS reference (0 = first) */
      __u64 ref;         /* [out] object reference */
      __u64 cid;         /* [out] caller ID */
      __u32 len;         /* [out] object length */
      __u32 type;        /* [out] object type */
  };

Pass ``start_ref=0`` to begin from the first object.  On return, pass
the returned ``ref`` as ``start_ref`` in the next call.  Iteration ends
when ``ref == 0``.

CMH_IOCTL_KEY_GRANT
-------------------

Set per-mailbox access permissions on a datastore object.

:Direction: ``_IOW``
:Number: 0x05
:Argument: ``struct cmh_ioctl_key_grant``

::

  struct cmh_ioctl_key_grant {
      __u32 version;
      __u32 __reserved;
      __u64 ref;         /* key reference */
      __u64 read;        /* per-MBX read permission bitfield */
      __u64 write;       /* per-MBX write permission bitfield */
      __u64 execute;     /* per-MBX execute permission bitfield */
  };

CMH_IOCTL_KEY_DELETE
--------------------

Delete a datastore object (persistent keys only).

:Direction: ``_IOW``
:Number: 0x06
:Argument: ``struct cmh_ioctl_key_grant``

Uses the same structure as ``KEY_GRANT``; only the ``ref`` field is
used.

Datastore Export/Import ioctls
==============================

CMH_IOCTL_DS_EXPORT
-------------------

Export the entire datastore as an encrypted blob.

:Direction: ``_IOWR``
:Number: 0x07
:Argument: ``struct cmh_ioctl_ds_export``

::

  struct cmh_ioctl_ds_export {
      __u32 version;
      __u32 len;         /* buffer length */
      __u64 cid;         /* caller ID for response tagging */
      __u64 wrap_key;    /* wrapping key ref (CMH_REF_NONE = plaintext) */
      __u64 data;        /* user-space pointer to output buffer */
      __u32 out_len;     /* [out] actual bytes written */
      __u32 __reserved;
  };

CMH_IOCTL_DS_IMPORT
-------------------

Import a previously exported datastore blob.

:Direction: ``_IOW``
:Number: 0x08
:Argument: ``struct cmh_ioctl_ds_import``

::

  struct cmh_ioctl_ds_import {
      __u32 version;
      __u32 len;         /* blob length */
      __u64 wrap_key;    /* wrapping key ref (CMH_REF_NONE = plaintext) */
      __u64 data;        /* user-space pointer to import blob */
  };

Key Derivation ioctls (KIC)
===========================

The Key Initialization Core (KIC) provides hardware key derivation from
OTP-provisioned base keys.  Up to 8 base keys are available
(``CMH_KIC_KEY1`` through ``CMH_KIC_KEY8``).

CMH_IOCTL_KIC_HKDF1
--------------------

HKDF-based key derivation (single-step, label only).

:Direction: ``_IOWR``
:Number: 0x09
:Argument: ``struct cmh_ioctl_kic_hkdf1``

::

  struct cmh_ioctl_kic_hkdf1 {
      __u32 version;
      __u32 key_len;     /* output key length */
      __u64 base_key;    /* KIC base key reference */
      __u64 cid;         /* CID for the new DS entry */
      __u64 label;       /* user-space pointer to label data */
      __u32 label_len;   /* label length in bytes */
      __u32 flags;       /* CMH_KIC_FLAG_* */
      __u64 ref;         /* [out] derived key reference */
  };

If ``CMH_KIC_FLAG_TEMP`` is set, the result is stored in the temporary
datastore (not persistent).

CMH_IOCTL_KIC_HKDF2
--------------------

HKDF-based key derivation (two-step, with salt key).

:Direction: ``_IOWR``
:Number: 0x0A
:Argument: ``struct cmh_ioctl_kic_hkdf2``

::

  struct cmh_ioctl_kic_hkdf2 {
      __u32 version;
      __u32 key_len;
      __u64 base_key;
      __u64 salt_key;    /* salt key reference (CMH_REF_NONE = no salt) */
      __u64 cid;
      __u64 label;
      __u32 label_len;
      __u32 flags;
      __u64 ref;         /* [out] derived key reference */
  };

CMH_IOCTL_KIC_AES_CMAC_KDF
---------------------------

AES-CMAC-based key derivation (NIST SP 800-108).

:Direction: ``_IOWR``
:Number: 0x0C
:Argument: ``struct cmh_ioctl_kic_aes_cmac_kdf``

::

  struct cmh_ioctl_kic_aes_cmac_kdf {
      __u32 version;
      __u32 key_len;     /* base & output key length (must be 32) */
      __u64 base_key;
      __u64 cid;
      __u64 label;
      __u32 label_len;
      __u32 flags;
      __u64 ref;         /* [out] derived key reference */
  };

CMH_IOCTL_KIC_DKEK_DERIVE
--------------------------

Derive a Device Key Encryption Key (DKEK) for secure key export.

:Direction: ``_IOWR``
:Number: 0x0D
:Argument: ``struct cmh_ioctl_kic_dkek_derive``

::

  struct cmh_ioctl_kic_dkek_derive {
      __u32 version;
      __u32 host_id;     /* target host ID (0 = caller's own) */
      __u64 base_key;
      __u64 cid;
      __u64 metadata;    /* user-space pointer to metadata */
      __u32 metadata_len;
      __u32 flags;
      __u64 ref;         /* [out] derived KEK reference */
  };

PKE (Public Key Engine) ioctls
==============================

RSA Operations
--------------

CMH_IOCTL_PKE_RSA_ENC
~~~~~~~~~~~~~~~~~~~~~~

RSA public-key encryption.

:Direction: ``_IOWR``
:Number: 0x10
:Argument: ``struct cmh_ioctl_pke_rsa_enc``

The public key (e, n) is passed as raw user-space buffers.

CMH_IOCTL_PKE_RSA_DEC
~~~~~~~~~~~~~~~~~~~~~~

RSA private-key decryption using a datastore key reference.

:Direction: ``_IOWR``
:Number: 0x11
:Argument: ``struct cmh_ioctl_pke_rsa_dec``

CMH_IOCTL_PKE_RSA_CRT_DEC
~~~~~~~~~~~~~~~~~~~~~~~~~~

RSA CRT private-key decryption (faster, uses CRT key format).

:Direction: ``_IOWR``
:Number: 0x12
:Argument: ``struct cmh_ioctl_pke_rsa_crt_dec``

CMH_IOCTL_PKE_RSA_KEYGEN
~~~~~~~~~~~~~~~~~~~~~~~~~

Generate an RSA key pair in hardware.

:Direction: ``_IOWR``
:Number: 0x13
:Argument: ``struct cmh_ioctl_pke_rsa_keygen``

Returns private key and optional CRT key as datastore references.
The modulus is written back to user space.

ECDSA Operations
----------------

CMH_IOCTL_PKE_ECDSA_SIGN
~~~~~~~~~~~~~~~~~~~~~~~~~

ECDSA signature generation using a datastore private key.

:Direction: ``_IOWR``
:Number: 0x14
:Argument: ``struct cmh_ioctl_pke_ecdsa_sign``

CMH_IOCTL_PKE_ECDH
~~~~~~~~~~~~~~~~~~~

Compute ECDH shared secret from a peer public key and a datastore
private key.

:Direction: ``_IOWR``
:Number: 0x16
:Argument: ``struct cmh_ioctl_pke_ecdh``

If ``CMH_PKE_FLAG_DS_RESULT`` is set, the shared secret is stored in
the datastore and a reference is returned instead of raw bytes.

CMH_IOCTL_PKE_ECDH_KEYGEN
~~~~~~~~~~~~~~~~~~~~~~~~~~

Derive a public key from a datastore private key.

:Direction: ``_IOWR``
:Number: 0x17
:Argument: ``struct cmh_ioctl_pke_ecdh_keygen``

EdDSA Operations
----------------

CMH_IOCTL_PKE_EDDSA_SIGN
~~~~~~~~~~~~~~~~~~~~~~~~~

EdDSA (Ed25519/Ed448) signature generation.

:Direction: ``_IOWR``
:Number: 0x18
:Argument: ``struct cmh_ioctl_pke_eddsa_sign``

Note: the ``digest`` field is the full message (pure EdDSA), not a
pre-computed hash.

CMH_IOCTL_PKE_EDDSA_VERIFY
~~~~~~~~~~~~~~~~~~~~~~~~~~~

EdDSA signature verification.

:Direction: ``_IOW``
:Number: 0x19
:Argument: ``struct cmh_ioctl_pke_eddsa_verify``

EC Key Management
-----------------

CMH_IOCTL_PKE_EC_KEYGEN
~~~~~~~~~~~~~~~~~~~~~~~~

Generate an EC private key in the hardware datastore.

:Direction: ``_IOWR``
:Number: 0x1A
:Argument: ``struct cmh_ioctl_pke_ec_keygen``

CMH_IOCTL_PKE_EC_PUBGEN
~~~~~~~~~~~~~~~~~~~~~~~~

Derive the public key from a datastore private key.

:Direction: ``_IOWR``
:Number: 0x1B
:Argument: ``struct cmh_ioctl_pke_ec_pubgen``

CMH_IOCTL_PKE_EDDSA_KEYGEN_SCA
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Generate a 2-share SCA-protected Ed448 private key.

:Direction: ``_IOWR``
:Number: 0x1C
:Argument: ``struct cmh_ioctl_pke_eddsa_keygen_sca``

Post-Quantum Cryptography (PQC) ioctls
=======================================

PQC operations support the following flags in the ``flags`` field:

============================  ====  ====================================
Flag                          Bit   Description
============================  ====  ====================================
``CMH_QSE_FLAG_MASKED``       0     Use masked (SCA-resistant) HW path
``CMH_QSE_FLAG_DS_REF``       1     Store key output in DS, return ref
``CMH_QSE_FLAG_HW_RNG``       2     Use HW RNG for seed/randomness
============================  ====  ====================================

ML-KEM (FIPS 203)
-----------------

CMH_IOCTL_ML_KEM_KEYGEN
~~~~~~~~~~~~~~~~~~~~~~~~

Generate an ML-KEM key pair.

:Direction: ``_IOWR``
:Number: 0x20
:Argument: ``struct cmh_ioctl_ml_kem_keygen``

Security parameter ``k`` selects the strength: 2 (ML-KEM-512),
3 (ML-KEM-768), or 4 (ML-KEM-1024).

CMH_IOCTL_ML_KEM_ENC
~~~~~~~~~~~~~~~~~~~~~

ML-KEM encapsulation.  Produces ciphertext and shared secret.

:Direction: ``_IOWR``
:Number: 0x21
:Argument: ``struct cmh_ioctl_ml_kem_enc``

CMH_IOCTL_ML_KEM_DEC
~~~~~~~~~~~~~~~~~~~~~

ML-KEM decapsulation.  Recovers shared secret from ciphertext.

:Direction: ``_IOWR``
:Number: 0x22
:Argument: ``struct cmh_ioctl_ml_kem_dec``

ML-DSA (FIPS 204)
-----------------

CMH_IOCTL_ML_DSA_KEYGEN
~~~~~~~~~~~~~~~~~~~~~~~~

Generate an ML-DSA key pair.

:Direction: ``_IOWR``
:Number: 0x23
:Argument: ``struct cmh_ioctl_ml_dsa_keygen``

Security parameter ``mode`` selects the strength: 2 (ML-DSA-44),
3 (ML-DSA-65), or 5 (ML-DSA-87).

.. note::

   When ``CMH_QSE_FLAG_DS_REF`` keeps the secret key in the datastore,
   the public key returned in ``pk`` is the only copy: there is no
   operation to derive the public key from the secret-key reference
   for ML-DSA.  User space must persist ``pk`` at keygen time.

CMH_IOCTL_ML_DSA_SIGN
~~~~~~~~~~~~~~~~~~~~~~

ML-DSA signature generation.

:Direction: ``_IOWR``
:Number: 0x24
:Argument: ``struct cmh_ioctl_ml_dsa_sign``

If ``mlen`` is set to ``CMH_ML_DSA_MLEN_EXTERNAL_MU`` (0xFFFFFFFF),
the ``m`` pointer is interpreted as a 64-byte pre-hashed mu value
(ExternalMu mode).

CMH_IOCTL_SLHDSA_KEYGEN
~~~~~~~~~~~~~~~~~~~~~~~~

Generate an SLH-DSA key pair.

:Direction: ``_IOWR``
:Number: 0x28
:Argument: ``struct cmh_ioctl_slhdsa_keygen``

.. note::

   When ``CMH_QSE_FLAG_DS_REF`` keeps the secret key in the datastore,
   the public key returned in ``pk`` is the only copy: there is no
   operation to derive the public key from the secret-key reference
   for SLH-DSA.  User space must persist ``pk`` at keygen time.

CMH_IOCTL_SLHDSA_SIGN
~~~~~~~~~~~~~~~~~~~~~~

SLH-DSA signature generation (pure mode).

:Direction: ``_IOWR``
:Number: 0x29
:Argument: ``struct cmh_ioctl_slhdsa_sign``

CMH_IOCTL_SLHDSA_SIGN_PREHASH
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

SLH-DSA pre-hash signature generation.

:Direction: ``_IOWR``
:Number: 0x2D
:Argument: ``struct cmh_ioctl_slhdsa_sign_prehash``

The ``prehash_algo`` field selects the hash algorithm
(``CMH_SLHDSA_PREHASH_SHA256``, etc.).

CMH_IOCTL_SM2_ENC_POINT
~~~~~~~~~~~~~~~~~~~~~~~~

:Direction: ``_IOWR``
:Number: 0x33
:Argument: ``struct cmh_ioctl_sm2_enc_point``

CMH_IOCTL_SM2_ENC_HASH
~~~~~~~~~~~~~~~~~~~~~~~

:Direction: ``_IOWR``
:Number: 0x37
:Argument: ``struct cmh_ioctl_sm2_enc_hash``

CMH_IOCTL_SM2_DEC_POINT
~~~~~~~~~~~~~~~~~~~~~~~~

:Direction: ``_IOWR``
:Number: 0x32
:Argument: ``struct cmh_ioctl_sm2_dec_point``

CMH_IOCTL_SM2_DEC_HASH
~~~~~~~~~~~~~~~~~~~~~~~

:Direction: ``_IOWR``
:Number: 0x36
:Argument: ``struct cmh_ioctl_sm2_dec_hash``

SM2 Key Exchange (GM/T 0003.3)
------------------------------

The key exchange protocol is a multi-step flow:

1. ``EC_KEYGEN(CMH_CURVE_SM2)`` -- generate a long-lived private key.
2. ``EC_PUBGEN`` -- derive the public key.
3. ``SM2_ID_DIGEST`` -- compute the SM3 identity digest (ZA).
4. ``SM2_ECDH_KEYGEN`` -- generate an ephemeral session key.
5. Exchange session keys with the peer.
6. ``SM2_ECDH`` -- compute the shared point.
7. ``SM2_ECDH_HASH`` -- derive the shared key from the shared point
   and both parties' ZA digests.

CMH_IOCTL_SM2_ECDH_KEYGEN
~~~~~~~~~~~~~~~~~~~~~~~~~~

:Direction: ``_IOWR``
:Number: 0x30
:Argument: ``struct cmh_ioctl_sm2_ecdh_keygen``

``nonce_len`` must be 0 or 32.  If ``nonce_len=0``, the hardware
generates the ephemeral scalar and writes it back to the ``nonce``
buffer.

CMH_IOCTL_SM2_ECDH
~~~~~~~~~~~~~~~~~~~

:Direction: ``_IOWR``
:Number: 0x31
:Argument: ``struct cmh_ioctl_sm2_ecdh``

If ``shared_point_ref`` points to a non-zero value, the shared point
is kept in the datastore for use by ``SM2_ECDH_HASH``.

CMH_IOCTL_SM2_ID_DIGEST
~~~~~~~~~~~~~~~~~~~~~~~~

Compute the SM3 identity digest (ZA) for a public key and identity
string.

:Direction: ``_IOWR``
:Number: 0x34
:Argument: ``struct cmh_ioctl_sm2_id_digest``

CMH_IOCTL_SM2_ECDH_HASH
~~~~~~~~~~~~~~~~~~~~~~~~

Derive the shared key from the shared point and ZA digests.

:Direction: ``_IOWR``
:Number: 0x35
:Argument: ``struct cmh_ioctl_sm2_ecdh_hash``

.. important::

   The digest fields use **absolute** ordering per GM/T 0003.3, not
   relative own/peer ordering.  Both parties must pass:

   - ``peer_id_digest`` = Z_A (initiator's digest) -- hashed first
   - ``id_digest`` = Z_B (responder's digest) -- hashed second

Hardware Management ioctls
==========================

CMH_IOCTL_EAC_READ
-------------------

Read and clear the hardware Error and Alarm Controller registers.

:Direction: ``_IOWR``
:Number: 0x0F
:Argument: ``struct cmh_ioctl_eac_read``

::

  struct cmh_ioctl_eac_read {
      __u32 version;
      __u32 __reserved;
      __u64 mailbox_notification;
      __u32 hw_error;
      __u32 hw_nmi;
      __u32 hw_panic;
      __u32 safety_fatal;
      __u32 safety_notification;
      __u32 sw_info0;
      __u32 sw_info1;
      __u32 sram_bank_errors[4];
      __u32 __pad;
  };

The eSW atomically reads and clears the registers on each call.
Successive reads show only new events since the last read.

CMH_IOCTL_DRBG_CONFIG
----------------------

Configure the hardware DRBG before first use.

:Direction: ``_IOW``
:Number: 0x40
:Argument: ``struct cmh_ioctl_drbg_config``

::

  struct cmh_ioctl_drbg_config {
      __u32 version;
      __u32 entropy_ratio;       /* CMH_DRBG_RATIO_* */
      __u32 security_strength;   /* CMH_DRBG_STRENGTH_* */
      __u32 __reserved;
  };

This is a management operation normally performed once at system
startup.  Must be called before any ``hwrng`` reads or DRBG generate
operations.

ioctl Number Summary
====================

======================================  ====  ====  =========================================
ioctl                                   Dir   Seq   Argument
======================================  ====  ====  =========================================
``CMH_IOCTL_KEY_NEW``                   IOWR  0x01  ``cmh_ioctl_key_new``
``CMH_IOCTL_KEY_WRITE``                 IOW   0x02  ``cmh_ioctl_key_write``
``CMH_IOCTL_KEY_READ``                  IOWR  0x03  ``cmh_ioctl_key_read``
``CMH_IOCTL_KEY_FIND``                  IOWR  0x04  ``cmh_ioctl_key_find``
``CMH_IOCTL_KEY_GRANT``                 IOW   0x05  ``cmh_ioctl_key_grant``
``CMH_IOCTL_KEY_DELETE``                IOW   0x06  ``cmh_ioctl_key_grant``
``CMH_IOCTL_DS_EXPORT``                 IOWR  0x07  ``cmh_ioctl_ds_export``
``CMH_IOCTL_DS_IMPORT``                 IOW   0x08  ``cmh_ioctl_ds_import``
``CMH_IOCTL_KIC_HKDF1``                 IOWR  0x09  ``cmh_ioctl_kic_hkdf1``
``CMH_IOCTL_KIC_HKDF2``                 IOWR  0x0A  ``cmh_ioctl_kic_hkdf2``
``CMH_IOCTL_KEY_NEW_RANDOM``            IOWR  0x0B  ``cmh_ioctl_key_new``
``CMH_IOCTL_KIC_AES_CMAC_KDF``          IOWR  0x0C  ``cmh_ioctl_kic_aes_cmac_kdf``
``CMH_IOCTL_KIC_DKEK_DERIVE``           IOWR  0x0D  ``cmh_ioctl_kic_dkek_derive``
``CMH_IOCTL_KEY_LIST``                  IOWR  0x0E  ``cmh_ioctl_key_list``
``CMH_IOCTL_EAC_READ``                  IOWR  0x0F  ``cmh_ioctl_eac_read``
``CMH_IOCTL_PKE_RSA_ENC``               IOWR  0x10  ``cmh_ioctl_pke_rsa_enc``
``CMH_IOCTL_PKE_RSA_DEC``               IOWR  0x11  ``cmh_ioctl_pke_rsa_dec``
``CMH_IOCTL_PKE_RSA_CRT_DEC``           IOWR  0x12  ``cmh_ioctl_pke_rsa_crt_dec``
``CMH_IOCTL_PKE_RSA_KEYGEN``            IOWR  0x13  ``cmh_ioctl_pke_rsa_keygen``
``CMH_IOCTL_PKE_ECDSA_SIGN``            IOWR  0x14  ``cmh_ioctl_pke_ecdsa_sign``
``CMH_IOCTL_PKE_ECDH``                  IOWR  0x16  ``cmh_ioctl_pke_ecdh``
``CMH_IOCTL_PKE_ECDH_KEYGEN``           IOWR  0x17  ``cmh_ioctl_pke_ecdh_keygen``
``CMH_IOCTL_PKE_EDDSA_SIGN``            IOWR  0x18  ``cmh_ioctl_pke_eddsa_sign``
``CMH_IOCTL_PKE_EDDSA_VERIFY``          IOW   0x19  ``cmh_ioctl_pke_eddsa_verify``
``CMH_IOCTL_PKE_EC_KEYGEN``             IOWR  0x1A  ``cmh_ioctl_pke_ec_keygen``
``CMH_IOCTL_PKE_EC_PUBGEN``             IOWR  0x1B  ``cmh_ioctl_pke_ec_pubgen``
``CMH_IOCTL_PKE_EDDSA_KEYGEN_SCA``      IOWR  0x1C  ``cmh_ioctl_pke_eddsa_keygen_sca``
``CMH_IOCTL_ML_KEM_KEYGEN``             IOWR  0x20  ``cmh_ioctl_ml_kem_keygen``
``CMH_IOCTL_ML_KEM_ENC``                IOWR  0x21  ``cmh_ioctl_ml_kem_enc``
``CMH_IOCTL_ML_KEM_DEC``                IOWR  0x22  ``cmh_ioctl_ml_kem_dec``
``CMH_IOCTL_ML_DSA_KEYGEN``             IOWR  0x23  ``cmh_ioctl_ml_dsa_keygen``
``CMH_IOCTL_ML_DSA_SIGN``               IOWR  0x24  ``cmh_ioctl_ml_dsa_sign``
``CMH_IOCTL_SLHDSA_KEYGEN``             IOWR  0x28  ``cmh_ioctl_slhdsa_keygen``
``CMH_IOCTL_SLHDSA_SIGN``               IOWR  0x29  ``cmh_ioctl_slhdsa_sign``
``CMH_IOCTL_SLHDSA_SIGN_PREHASH``       IOWR  0x2D  ``cmh_ioctl_slhdsa_sign_prehash``
``CMH_IOCTL_SM2_ECDH_KEYGEN``           IOWR  0x30  ``cmh_ioctl_sm2_ecdh_keygen``
``CMH_IOCTL_SM2_ECDH``                  IOWR  0x31  ``cmh_ioctl_sm2_ecdh``
``CMH_IOCTL_SM2_DEC_POINT``             IOWR  0x32  ``cmh_ioctl_sm2_dec_point``
``CMH_IOCTL_SM2_ENC_POINT``             IOWR  0x33  ``cmh_ioctl_sm2_enc_point``
``CMH_IOCTL_SM2_ID_DIGEST``             IOWR  0x34  ``cmh_ioctl_sm2_id_digest``
``CMH_IOCTL_SM2_ECDH_HASH``             IOWR  0x35  ``cmh_ioctl_sm2_ecdh_hash``
``CMH_IOCTL_SM2_DEC_HASH``              IOWR  0x36  ``cmh_ioctl_sm2_dec_hash``
``CMH_IOCTL_SM2_ENC_HASH``              IOWR  0x37  ``cmh_ioctl_sm2_enc_hash``
``CMH_IOCTL_DRBG_CONFIG``               IOW   0x40  ``cmh_ioctl_drbg_config``
======================================  ====  ====  =========================================

Migration Plan
==============

Several ioctl commands provide operations that may gain dedicated kernel
crypto API bindings in the future.  When those APIs land, the driver will
register through them and the corresponding ioctls will be deprecated
(retained for backward compatibility but no longer the primary interface):

- **EdDSA** (``CMH_IOCTL_PKE_EDDSA_*``): will migrate to the kernel ``sig``
  API once ed25519/ed448 algorithm types are accepted upstream.

- **ML-KEM** (``CMH_IOCTL_ML_KEM_*``): will migrate to the kernel KEM API
  once the in-flight KEM subsystem series lands.

- **Key lifecycle** (``CMH_IOCTL_KEY_*``): will evaluate integration with
  the kernel KEYS subsystem (trusted-keys / encrypted-keys) as a follow-up
  series.

Operations that are inherently vendor-specific (EAC Chip Authentication,
KIC key derivation, SM2 key exchange, DRBG configuration, datastore
export/import) will remain as ioctls permanently -- they have no
corresponding kernel abstraction and are not expected to gain one.
