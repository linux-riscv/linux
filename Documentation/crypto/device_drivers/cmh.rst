.. SPDX-License-Identifier: GPL-2.0

=====================================
Rambus CryptoManager Hub (CMH) Driver
=====================================

Overview
========

The ``cmh`` driver supports the Rambus CryptoManager Hub hardware cryptographic
accelerator.  The hardware is accessed through a mailbox-based VCQ
(Virtual Command Queue) interface: the driver writes command sequences
into per-mailbox DMA queue buffers and rings a doorbell register; the
CryptoManager Hub embedded software (eSW) processes the commands and signals
completion via a per-mailbox interrupt.

The driver registers algorithms with the Linux kernel crypto subsystem
and exposes a management character device (``/dev/cmh_mgmt``) for
operations that have no standard crypto API binding.

Hardware Interface
==================

The CryptoManager Hub is presented as a platform device matched via Device Tree
(compatible ``"rambus,cmh-v1030"``).  The driver maps a single MMIO region
(the SIC -- System Interface Controller) whose sub-regions contain
per-mailbox doorbell, status, and command queue registers.

The driver manages a configurable number of mailboxes (default 2).
Each mailbox has a configurable number of slots (default 64) and a
configurable stride (default 512 bytes per slot).  The driver allocates
DMA-coherent memory for each mailbox queue during probe.

A mailbox is owned by a single host identity for the duration of a lock,
and the hardware permits only that identity to access it.  The platform
must present one consistent HOST ID for all accesses to a given mailbox,
independent of the issuing CPU; see the device-tree binding for this
integration requirement.

Interrupts are per-mailbox completion/error interrupts.  The driver
registers a threaded IRQ handler for each configured mailbox.

The eSW is loaded independently of this driver -- typically by the
boot firmware or a platform-specific loader -- so the driver does not
use ``request_firmware()``.  Instead it waits for the eSW to reach
mission mode during probe, bounded by a fixed timeout.

Supported Algorithms
====================

The driver registers the following algorithm families:

Hash (ahash)
  SHA-224, SHA-256, SHA-384, SHA-512, SHA3-224, SHA3-256, SHA3-384,
  SHA3-512, SHAKE-128, SHAKE-256, cSHAKE-128, cSHAKE-256, KMAC-128,
  KMAC-256, SM3 (10 hash + 2 cSHAKE + 2 KMAC + 1 SM3 = 15 algorithms)

HMAC (ahash)
  HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512,
  HMAC-SHA3-224, HMAC-SHA3-256, HMAC-SHA3-384, HMAC-SHA3-512
  (8 algorithms)

Symmetric Ciphers (skcipher)
  AES: ECB, CBC, CTR, CFB, XTS (5 algorithms)
  SM4: ECB, CBC, CTR, CFB, XTS (5 algorithms)
  ChaCha20 (1 algorithm)

AEAD
  AES-GCM, AES-CCM (2 algorithms)
  SM4-GCM, SM4-CCM (2 algorithms)
  ``rfc7539(chacha20,poly1305)``, ``rfc7539esp(chacha20,poly1305)``
  (2 algorithms)

MAC (ahash)
  CMAC(AES) (1 algorithm)
  CMAC(SM4), XCBC(SM4) (2 algorithms)
  Poly1305 (1 algorithm)

Public-Key, Key Agreement, and PQC Signatures
  RSA (akcipher, 1 algorithm)
  ECDSA P-256, P-384, P-521 (sig, 3 algorithms)
  SM2 (sig, verify-only, 1 algorithm)
  ECDH P-256, P-384, X25519 (kpp, 3 algorithms)
  ML-DSA-44, ML-DSA-65, ML-DSA-87 (sig, 3 algorithms)
  SLH-DSA: all 12 parameter sets (sig, 12 algorithms)
  LMS, LMS-HSS (sig, verify-only, 2 algorithms)
  XMSS, XMSS-MT (sig, verify-only, 2 algorithms)
  (ML-KEM keygen/encaps/decaps is available via ``/dev/cmh_mgmt``
  only -- see `Limitations`_.)

Hardware RNG
  DRBG-backed hwrng (``/dev/hwrng``, 1 algorithm)

All algorithm driver names use the ``rambus-cmh-`` prefix (e.g.
``rambus-cmh-sha256``, ``rambus-cmh-ecb-aes``, ``rambus-cmh-gcm-aes``,
``rambus-cmh-mldsa44``).  Names generally follow the kernel's hyphenated
template name; families that have no kernel template (e.g. ML-DSA) use
the concatenated upstream algorithm name (``mldsa44``).

Most algorithms register at priority 300 (301 for AES-CCM).
The ML-DSA ``sig`` algorithms register at priority 5001 to
outrank the kernel's generic software ML-DSA (priority 5000, which is
verify-only); the CMH driver provides full hardware sign and verify.

Request model
-------------

All crypto API operations are asynchronous: the driver queues each
request to its transaction-manager kthread and returns
``-EINPROGRESS``, invoking the caller's completion callback when the
hardware finishes.  Requests that set ``CRYPTO_TFM_REQ_MAY_BACKLOG``
are queued on a bounded backlog when the command queue is full;
without that flag a full queue is reported as
``-EBUSY``.  Hardware or eSW failures surface as ``-EIO``, malformed
requests as ``-EINVAL``, oversized requests as ``-EMSGSIZE`` or
``-EINVAL`` (see `Data-Size Limits`_), and unresponsive hardware as
``-ETIMEDOUT``.  The ``/dev/cmh_mgmt`` ioctls are, by contrast,
synchronous -- each ioctl blocks until the hardware completes.

Driver Architecture
===================

The driver is structured as follows:

Platform Driver
  Matches DT compatible ``"rambus,cmh-v1030"``.  Probe initializes all
  subsystems in order; remove tears them down in reverse.

Configuration
  Parses and validates DT properties (mailbox counts, slot sizes, and
  stride values).

MQI (Mailbox Queue Interface)
  Allocates DMA-coherent queue memory per mailbox.  Manages slot
  allocation, VCQ command writing, and doorbell ringing.

Transaction Manager
  A dedicated kthread dequeues crypto requests from a central command
  queue, builds VCQ command sequences, and submits them to mailbox
  slots.  Completion is signaled via wait queues.

Response Handler
  Per-mailbox threaded IRQ handlers walk completed slots, parse
  results, and fire request completions.  A configurable watchdog
  timer (the ``watchdog_ms`` debugfs knob, default 200 ms) detects
  stuck requests and escalates through ABORT, RESTART, and FLUSH
  recovery.

Key Management (``/dev/cmh_mgmt``)
  A misc character device providing ioctl-based access to datastore
  key CRUD, key derivation (KIC), PKE operations (EdDSA, SM2),
  PQC operations (ML-KEM, ML-DSA, SLH-DSA),
  EAC error register readback, and DRBG runtime configuration.
  See ``Documentation/ABI/testing/cmh-mgmt`` for the full ioctl list.

Power Management
  The driver implements ``DEFINE_SIMPLE_DEV_PM_OPS`` suspend/resume.
  On suspend, the transaction-manager kthread is stopped and pending
  transactions are drained, waiting up to ``drain_timeout_ms``
  (default 10000 ms); resume restarts the kthread.

Module Parameters
=================

The driver defines no production module parameters.  All mailbox
topology, per-core affinity, slot counts, and strides are taken from
Device Tree properties; the eSW boot timeout and queue depths are
built-in constants, and the runtime-tunable knobs are exposed via
debugfs (see `debugfs Counters`_ below).

A small set of debug-only parameters is compiled in only with
``CONFIG_CRYPTO_DEV_CMH_DEBUG``.  They exist solely to force alternate
geometries at ``insmod`` time during bringup and validation (for
example, to drive the mailbox-contention and cross-mailbox dispatch
paths without rebuilding the Device Tree); they default to "use the DT
value" and have no effect in a production build:

``mbx_count_override`` (uint, default 0)
  Override the DT mailbox count (0 = use DT) to force fewer
  mailboxes than the hardware provides.

``mbx_slots_override`` (uint, default 0)
  Override all per-mailbox slot counts (0 = use DT).

``mbx_round_robin`` (bool, default false)
  Ignore DT ``rambus,cores`` affinity and round-robin all cores
  across the configured mailboxes (0 = use DT affinity).

``skip_fw_check`` (bool, default false)
  Skip the SIC boot status and eSW mission-mode checks at probe.
  Allows the module to load before the eSW has booted.

sysfs Attributes
================

The driver exposes five read-only attributes under the platform
device sysfs directory: ``fw_version``, ``hw_version``,
``boot_status``, ``mbx_available``, and ``mbx_count``.  See
``Documentation/ABI/testing/sysfs-driver-cmh`` for the authoritative
per-attribute description.

debugfs Counters
================

When built with ``CONFIG_CRYPTO_DEV_CMH_DEBUG``, the driver creates
``/sys/kernel/debug/cmh/`` with three groups: per-mailbox counters
(``mbxN/``), transaction-manager statistics (``tm/``), and
runtime-tunable knobs (``config/``, including ``drain_timeout_ms``,
``watchdog_ms``, ``cmq_max_depth``, and ``backlog_max_depth``).  See
``Documentation/ABI/testing/debugfs-driver-cmh`` for the authoritative
per-file description.

Device Tree Binding
===================

See ``Documentation/devicetree/bindings/crypto/rambus,cmh-v1030.yaml`` for the
full DT binding schema and complete, schema-validated examples.  Each
mailbox owned by the host is a ``queue@N`` child node with its own
``reg`` (instance index), optional ``interrupts``, optional per-mailbox
VCQ ring geometry (``rambus,num-slots`` / ``rambus,slot-stride-bytes``,
defaulting to 64 and 512), and an optional ``rambus,cores`` list pinning
specific crypto cores to that mailbox.  Which crypto cores are present is read from the
SIC ``CORE_ENABLE`` register at probe, not described in the device tree.

The parent node may also carry up to three ``clocks`` (the main core
clock, a half-rate clock present only on configurations with
side-channel-protected cores, and the real-time tick clock) and an
optional ``reset-gpios``.  The driver enables every supplied clock and
acquires the reset line deasserted; it does not drive a reset sequence.
Both are absent when a separate management controller owns them, in
which case the driver drives neither.

User-Space Interfaces
=====================

``/dev/cmh_mgmt``
  Management character device.  Opening it requires ``CAP_SYS_ADMIN``.
  See ``Documentation/ABI/testing/cmh-mgmt`` for ioctl documentation.
  The UAPI header is ``<linux/cmh_mgmt_ioctl.h>``.

In-kernel crypto API
  All algorithms register with the standard kernel crypto API and are
  consumed by in-kernel users (dm-crypt, fscrypt, IPsec, kTLS, etc.).

  Keys provisioned inside the hardware via ``/dev/cmh_mgmt`` are
  referenced by an opaque hardware key identifier and are operated on
  through the ``/dev/cmh_mgmt`` ioctl interface, without ever exposing
  plaintext key material to user space.  See
  ``Documentation/ABI/testing/cmh-mgmt`` for key provisioning.

``/dev/hwrng``
  The DRBG-backed hardware RNG is available as a standard hwrng device.
  The driver configures the DRBG at probe with built-in defaults where
  the firmware permits it (stateless mode, or on the management host);
  otherwise the management host configures it out of band or via the
  ``/dev/cmh_mgmt`` ioctl, after which random data becomes available.

Limitations
===========

- LMS and XMSS support verify-only (no sign/keygen in hardware for
  stateful hash-based signatures).
- SM2 sig registration is verify-only (sign via ``/dev/cmh_mgmt`` ioctl).
- EdDSA (Ed25519/Ed448) is available only through ``/dev/cmh_mgmt``
  ioctls; no kernel ``sig`` registration.
- ML-KEM operations (encapsulate/decapsulate/keygen) are available only
  through ``/dev/cmh_mgmt`` ioctls; no standard kernel crypto API
  binding exists for KEM.

Data-Size Limits
================

The driver imposes data-size limits on several APIs.  These are
driver-level safety caps for kernel memory allocation unless noted
otherwise.

Symmetric / AEAD / MAC linearization caps:

==============================  =======  =======================================
Scope                           Limit    Origin
==============================  =======  =======================================
AES skcipher                    32 MiB   Driver-imposed DMA linearization cap
SM4 skcipher                    32 MiB   Driver-imposed DMA linearization cap
All AEAD + ChaCha20 skcipher    1 MiB    Driver-imposed DMA linearization cap
==============================  =======  =======================================

MAC and keyed-hash algorithms buffer all input in kernel memory because
the hardware exposes no keyed-MAC context save/restore.  Rather than
enforce a hard limit, most of them fall back to a software implementation
once the buffered input -- or a clone request -- exceeds the window:

====================  =======  =============================================
Algorithm             Window   Behaviour past the window
====================  =======  =============================================
``cmac(aes)``         64 KiB   switch to generic software cmac(aes)
``cmac(sm4)``         64 KiB   switch to generic software cmac(sm4)
``xcbc(sm4)``         64 KiB   switch to generic software xcbc(sm4)
``poly1305``          64 KiB   switch to the in-kernel Poly1305 library
``hmac(sha*)``        64 KiB   switch to generic software hmac(sha\*)
``hmac(sha3-*)``      64 KiB   switch to generic software hmac(sha3-\*)
``kmac128``           64 KiB   hard limit -- reject with -EINVAL
``kmac256``           64 KiB   hard limit -- reject with -EINVAL
====================  =======  =============================================

For hmac/cmac/xcbc the driver allocates and keys a matching generic
software MAC transform itself -- it registers with
``CRYPTO_ALG_NO_FALLBACK`` and does not rely on the crypto core's
automatic fallback; poly1305, which has no ``crypto_shash`` provider,
uses the in-kernel Poly1305 library directly.
After the switch, both arbitrarily long messages and transform ``clone``
(``.export()``/``.import()``) work at any length.

KMAC is the exception: there is neither a generic KMAC shash nor a KMAC
library, and the eSW rejects the save command while ``outlen != 0``
(always true for KMAC), so it can neither stream nor serialize its state.
It keeps a hard 64 KiB cap (``.update()`` returns ``-EINVAL`` past it)
and returns ``-EOPNOTSUPP`` from ``.export()``/``.import()``.  For
HMAC-SHA3 the same software fallback also avoids exposing the invertible
Keccak sponge state, which would otherwise allow key recovery; the eSW
likewise does not expose HMAC-SHA2 save/restore.

Pure hash algorithms (SHA-2, SHA-3, SHAKE, cSHAKE, SM3) have no data
limit because the hardware supports incremental save/restore.

cSHAKE uses save/restore for ``.export()``/``.import()`` but accumulates
data in ``.update()`` by design (the Keccak sponge has no block-alignment
boundary to trigger per-update HW submission, and HC_CMD_GATHER amortizes
the cost into a single finalize-time submission).

Asymmetric / PQC algorithm limits:

==============================  =========  ====================================
Scope                           Limit      Origin
==============================  =========  ====================================
RSA key size                    4096 bit   HW-imposed
ML-DSA message                  10 KiB     eSW-imposed (QSE ABI)
SLH-DSA message                 128 B      eSW-imposed (HCQ ABI)
SLH-DSA context                 255 B      Spec-imposed (FIPS 205)
LMS public key                  60 B       eSW-imposed (HCQ ABI)
LMS message                     256 B      eSW-imposed (HCQ ABI)
LMS signature                   13,364 B   eSW-imposed (HCQ ABI)
XMSS public key                 136 B      eSW-imposed (HCQ ABI)
XMSS message                    64 B       eSW-imposed (HCQ ABI)
XMSS signature                  27,688 B   eSW-imposed (HCQ ABI)
SM2 encrypt message             32 B       eSW KDF (single SM3 block)
==============================  =========  ====================================

Miscellaneous limits:

==============================  =========  ====================================
Scope                           Limit      Origin
==============================  =========  ====================================
cSHAKE/KMAC customization       256 B      VCQ slot layout constraint
KIC HKDF key                    64 B       Partially eSW-derived
KIC HKDF label                  56 B       VCQ slot layout constraint
Key/blob mgmt ioctls            256 KiB    Driver-imposed sanity cap
==============================  =========  ====================================
