.. SPDX-License-Identifier: GPL-2.0

====================================
CRI CryptoManager Hub (CMH) Driver
====================================

Overview
========

The ``cmh`` driver supports the CRI CryptoManager Hub hardware cryptographic
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
(compatible ``"cri,cmh"``).  The driver maps a single MMIO region
(the SIC -- System Interface Controller) whose sub-regions contain
per-mailbox doorbell, status, and command queue registers.

The driver manages a configurable number of mailboxes (default 2).
Each mailbox has a configurable number of slots (default 32) and a
configurable stride (default 128 bytes per slot).  The driver allocates
DMA-coherent memory for each mailbox queue during probe.

Interrupts are per-mailbox completion/error interrupts.  The driver
registers a threaded IRQ handler for each configured mailbox.

The eSW is loaded independently of this driver -- typically by the
boot firmware or a platform-specific loader -- so the driver does not
use ``request_firmware()``.  Instead it waits for the eSW to reach
mission mode during probe, bounded by ``fw_ready_timeout_ms``.

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

All algorithm driver names use the ``cri-cmh-`` prefix (e.g.
``cri-cmh-sha256``, ``cri-cmh-ecb-aes``, ``cri-cmh-gcm-aes``,
``cri-cmh-mldsa44``).  Names generally follow the kernel's hyphenated
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
are queued on a backlog of up to ``backlog_max_depth`` entries when the
command queue is full; without that flag a full queue is reported as
``-EBUSY``.  Hardware or eSW failures surface as ``-EIO``, malformed
requests as ``-EINVAL``, oversized requests as ``-EMSGSIZE`` or
``-EINVAL`` (see `Data-Size Limits`_), and unresponsive hardware as
``-ETIMEDOUT``.  The ``/dev/cmh_mgmt`` ioctls are, by contrast,
synchronous -- each ioctl blocks until the hardware completes.

Driver Architecture
===================

The driver is structured as follows:

Platform Driver
  Matches DT compatible ``"cri,cmh"``.  Probe initializes all
  subsystems in order; remove tears them down in reverse.

Configuration
  Parses DT properties and module parameter overrides.  Validates
  mailbox counts, slot sizes, and stride values.

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

The driver defines four production module parameters and five
debug-only parameters (compiled only with
``CONFIG_CRYPTO_DEV_CMH_DEBUG``).  In production, all mailbox topology,
per-core affinity, slot counts, strides, and timeout tuning are taken
from Device Tree properties, not module parameters.  The debug-only
parameters exist solely to force alternate geometries at ``insmod``
time during bringup and validation (for example, to drive the
mailbox-contention and cross-mailbox dispatch paths without
rebuilding the Device Tree); they default to "use the DT value"
and have no effect in a production build.

Production:

``fw_ready_timeout_ms`` (uint, default 5000, RO)
  Timeout in milliseconds to wait for CMH eSW to reach mission mode
  during probe.

``cmq_max_depth`` (uint, default 256, RO)
  Maximum number of pending commands in the central Command Message
  Queue.

``backlog_max_depth`` (uint, default 1024, RO)
  Maximum depth of the backlog queue for ``CRYPTO_TFM_REQ_MAY_BACKLOG``
  requests.  Set to 0 to disable backlogs.

``hwrng_quality`` (int, default 0, RO)
  Quality value passed to ``hwrng_register()``.  0 disables kernel CRNG
  seeding; 1-1024 sets the quality directly.

Debug-only (``CONFIG_CRYPTO_DEV_CMH_DEBUG``):

``mbx_count_override`` (uint, default 0, RO)
  Override the DT mailbox count (0 = use DT) to force fewer
  mailboxes than the hardware provides.

``mbx_slots_override`` (uint, default 0, RO)
  Override all MBX slots_log2 values (0 = use DT).

``mbx_round_robin`` (bool, default false, RO)
  Ignore DT ``cri,mbx`` affinity pins and round-robin all cores
  across the configured mailboxes (0 = use DT affinity).  Restores
  the unpinned dispatch that exercises cross-mailbox distribution.

``drbg_config`` (charp, default "auto", RO)
  DRBG configuration at probe: ``"auto"`` (normal) or ``"skip"``
  (skip initial DRBG configuration).

``skip_fw_check`` (bool, default false, RO)
  Skip the SIC boot status and eSW mission-mode checks at probe.
  Allows the module to load before the eSW has booted.

Runtime-tunable timeout knobs are exposed via debugfs rather than
module parameters; see `debugfs Counters`_ below.

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
runtime-tunable timeout knobs (``config/``, including
``drain_timeout_ms`` and ``watchdog_ms``).  See
``Documentation/ABI/testing/debugfs-driver-cmh`` for the authoritative
per-file description.

Device Tree Binding
===================

See ``Documentation/devicetree/bindings/crypto/cri,cmh.yaml`` for the
full DT binding schema and complete, schema-validated examples
(including the per-mailbox topology properties ``cri,mbx-instances``,
``cri,mbx-slots-log2``, and ``cri,mbx-strides-log2``).  When those
properties are omitted the driver falls back to two mailboxes
(instances 0 and 1) with the slot/stride defaults described above.

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

MAC and keyed-hash algorithms that buffer all input in kernel memory
(hardware lacks context save/restore):

====================  =======  =============================================
Algorithm             Limit    Reason
====================  =======  =============================================
``cmac(aes)``         64 KiB   AES core has no external save/restore
``cmac(sm4)``         64 KiB   SM4 core has no external save/restore
``xcbc(sm4)``         64 KiB   SM4 core has no external save/restore
``poly1305``          64 KiB   CCP core has no external save/restore
``hmac(sha*)``        64 KiB   HMAC save/restore not supported (see below)
``hmac(sha3-*)``      64 KiB   HMAC save/restore not supported (see below)
``kmac128``           64 KiB   eSW rejects save when outlen != 0
``kmac256``           64 KiB   eSW rejects save when outlen != 0
====================  =======  =============================================

HMAC save/restore is unsupported by the eSW firmware.  For HMAC-SHA3,
exposing the Keccak sponge state would allow key recovery because the
sponge permutation is invertible; HMAC-SHA2 save/restore is likewise
not exposed by the eSW.

HMAC ``.export()``/``.import()`` (used for request cloning) is limited
to a single-page accumulated-data window of 4092 bytes (one page minus
a 4-byte length header), since the crypto subsystem pre-allocates the
state buffer per request.  Cloning a request that has accumulated more
input than this window fails.

Requests exceeding the limit are rejected with ``-EINVAL``.  Pure hash
algorithms (SHA-2, SHA-3, SHAKE, cSHAKE, SM3) have no data limit because
the hardware supports incremental save/restore.

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
