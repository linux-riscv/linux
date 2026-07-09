# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the CRI CryptoManager Hub (CMH) hardware crypto accelerator driver.
#

obj-$(CONFIG_CRYPTO_DEV_CMH) += cmh.o

cmh-y := \
	cmh_main.o \
	cmh_config.o \
	cmh_mqi.o \
	cmh_txn.o \
	cmh_rh.o \
	cmh_dma.o \
	cmh_sysfs.o \
	cmh_key.o \
	cmh_sys.o \
	cmh_hash.o \
	cmh_hmac.o \
	cmh_cshake.o \
	cmh_kmac.o \
	cmh_sm3.o \
	cmh_aes.o \
	cmh_aes_aead.o \
	cmh_aes_cmac.o \
	cmh_sm4_skcipher.o \
	cmh_sm4_aead.o \
	cmh_sm4_cmac.o \
	cmh_ccp.o \
	cmh_ccp_aead.o \
	cmh_ccp_poly.o

# Management ioctl device (/dev/cmh_mgmt): key lifecycle, PKE, PQC ioctls.
cmh-$(CONFIG_CRYPTO_DEV_CMH_MGMT) += \
	cmh_mgmt.o \
	cmh_mgmt_pke.o \
	cmh_mgmt_pqc.o \
	cmh_pke_sm2.o

ccflags-y += -I$(src)/include

# Suppress -Woverride-init for the [0 ... N] = -1 range-initializer pattern
# (standard kernel idiom for sparse lookup tables with a default value).
CFLAGS_cmh_config.o += -Wno-override-init

# Debug instrumentation: per-mailbox debugfs counters.
# cmh_debugfs.o is linked into the composite cmh.o (same tristate).
cmh-$(CONFIG_CRYPTO_DEV_CMH_DEBUG) += cmh_debugfs.o
