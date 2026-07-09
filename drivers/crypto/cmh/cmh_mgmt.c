// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- Key Management misc_device (/dev/cmh_mgmt)
 *
 * Provides ioctl interface for key provisioning (NEW, NEW_RANDOM, WRITE, READ,
 * FIND, GRANT, DELETE) and datastore lifecycle (EXPORT, IMPORT).
 *
 * Each ioctl handler: copy_from_user -> validate -> DMA alloc ->
 * build VCQ -> cmh_tm_submit_sync -> copy_to_user -> DMA free.
 *
 * Access requires CAP_SYS_ADMIN (checked in open()).  The device node
 * is mode 0660; DAC further limits access to owner/group.
 * CMH eSW enforces per-MBX access control on top of this.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/capability.h>
#include <linux/overflow.h>

#include "cmh_mgmt.h"
#include "cmh_sys.h"
#include "cmh_txn.h"
#include "cmh_key.h"
#include "cmh_dma.h"
#include "cmh_config.h"
#include "cmh_sys_abi.h"
#include "cmh_pke.h"
#include "cmh_pke_sm2.h"
#include "cmh_qse_abi.h"
#include "cmh_hcq_abi.h"
#include <uapi/linux/cmh_mgmt_ioctl.h>

#include <crypto/utils.h>

/*
 * Pin all mgmt ioctls to a single management mailbox (MBX 0).
 *
 * This is a deliberate, structural choice -- not a performance default.
 * The /dev/cmh_mgmt path is *stateful* with respect to the eSW datastore,
 * and that state is per-mailbox, so every step of a key's lifecycle must
 * land on the same mailbox:
 *
 * 1. Datastore access control is per-mailbox AND opaque to the driver.
 *    SYS_CMD_NEW grants the creating mailbox a (1 << mbx_id) access mask
 *    (read/write/execute).  Crucially, the returned 64-bit ref encodes a
 *    randomised offset -- NOT the owning mailbox -- so given only a ref
 *    (as KEY_GRANT/READ/DELETE/DS_EXPORT receive), the driver cannot
 *    recover which mailbox owns the object.  A fixed management mailbox
 *    is therefore the only way to guarantee that NEW, WRITE, GRANT, READ
 *    and the subsequent hardware-held-key compute ops all share the
 *    mailbox that holds the access rights, without exposing mailbox
 *    identity in the UABI.  (User space may still widen access to other
 *    mailboxes explicitly via KEY_GRANT.)
 *
 * 2. The eSW SYS_REF_TEMP scratch store is per-mailbox and persists
 *    across ioctl calls.  A derivation that writes SYS_REF_TEMP (e.g. a
 *    KIC_* derive) must be consumed by a later ioctl on the *same*
 *    mailbox (e.g. DS_EXPORT with wrap_key=SYS_REF_TEMP).
 *
 * Device-tree per-core ``cri,mbx`` affinity applies to the *stateless*
 * registered crypto API path (cmh_core_select_instance()), which carries
 * no datastore state across calls and is free to balance across mailboxes.
 *
 * Note: MBX 0 is NOT reserved exclusively for mgmt -- registered crypto
 * operations may also land here via TM round-robin (target_mbx = -1).
 * This is safe because those ops do not allocate from the temp store.
 */

/* VCQ layout: header + command + flush = 3 entries */
#define MGMT_VCQ_CMDS		3

/*
 * Tracks whether any operation has left residual state in the device's
 * per-mailbox temporary key store since the last flush.  The device
 * reclaims temp storage only on a full mailbox flush (MBX_COMMAND_FLUSH),
 * which also terminates any executing command queue with -EPIPE.
 *
 * To avoid killing concurrent in-flight operations, the flush in
 * cmh_mgmt_ioctl() is conditional: it fires only when this flag is set.
 * Operations that allocate temp storage (currently: KIC derivations
 * targeting SYS_REF_TEMP) set this flag on success.
 */
static atomic_t mgmt_temp_dirty = ATOMIC_INIT(0);

/* -- KEY_NEW -------------------------- */

static int cmh_mgmt_key_new(void __user *argp)
{
	struct cmh_ioctl_key_new req;
	struct vcq_cmd vcq[MGMT_VCQ_CMDS];
	u64 *ref_buf;
	dma_addr_t ref_dma;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (!req.len)
		return -EINVAL;

	/* DMA buffer for CMH eSW to write back the ref */
	ref_buf = kmalloc_obj(*ref_buf, GFP_KERNEL);
	if (!ref_buf)
		return -ENOMEM;

	*ref_buf = 0;
	ref_dma = cmh_dma_map_single(ref_buf, sizeof(*ref_buf),
				     DMA_FROM_DEVICE);
	if (cmh_dma_map_error(ref_dma)) {
		kfree(ref_buf);
		return -ENOMEM;
	}

	vcq_set_header(&vcq[0], MGMT_VCQ_CMDS);
	vcq_add_sys_new(&vcq[1], req.cid, ref_dma, req.len);
	vcq_add_sys_flush(&vcq[2]);

	ret = cmh_tm_submit_sync_mbx(vcq, MGMT_VCQ_CMDS, 1, MGMT_MBX);

	/*
	 * Unmap before CPU read: single-phase operation (no re-use of
	 * the DMA mapping), so unmap transfers ownership back to the
	 * CPU.  On SWIOTLB systems the unmap copies the bounce buffer
	 * to the original allocation.  This is the correct pattern for
	 * single-shot sync submits where the buffer is not re-mapped.
	 */
	cmh_dma_unmap_single(ref_dma, sizeof(*ref_buf), DMA_FROM_DEVICE);

	if (ret) {
		kfree(ref_buf);
		return ret;
	}

	req.ref = *ref_buf;
	kfree(ref_buf);

	if (copy_to_user(argp, &req, sizeof(req)))
		return -EFAULT;

	dev_dbg(cmh_dev(), "mgmt: KEY_NEW cid=0x%llx len=%u -> ref=0x%llx\n",
		req.cid, req.len, req.ref);
	return 0;
}

/* -- KEY_WRITE ------------------------- */

static int cmh_mgmt_key_write(void __user *argp)
{
	struct cmh_ioctl_key_write req;
	struct vcq_cmd vcq[MGMT_VCQ_CMDS];
	void *dmabuf;
	dma_addr_t dma_addr;
	u32 core_id, sys_type;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (!req.len || req.len > CMH_MGMT_MAX_DATA_LEN)
		return -EINVAL;

	core_id = cmh_ds_type_to_core_id(req.ds_type);
	if (core_id == CORE_ID_NUM)
		return -EINVAL;
	sys_type = SYS_TYPE_SET(req.flags, core_id);

	dmabuf = kmalloc(req.len, GFP_KERNEL);
	if (!dmabuf)
		return -ENOMEM;

	if (copy_from_user(dmabuf, u64_to_user_ptr(req.data),
			   req.len)) {
		kfree_sensitive(dmabuf);
		return -EFAULT;
	}

	dma_addr = cmh_dma_map_single(dmabuf, req.len, DMA_TO_DEVICE);
	if (cmh_dma_map_error(dma_addr)) {
		kfree_sensitive(dmabuf);
		return -ENOMEM;
	}

	vcq_set_header(&vcq[0], MGMT_VCQ_CMDS);
	vcq_add_sys_write(&vcq[1], req.ref, dma_addr, req.wrap_key,
			  req.len, sys_type);
	/*
	 * PKE keys on Weierstrass curves and RSA keys must be byte-swapped
	 * when stored in the DS so they match the internal big-endian
	 * representation used by the PKE sidecar.  Edwards curve keys
	 * (EdDSA) use native byte order and must NOT be swapped.
	 */
	switch (req.ds_type) {
	case CMH_DS_RSA_PRIV_KEY:
	case CMH_DS_RSA_PUB_KEY:
	case CMH_DS_RSA_CRT_KEY:
	case CMH_DS_ECDSA_PRIV_KEY:
	case CMH_DS_ECDSA_PUB_KEY:
	case CMH_DS_ECDH_PRIV_KEY:
	case CMH_DS_SHARED_SECRET:
	case CMH_DS_SM2_PRIV_KEY:
		vcq[1].id |= PKE_SWAP_FLAGS;
		break;
	default:
		/* EdDSA, symmetric keys -- no swap */
		break;
	}
	vcq_add_sys_flush(&vcq[2]);

	ret = cmh_tm_submit_sync_mbx(vcq, MGMT_VCQ_CMDS, 1, MGMT_MBX);

	cmh_dma_unmap_single(dma_addr, req.len, DMA_TO_DEVICE);
	kfree_sensitive(dmabuf);

	if (ret)
		return ret;

	dev_dbg(cmh_dev(), "mgmt: KEY_WRITE ref=0x%llx len=%u type=0x%x\n",
		req.ref, req.len, sys_type);
	return 0;
}

/* -- KEY_READ -------------------------- */

static int cmh_mgmt_key_read(void __user *argp)
{
	struct cmh_ioctl_key_read req;
	struct vcq_cmd vcq[MGMT_VCQ_CMDS];
	void *dmabuf;
	dma_addr_t dma_addr;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.__reserved)
		return -EINVAL;
	if (!req.len || req.len > CMH_MGMT_MAX_DATA_LEN)
		return -EINVAL;

	dmabuf = kzalloc(req.len, GFP_KERNEL);
	if (!dmabuf)
		return -ENOMEM;

	dma_addr = cmh_dma_map_single(dmabuf, req.len, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(dma_addr)) {
		kfree(dmabuf);
		return -ENOMEM;
	}

	vcq_set_header(&vcq[0], MGMT_VCQ_CMDS);
	vcq_add_sys_read(&vcq[1], req.ref, dma_addr, req.wrap_key, req.len);
	vcq_add_sys_flush(&vcq[2]);

	ret = cmh_tm_submit_sync_mbx(vcq, MGMT_VCQ_CMDS, 1, MGMT_MBX);

	cmh_dma_unmap_single(dma_addr, req.len, DMA_FROM_DEVICE);

	if (ret) {
		kfree_sensitive(dmabuf);
		return ret;
	}

	if (copy_to_user(u64_to_user_ptr(req.data),
			 dmabuf, req.len)) {
		kfree_sensitive(dmabuf);
		return -EFAULT;
	}

	req.out_len = req.len;
	kfree_sensitive(dmabuf);

	if (copy_to_user(argp, &req, sizeof(req)))
		return -EFAULT;

	dev_dbg(cmh_dev(), "mgmt: KEY_READ ref=0x%llx len=%u\n",
		req.ref, req.out_len);
	return 0;
}

/* -- KEY_FIND -------------------------- */

static int cmh_mgmt_key_find(void __user *argp)
{
	struct cmh_ioctl_key_find req;
	struct vcq_cmd vcq[MGMT_VCQ_CMDS];
	struct sys_list_item *item;
	dma_addr_t item_dma;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.__reserved)
		return -EINVAL;

	item = kzalloc_obj(*item, GFP_KERNEL);
	if (!item)
		return -ENOMEM;

	item_dma = cmh_dma_map_single(item, sizeof(*item), DMA_FROM_DEVICE);
	if (cmh_dma_map_error(item_dma)) {
		kfree(item);
		return -ENOMEM;
	}

	vcq_set_header(&vcq[0], MGMT_VCQ_CMDS);
	vcq_add_sys_find(&vcq[1], req.cid, item_dma, sizeof(*item));
	vcq_add_sys_flush(&vcq[2]);

	ret = cmh_tm_submit_sync_mbx(vcq, MGMT_VCQ_CMDS, 1, MGMT_MBX);

	cmh_dma_unmap_single(item_dma, sizeof(*item), DMA_FROM_DEVICE);

	if (ret) {
		kfree(item);
		return ret;
	}

	req.ref = item->ref;
	req.len = item->len;
	req.type = item->type;
	kfree(item);

	if (copy_to_user(argp, &req, sizeof(req)))
		return -EFAULT;

	dev_dbg(cmh_dev(), "mgmt: KEY_FIND cid=0x%llx -> ref=0x%llx\n",
		req.cid, req.ref);
	return 0;
}

/* -- KEY_LIST ------------------------- */

static int cmh_mgmt_key_list(void __user *argp)
{
	struct cmh_ioctl_key_list req;
	struct vcq_cmd vcq[MGMT_VCQ_CMDS];
	struct sys_list_item *item;
	dma_addr_t item_dma;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	if (req.version != CMH_MGMT_V1)
		return -EINVAL;

	if (req.__reserved)
		return -EINVAL;

	item = kzalloc_obj(*item, GFP_KERNEL);
	if (!item)
		return -ENOMEM;

	item_dma = cmh_dma_map_single(item, sizeof(*item), DMA_FROM_DEVICE);
	if (cmh_dma_map_error(item_dma)) {
		kfree(item);
		return -ENOMEM;
	}

	vcq_set_header(&vcq[0], MGMT_VCQ_CMDS);
	vcq_add_sys_list(&vcq[1], req.start_ref, item_dma, sizeof(*item));
	vcq_add_sys_flush(&vcq[2]);

	ret = cmh_tm_submit_sync_mbx(vcq, MGMT_VCQ_CMDS, 1, MGMT_MBX);

	cmh_dma_unmap_single(item_dma, sizeof(*item), DMA_FROM_DEVICE);

	if (ret) {
		kfree(item);
		return ret;
	}

	req.ref = item->ref;
	req.cid = item->cid;
	req.len = item->len;
	req.type = item->type;
	kfree(item);

	if (copy_to_user(argp, &req, sizeof(req)))
		return -EFAULT;

	return 0;
}

/* -- KEY_GRANT / KEY_DELETE --------------------- */

static int cmh_mgmt_key_grant(void __user *argp, bool is_delete)
{
	struct cmh_ioctl_key_grant req;
	struct vcq_cmd vcq[MGMT_VCQ_CMDS];
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.__reserved)
		return -EINVAL;

	/* DELETE = GRANT with all permissions zeroed */
	if (is_delete) {
		req.read = 0;
		req.write = 0;
		req.execute = 0;
	}

	vcq_set_header(&vcq[0], MGMT_VCQ_CMDS);
	vcq_add_sys_grant(&vcq[1], req.ref, req.read, req.write, req.execute);
	vcq_add_sys_flush(&vcq[2]);

	ret = cmh_tm_submit_sync_mbx(vcq, MGMT_VCQ_CMDS, 1, MGMT_MBX);
	if (ret)
		return ret;

	dev_dbg(cmh_dev(), "mgmt: KEY_%s ref=0x%llx r=0x%llx w=0x%llx x=0x%llx\n",
		is_delete ? "DELETE" : "GRANT",
		req.ref, req.read, req.write, req.execute);
	return 0;
}

/* -- DS_EXPORT ------------------------- */

static int cmh_mgmt_ds_export(void __user *argp)
{
	struct cmh_ioctl_ds_export req;
	struct vcq_cmd vcq[MGMT_VCQ_CMDS];
	void *dmabuf;
	dma_addr_t dma_addr;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.__reserved)
		return -EINVAL;
	if (!req.len || req.len > CMH_MGMT_MAX_DATA_LEN)
		return -EINVAL;

	/*
	 * req.len is the exact DMA buffer size given to the eSW.
	 * Userspace must size it to at least the export blob:
	 *
	 *   wrapped:   sizeof(sys_wrap_hdr) + 2*AES_BLOCK_SIZE + obj_len
	 *              = 16 + 32 + obj_len  = 48 + obj_len
	 *   plaintext: sizeof(sys_wrap_hdr) + obj_len
	 *              = 16 + obj_len
	 *
	 * obj_len is known from KEY_NEW or KEY_FIND.  If req.len is
	 * too small, the eSW rejects the command and we return -EIO.
	 */
	dmabuf = kzalloc(req.len, GFP_KERNEL);
	if (!dmabuf)
		return -ENOMEM;

	dma_addr = cmh_dma_map_single(dmabuf, req.len, DMA_FROM_DEVICE);
	if (cmh_dma_map_error(dma_addr)) {
		kfree(dmabuf);
		return -ENOMEM;
	}

	vcq_set_header(&vcq[0], MGMT_VCQ_CMDS);
	vcq_add_sys_export(&vcq[1], req.cid, dma_addr, req.wrap_key, req.len);
	vcq_add_sys_flush(&vcq[2]);

	ret = cmh_tm_submit_sync_mbx(vcq, MGMT_VCQ_CMDS, 1, MGMT_MBX);

	cmh_dma_unmap_single(dma_addr, req.len, DMA_FROM_DEVICE);

	if (ret) {
		kfree_sensitive(dmabuf);
		return ret;
	}

	/* Parse actual blob size from the eSW-written header */
	{
		struct sys_wrap_hdr *hdr = (struct sys_wrap_hdr *)dmabuf;
		u64 actual;

		if (check_add_overflow((u64)sizeof(*hdr), (u64)hdr->wrap,
				       &actual) ||
		    check_add_overflow(actual, (u64)hdr->len, &actual) ||
		    actual > req.len) {
			kfree_sensitive(dmabuf);
			return -EIO;
		}
		req.out_len = (u32)actual;
	}

	if (copy_to_user(u64_to_user_ptr(req.data),
			 dmabuf, req.out_len)) {
		kfree_sensitive(dmabuf);
		return -EFAULT;
	}

	kfree_sensitive(dmabuf);

	if (copy_to_user(argp, &req, sizeof(req)))
		return -EFAULT;

	dev_dbg(cmh_dev(), "mgmt: DS_EXPORT wrap_key=0x%llx len=%u\n",
		req.wrap_key, req.out_len);
	return 0;
}

/* -- DS_IMPORT ------------------------- */

static int cmh_mgmt_ds_import(void __user *argp)
{
	struct cmh_ioctl_ds_import req;
	struct vcq_cmd vcq[MGMT_VCQ_CMDS];
	void *dmabuf;
	dma_addr_t dma_addr;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (!req.len || req.len > CMH_MGMT_MAX_DATA_LEN)
		return -EINVAL;

	dmabuf = kmalloc(req.len, GFP_KERNEL);
	if (!dmabuf)
		return -ENOMEM;

	if (copy_from_user(dmabuf, u64_to_user_ptr(req.data),
			   req.len)) {
		kfree_sensitive(dmabuf);
		return -EFAULT;
	}

	dma_addr = cmh_dma_map_single(dmabuf, req.len, DMA_TO_DEVICE);
	if (cmh_dma_map_error(dma_addr)) {
		kfree_sensitive(dmabuf);
		return -ENOMEM;
	}

	vcq_set_header(&vcq[0], MGMT_VCQ_CMDS);
	vcq_add_sys_import(&vcq[1], dma_addr, req.wrap_key, req.len);
	vcq_add_sys_flush(&vcq[2]);

	ret = cmh_tm_submit_sync_mbx(vcq, MGMT_VCQ_CMDS, 1, MGMT_MBX);

	cmh_dma_unmap_single(dma_addr, req.len, DMA_TO_DEVICE);
	kfree_sensitive(dmabuf);

	if (ret)
		return ret;

	dev_dbg(cmh_dev(), "mgmt: DS_IMPORT wrap_key=0x%llx len=%u\n",
		req.wrap_key, req.len);
	return 0;
}

/* -- KIC key derivation ioctls --------
 *
 * All four KIC derivation handlers (HKDF1, HKDF2, AES-CMAC-KDF,
 * DKEK-derive) share the same two-mode structure and temp-flush pattern.
 *
 * Temp-storage flush rationale:
 *
 *   The device maintains a small per-mailbox temporary key store
 *   (~960 bytes, LIFO).  A derivation targeting SYS_REF_TEMP allocates
 *   from this store; the allocation persists across command-queue
 *   boundaries until either (a) a subsequent command consumes it or
 *   (b) a mailbox flush resets the store.
 *
 *   Our single-derivation ioctls produce a temp key with no consumer
 *   in the same queue -- the key is consumed by a *later* ioctl
 *   (e.g. DS_EXPORT with wrap_key=SYS_REF_TEMP).  If no consumer
 *   follows, the allocation persists.  Sequential temp derivations
 *   accumulate allocations until the store is exhausted (3--8 calls
 *   depending on key size), after which the device returns ENOMEM.
 *
 *   A mailbox flush (cmh_tm_flush_mbx / MBX_COMMAND_FLUSH) resets the
 *   temp store.  It does NOT destroy persistent keys, datastore
 *   objects, or DRBG state -- only the command queue and temp store.
 *
 *   Safe for cross-ioctl temp flows (e.g. export-to-file:
 *   HKDF1->TEMP in ioctl 1, then DS_EXPORT with wrap_key=TEMP in
 *   ioctl 2): the flush only happens in derivation handlers and in
 *   the pre-PKE dispatch path, not in DS_EXPORT/DS_IMPORT, so the
 *   temp key survives until consumed.
 *
 * The ioctl dispatch also flushes before PKE/SM2/PQC ioctls to
 * protect them from temp residue left by earlier derivations on the
 * same mailbox.  The per-handler flushes here remain necessary
 * because sequential temp derivations (without an intervening
 * PKE/SM2/PQC ioctl) would still exhaust the store.
 */

/* -- KIC_HKDF1 ------------------------- */

/*
 * Derive a key from a KIC base key via one-step HKDF.
 *
 * Two modes controlled by CMH_KIC_FLAG_TEMP:
 *
 *   TEMP (flag set) -- 3-command VCQ:
 *     [0] SYS header
 *     [1] KIC_CMD_HKDF1 (dst=SYS_REF_TEMP)
 *     [2] flush
 *   Returns SYS_REF_TEMP as ref.  No DS entry created.
 *
 *   Persistent (flag clear) -- 4-command VCQ:
 *     [0] SYS header
 *     [1] SYS_CMD_NEW   (allocate DS slot, CMH eSW writes ref)
 *     [2] KIC_CMD_HKDF1 (dst=SYS_REF_LAST = just-allocated slot)
 *     [3] flush
 *   Returns the new DS reference.
 */
#define KDF_VCQ_MAX		4
#define KDF_MAX_KEY_LEN		64
#define KDF_MAX_LABEL_LEN	56

static int cmh_mgmt_kic_hkdf1(void __user *argp)
{
	struct cmh_ioctl_kic_hkdf1 req;
	struct vcq_cmd vcq[KDF_VCQ_MAX];
	bool temp;
	u64 *ref_buf = NULL;
	void *label_buf = NULL;
	dma_addr_t ref_dma = DMA_MAPPING_ERROR, label_dma = DMA_MAPPING_ERROR;
	unsigned int n_cmds;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (!req.key_len || req.key_len > KDF_MAX_KEY_LEN)
		return -EINVAL;
	if (req.label_len > KDF_MAX_LABEL_LEN)
		return -EINVAL;

	temp = !!(req.flags & CMH_KIC_FLAG_TEMP);

	/*
	 * Persistent path: need DMA buffer for CMH eSW to write the
	 * newly-allocated DS reference.
	 */
	if (!temp) {
		ref_buf = kmalloc_obj(*ref_buf, GFP_KERNEL);
		if (!ref_buf)
			return -ENOMEM;
		*ref_buf = 0;
		ref_dma = cmh_dma_map_single(ref_buf, sizeof(*ref_buf),
					     DMA_FROM_DEVICE);
		if (cmh_dma_map_error(ref_dma)) {
			kfree(ref_buf);
			return -ENOMEM;
		}
	}

	/* DMA buffer for label data (CMH eSW DMA-reads it) */
	if (req.label_len > 0) {
		label_buf = kzalloc(req.label_len, GFP_KERNEL);
		if (!label_buf) {
			ret = -ENOMEM;
			goto out_ref;
		}
		if (copy_from_user(label_buf,
				   u64_to_user_ptr(req.label),
				   req.label_len)) {
			ret = -EFAULT;
			goto out_label;
		}
		label_dma = cmh_dma_map_single(label_buf, req.label_len,
					       DMA_TO_DEVICE);
		if (cmh_dma_map_error(label_dma)) {
			ret = -ENOMEM;
			goto out_label;
		}
	}

	/* Build VCQ */
	memset(vcq, 0, sizeof(vcq));

	if (temp) {
		/* Flush MBX to reset temp stack -- see KIC section comment */
		ret = cmh_tm_flush_mbx(MGMT_MBX);
		if (ret)
			goto out_unmap_label;

		n_cmds = 3;
		vcq_set_header(&vcq[0], n_cmds);
		vcq_add_kic_hkdf1(&vcq[1], SYS_REF_TEMP, req.base_key,
				  label_dma, req.key_len, req.label_len,
				   SYS_TYPE_SET(0, CORE_ID_AES));
		vcq_add_sys_flush(&vcq[2]);
	} else {
		n_cmds = 4;
		vcq_set_header(&vcq[0], n_cmds);
		vcq_add_sys_new(&vcq[1], req.cid, ref_dma, req.key_len);
		vcq_add_kic_hkdf1(&vcq[2], SYS_REF_LAST, req.base_key,
				  label_dma, req.key_len, req.label_len,
				   SYS_TYPE_SET(0, CORE_ID_AES));
		vcq_add_sys_flush(&vcq[3]);
	}

	ret = cmh_tm_submit_sync_mbx(vcq, n_cmds, 1, MGMT_MBX);

	/* Cleanup label DMA */
	if (label_buf) {
		cmh_dma_unmap_single(label_dma, req.label_len, DMA_TO_DEVICE);
		kfree(label_buf);
		label_buf = NULL;
	}

	if (ret)
		goto out_ref;

	if (temp) {
		req.ref = SYS_REF_TEMP;
		atomic_set(&mgmt_temp_dirty, 1);
	} else {
		cmh_dma_unmap_single(ref_dma, sizeof(*ref_buf),
				     DMA_FROM_DEVICE);
		req.ref = *ref_buf;
		kfree(ref_buf);
		ref_buf = NULL;
	}

	if (copy_to_user(argp, &req, sizeof(req)))
		return -EFAULT;

	dev_dbg(cmh_dev(),
		"mgmt: KIC_HKDF1 base=0x%llx len=%u flags=0x%x -> ref=0x%llx\n",
		req.base_key, req.key_len, req.flags, req.ref);
	return 0;

out_unmap_label:
	if (label_buf && !cmh_dma_map_error(label_dma) && label_dma)
		cmh_dma_unmap_single(label_dma, req.label_len, DMA_TO_DEVICE);
out_label:
	kfree(label_buf);
out_ref:
	if (ref_buf) {
		cmh_dma_unmap_single(ref_dma, sizeof(*ref_buf),
				     DMA_FROM_DEVICE);
		kfree(ref_buf);
	}
	return ret;
}

/* -- KIC_HKDF2 ------------------------- */

/*
 * Two-step HKDF key derivation.  Same as HKDF1 but adds a salt key
 * reference: Step 1: HMAC(salt, base) -> PRK; Step 2: HMAC(PRK, label) -> key.
 */

static int cmh_mgmt_kic_hkdf2(void __user *argp)
{
	struct cmh_ioctl_kic_hkdf2 req;
	struct vcq_cmd vcq[KDF_VCQ_MAX];
	bool temp;
	u64 *ref_buf = NULL;
	void *label_buf = NULL;
	dma_addr_t ref_dma = DMA_MAPPING_ERROR, label_dma = DMA_MAPPING_ERROR;
	unsigned int n_cmds;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (!req.key_len || req.key_len > KDF_MAX_KEY_LEN)
		return -EINVAL;
	if (req.label_len > KDF_MAX_LABEL_LEN)
		return -EINVAL;

	temp = !!(req.flags & CMH_KIC_FLAG_TEMP);

	if (!temp) {
		ref_buf = kmalloc_obj(*ref_buf, GFP_KERNEL);
		if (!ref_buf)
			return -ENOMEM;
		*ref_buf = 0;
		ref_dma = cmh_dma_map_single(ref_buf, sizeof(*ref_buf),
					     DMA_FROM_DEVICE);
		if (cmh_dma_map_error(ref_dma)) {
			kfree(ref_buf);
			return -ENOMEM;
		}
	}

	if (req.label_len > 0) {
		label_buf = kzalloc(req.label_len, GFP_KERNEL);
		if (!label_buf) {
			ret = -ENOMEM;
			goto out_ref2;
		}
		if (copy_from_user(label_buf,
				   u64_to_user_ptr(req.label),
				   req.label_len)) {
			ret = -EFAULT;
			goto out_label2;
		}
		label_dma = cmh_dma_map_single(label_buf, req.label_len,
					       DMA_TO_DEVICE);
		if (cmh_dma_map_error(label_dma)) {
			ret = -ENOMEM;
			goto out_label2;
		}
	}

	memset(vcq, 0, sizeof(vcq));

	if (temp) {
		/* Flush MBX to reset temp stack -- see KIC section comment */
		ret = cmh_tm_flush_mbx(MGMT_MBX);
		if (ret)
			goto out_unmap_label2;

		n_cmds = 3;
		vcq_set_header(&vcq[0], n_cmds);
		vcq_add_kic_hkdf2(&vcq[1], SYS_REF_TEMP, req.base_key,
				  req.salt_key, label_dma,
				   req.key_len, req.label_len,
				   SYS_TYPE_SET(0, CORE_ID_AES));
		vcq_add_sys_flush(&vcq[2]);
	} else {
		n_cmds = 4;
		vcq_set_header(&vcq[0], n_cmds);
		vcq_add_sys_new(&vcq[1], req.cid, ref_dma, req.key_len);
		vcq_add_kic_hkdf2(&vcq[2], SYS_REF_LAST, req.base_key,
				  req.salt_key, label_dma,
				   req.key_len, req.label_len,
				   SYS_TYPE_SET(0, CORE_ID_AES));
		vcq_add_sys_flush(&vcq[3]);
	}

	ret = cmh_tm_submit_sync_mbx(vcq, n_cmds, 1, MGMT_MBX);

	if (label_buf) {
		cmh_dma_unmap_single(label_dma, req.label_len, DMA_TO_DEVICE);
		kfree(label_buf);
		label_buf = NULL;
	}

	if (ret)
		goto out_ref2;

	if (temp) {
		req.ref = SYS_REF_TEMP;
		atomic_set(&mgmt_temp_dirty, 1);
	} else {
		cmh_dma_unmap_single(ref_dma, sizeof(*ref_buf),
				     DMA_FROM_DEVICE);
		req.ref = *ref_buf;
		kfree(ref_buf);
		ref_buf = NULL;
	}

	if (copy_to_user(argp, &req, sizeof(req)))
		return -EFAULT;

	dev_dbg(cmh_dev(),
		"mgmt: KIC_HKDF2 base=0x%llx salt=0x%llx len=%u flags=0x%x -> ref=0x%llx\n",
		req.base_key, req.salt_key, req.key_len, req.flags, req.ref);
	return 0;

out_unmap_label2:
	if (label_buf && !cmh_dma_map_error(label_dma) && label_dma)
		cmh_dma_unmap_single(label_dma, req.label_len, DMA_TO_DEVICE);
out_label2:
	kfree(label_buf);
out_ref2:
	if (ref_buf) {
		cmh_dma_unmap_single(ref_dma, sizeof(*ref_buf),
				     DMA_FROM_DEVICE);
		kfree(ref_buf);
	}
	return ret;
}

/* -- KIC_AES_CMAC_KDF ------------------ */

/*
 * Derive a key using AES-CMAC-based KDF (NIST SP800-108 style).
 * Base key must be 32 bytes.  Output is always non-PT (the hub driver
 * rejects SYS_TYPE_FLAG_PT).
 *
 * VCQ layout matches HKDF: TEMP mode uses 3 commands, persistent uses 4.
 */
#define CMAC_KDF_KEY_LEN	32

static int cmh_mgmt_kic_aes_cmac_kdf(void __user *argp)
{
	struct cmh_ioctl_kic_aes_cmac_kdf req;
	struct vcq_cmd vcq[KDF_VCQ_MAX];
	bool temp;
	u64 *ref_buf = NULL;
	void *label_buf = NULL;
	dma_addr_t ref_dma = DMA_MAPPING_ERROR, label_dma = DMA_MAPPING_ERROR;
	unsigned int n_cmds;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.key_len != CMAC_KDF_KEY_LEN)
		return -EINVAL;
	if (req.label_len > KDF_MAX_LABEL_LEN)
		return -EINVAL;

	temp = !!(req.flags & CMH_KIC_FLAG_TEMP);

	if (!temp) {
		ref_buf = kmalloc_obj(*ref_buf, GFP_KERNEL);
		if (!ref_buf)
			return -ENOMEM;
		*ref_buf = 0;
		ref_dma = cmh_dma_map_single(ref_buf, sizeof(*ref_buf),
					     DMA_FROM_DEVICE);
		if (cmh_dma_map_error(ref_dma)) {
			kfree(ref_buf);
			return -ENOMEM;
		}
	}

	if (req.label_len > 0) {
		label_buf = kzalloc(req.label_len, GFP_KERNEL);
		if (!label_buf) {
			ret = -ENOMEM;
			goto out_ref_cmac;
		}
		if (copy_from_user(label_buf,
				   u64_to_user_ptr(req.label),
				   req.label_len)) {
			ret = -EFAULT;
			goto out_label_cmac;
		}
		label_dma = cmh_dma_map_single(label_buf, req.label_len,
					       DMA_TO_DEVICE);
		if (cmh_dma_map_error(label_dma)) {
			ret = -ENOMEM;
			goto out_label_cmac;
		}
	}

	memset(vcq, 0, sizeof(vcq));

	if (temp) {
		/* Flush MBX to reset temp stack -- see KIC section comment */
		ret = cmh_tm_flush_mbx(MGMT_MBX);
		if (ret)
			goto out_unmap_label_cmac;

		n_cmds = 3;
		vcq_set_header(&vcq[0], n_cmds);
		vcq_add_kic_aes_cmac_kdf(&vcq[1], SYS_REF_TEMP,
					 req.base_key, label_dma,
					 req.key_len, req.label_len,
					 SYS_TYPE_SET(0, CORE_ID_AES));
		vcq_add_sys_flush(&vcq[2]);
	} else {
		n_cmds = 4;
		vcq_set_header(&vcq[0], n_cmds);
		vcq_add_sys_new(&vcq[1], req.cid, ref_dma, req.key_len);
		vcq_add_kic_aes_cmac_kdf(&vcq[2], SYS_REF_LAST,
					 req.base_key, label_dma,
					 req.key_len, req.label_len,
					 SYS_TYPE_SET(0, CORE_ID_AES));
		vcq_add_sys_flush(&vcq[3]);
	}

	ret = cmh_tm_submit_sync_mbx(vcq, n_cmds, 1, MGMT_MBX);

	if (label_buf) {
		cmh_dma_unmap_single(label_dma, req.label_len, DMA_TO_DEVICE);
		kfree(label_buf);
		label_buf = NULL;
	}

	if (ret)
		goto out_ref_cmac;

	if (temp) {
		req.ref = SYS_REF_TEMP;
		atomic_set(&mgmt_temp_dirty, 1);
	} else {
		cmh_dma_unmap_single(ref_dma, sizeof(*ref_buf),
				     DMA_FROM_DEVICE);
		req.ref = *ref_buf;
		kfree(ref_buf);
		ref_buf = NULL;
	}

	if (copy_to_user(argp, &req, sizeof(req)))
		return -EFAULT;

	dev_dbg(cmh_dev(),
		"mgmt: KIC_AES_CMAC_KDF base=0x%llx len=%u flags=0x%x -> ref=0x%llx\n",
		req.base_key, req.key_len, req.flags, req.ref);
	return 0;

out_unmap_label_cmac:
	if (label_buf && !cmh_dma_map_error(label_dma) && label_dma)
		cmh_dma_unmap_single(label_dma, req.label_len, DMA_TO_DEVICE);
out_label_cmac:
	kfree(label_buf);
out_ref_cmac:
	if (ref_buf) {
		cmh_dma_unmap_single(ref_dma, sizeof(*ref_buf),
				     DMA_FROM_DEVICE);
		kfree(ref_buf);
	}
	return ret;
}

/* -- KIC_DKEK_DERIVE ------------------- */

/*
 * Derive a Key Encryption Key (KEK) from a KIC base key.
 * Output is tagged CORE_ID_KIC (usable for further derivation only).
 * host_id=0 means the caller's own host; non-zero requires management
 * host privilege (eSW enforces this).
 */
#define DKEK_VCQ_MAX		4

static int cmh_mgmt_kic_dkek_derive(void __user *argp)
{
	struct cmh_ioctl_kic_dkek_derive req;
	struct vcq_cmd vcq[DKEK_VCQ_MAX];
	bool temp;
	u64 *ref_buf = NULL;
	void *meta_buf = NULL;
	dma_addr_t ref_dma = DMA_MAPPING_ERROR, meta_dma = DMA_MAPPING_ERROR;
	unsigned int n_cmds;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.metadata_len > KIC_DKEK_MAX_METADATA)
		return -EINVAL;

	temp = !!(req.flags & CMH_KIC_FLAG_TEMP);

	if (!temp) {
		ref_buf = kmalloc_obj(*ref_buf, GFP_KERNEL);
		if (!ref_buf)
			return -ENOMEM;
		*ref_buf = 0;
		ref_dma = cmh_dma_map_single(ref_buf, sizeof(*ref_buf),
					     DMA_FROM_DEVICE);
		if (cmh_dma_map_error(ref_dma)) {
			kfree(ref_buf);
			return -ENOMEM;
		}
	}

	if (req.metadata_len > 0) {
		meta_buf = kzalloc(req.metadata_len, GFP_KERNEL);
		if (!meta_buf) {
			ret = -ENOMEM;
			goto out_ref_dkek;
		}
		if (copy_from_user(meta_buf,
				   u64_to_user_ptr(req.metadata),
				   req.metadata_len)) {
			ret = -EFAULT;
			goto out_meta;
		}
		meta_dma = cmh_dma_map_single(meta_buf, req.metadata_len,
					      DMA_TO_DEVICE);
		if (cmh_dma_map_error(meta_dma)) {
			ret = -ENOMEM;
			goto out_meta;
		}
	}

	memset(vcq, 0, sizeof(vcq));

	if (temp) {
		/* Flush MBX to reset temp stack -- see KIC section comment */
		ret = cmh_tm_flush_mbx(MGMT_MBX);
		if (ret)
			goto out_unmap_meta;

		n_cmds = 3;
		vcq_set_header(&vcq[0], n_cmds);
		vcq_add_kic_dkek_derive(&vcq[1], SYS_REF_TEMP,
					req.base_key, req.host_id,
					meta_dma, req.metadata_len);
		vcq_add_sys_flush(&vcq[2]);
	} else {
		n_cmds = 4;
		vcq_set_header(&vcq[0], n_cmds);
		vcq_add_sys_new(&vcq[1], req.cid, ref_dma, KIC_KEY_SIZE);
		vcq_add_kic_dkek_derive(&vcq[2], SYS_REF_LAST,
					req.base_key, req.host_id,
					meta_dma, req.metadata_len);
		vcq_add_sys_flush(&vcq[3]);
	}

	ret = cmh_tm_submit_sync_mbx(vcq, n_cmds, 1, MGMT_MBX);

	if (meta_buf) {
		cmh_dma_unmap_single(meta_dma, req.metadata_len,
				     DMA_TO_DEVICE);
		kfree(meta_buf);
		meta_buf = NULL;
	}

	if (ret)
		goto out_ref_dkek;

	if (temp) {
		req.ref = SYS_REF_TEMP;
		atomic_set(&mgmt_temp_dirty, 1);
	} else {
		cmh_dma_unmap_single(ref_dma, sizeof(*ref_buf),
				     DMA_FROM_DEVICE);
		req.ref = *ref_buf;
		kfree(ref_buf);
		ref_buf = NULL;
	}

	if (copy_to_user(argp, &req, sizeof(req)))
		return -EFAULT;

	dev_dbg(cmh_dev(),
		"mgmt: KIC_DKEK_DERIVE base=0x%llx host=%u meta_len=%u flags=0x%x -> ref=0x%llx\n",
		req.base_key, req.host_id, req.metadata_len, req.flags,
		req.ref);
	return 0;

out_unmap_meta:
	if (meta_buf && !cmh_dma_map_error(meta_dma) && meta_dma)
		cmh_dma_unmap_single(meta_dma, req.metadata_len, DMA_TO_DEVICE);
out_meta:
	kfree(meta_buf);
out_ref_dkek:
	if (ref_buf) {
		cmh_dma_unmap_single(ref_dma, sizeof(*ref_buf),
				     DMA_FROM_DEVICE);
		kfree(ref_buf);
	}
	return ret;
}

/* -- KEY_NEW_RANDOM -- DRBG-backed key generation --- */

/*
 * Allocate a new datastore slot and fill it with DRBG-generated
 * random key material in a single atomic VCQ submission:
 *
 *   [0] SYS header(5)
 *   [1] SYS_CMD_NEW   -- allocate DS slot (CMH eSW writes ref)
 *   [2] DRBG_CMD_DATASTORE(SYS_REF_LAST) -- fill with random data
 *   [3] DRBG flush -- release DRBG core ownership
 *   [4] SYS flush
 *
 * The DRBG must be configured before this ioctl is used.
 * Reuses struct cmh_ioctl_key_new (ds_type, flags, cid, len, ref).
 */
#define DRBG_KEYGEN_VCQ_CMDS	5

static int cmh_mgmt_key_new_random(void __user *argp)
{
	struct cmh_ioctl_key_new req;
	struct vcq_cmd vcq[DRBG_KEYGEN_VCQ_CMDS];
	u64 *ref_buf;
	dma_addr_t ref_dma;
	u32 core_id, sys_type;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (!req.len)
		return -EINVAL;

	core_id = cmh_ds_type_to_core_id(req.ds_type);
	if (core_id == CORE_ID_NUM)
		return -EINVAL;
	sys_type = SYS_TYPE_SET(req.flags, core_id);

	ref_buf = kmalloc_obj(*ref_buf, GFP_KERNEL);
	if (!ref_buf)
		return -ENOMEM;

	*ref_buf = 0;
	ref_dma = cmh_dma_map_single(ref_buf, sizeof(*ref_buf),
				     DMA_FROM_DEVICE);
	if (cmh_dma_map_error(ref_dma)) {
		kfree(ref_buf);
		return -ENOMEM;
	}

	vcq_set_header(&vcq[0], DRBG_KEYGEN_VCQ_CMDS);
	vcq_add_sys_new(&vcq[1], req.cid, ref_dma, req.len);
	vcq_add_drbg_datastore(&vcq[2], SYS_REF_LAST, req.len, sys_type);
	vcq_add_flush(&vcq[3], CORE_ID_DRBG);
	vcq_add_sys_flush(&vcq[4]);

	ret = cmh_tm_submit_sync_mbx(vcq, DRBG_KEYGEN_VCQ_CMDS, 1, MGMT_MBX);

	cmh_dma_unmap_single(ref_dma, sizeof(*ref_buf), DMA_FROM_DEVICE);

	if (ret) {
		kfree(ref_buf);
		return ret;
	}

	req.ref = *ref_buf;
	kfree(ref_buf);

	if (copy_to_user(argp, &req, sizeof(req)))
		return -EFAULT;

	dev_dbg(cmh_dev(),
		"mgmt: KEY_NEW_RANDOM cid=0x%llx len=%u type=0x%x -> ref=0x%llx\n",
		req.cid, req.len, sys_type, req.ref);
	return 0;
}

#define EAC_VCQ_CMDS		3	/* header + EAC_READ + flush */

static long cmh_mgmt_eac_read(void __user *argp)
{
	struct cmh_ioctl_eac_read req;
	struct eac_read_rsp *rsp;
	struct vcq_cmd vcq[EAC_VCQ_CMDS];
	dma_addr_t rsp_dma;
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.__reserved != 0)
		return -EINVAL;
	if (req.__pad != 0)
		return -EINVAL;

	rsp = kmalloc_obj(*rsp, GFP_KERNEL);
	if (!rsp)
		return -ENOMEM;

	rsp_dma = cmh_dma_map_single(rsp, sizeof(*rsp), DMA_FROM_DEVICE);
	if (cmh_dma_map_error(rsp_dma)) {
		kfree(rsp);
		return -ENOMEM;
	}

	vcq_set_header(&vcq[0], EAC_VCQ_CMDS);
	vcq_add_eac_read(&vcq[1], rsp_dma, sizeof(*rsp));
	vcq_add_flush(&vcq[2], CORE_ID_EAC);

	ret = cmh_tm_submit_sync_mbx(vcq, EAC_VCQ_CMDS, 1, MGMT_MBX);

	cmh_dma_unmap_single(rsp_dma, sizeof(*rsp), DMA_FROM_DEVICE);

	if (ret) {
		kfree(rsp);
		return ret;
	}

	/* Copy response fields into ioctl struct */
	req.mailbox_notification = rsp->mailbox_notification;
	req.hw_error = rsp->hw_error;
	req.hw_nmi = rsp->hw_nmi;
	req.hw_panic = rsp->hw_panic;
	req.safety_fatal = rsp->safety_fatal;
	req.safety_notification = rsp->safety_notification;
	req.sw_info0 = rsp->sw_info0;
	req.sw_info1 = rsp->sw_info1;
	memcpy(req.sram_bank_errors, rsp->sram_bank_errors,
	       sizeof(req.sram_bank_errors));
	req.__pad = 0;

	kfree(rsp);

	if (copy_to_user(argp, &req, sizeof(req)))
		return -EFAULT;

	return 0;
}

/* -- DRBG CONFIG (management) ------------ */

#define DRBG_CONFIG_VCQ_CMDS	4	/* header + RESET + CONFIG + flush */

static long cmh_mgmt_drbg_config(void __user *argp)
{
	struct cmh_ioctl_drbg_config req;
	struct vcq_cmd vcq[DRBG_CONFIG_VCQ_CMDS];
	int ret;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;
	if (req.version != CMH_MGMT_V1)
		return -EINVAL;
	if (req.__reserved != 0)
		return -EINVAL;
	if (req.entropy_ratio > 3)
		return -EINVAL;
	if (req.security_strength != CMH_DRBG_STRENGTH_128 &&
	    req.security_strength != CMH_DRBG_STRENGTH_256)
		return -EINVAL;

	vcq_set_header(&vcq[0], DRBG_CONFIG_VCQ_CMDS);
	vcq_add_drbg_reset(&vcq[1]);
	vcq_add_drbg_config(&vcq[2], req.entropy_ratio,
			    req.security_strength);
	vcq_add_flush(&vcq[3], CORE_ID_DRBG);

	ret = cmh_tm_submit_sync_mbx(vcq, DRBG_CONFIG_VCQ_CMDS, 1, MGMT_MBX);
	if (ret)
		dev_warn(cmh_dev(), "mgmt: DRBG CONFIG failed (rc=%d)\n", ret);
	else
		dev_info(cmh_dev(), "mgmt: DRBG configured (ratio=%u strength=0x%x)\n",
			 req.entropy_ratio, req.security_strength);

	return ret;
}

/* -- ioctl dispatch ------------------------ */

/*
 * PKE, SM2, and PQC ioctls use device-internal temporary storage for
 * intermediate results.  Residual allocations in the per-mailbox temp
 * store (left by prior operations that targeted SYS_REF_TEMP) reduce
 * the space available and can cause the device to return ENOMEM.
 *
 * Flush the mailbox before these operations to reset the temp store,
 * but ONLY when the store is actually dirty (mgmt_temp_dirty flag).
 * Unconditional flushing would kill in-flight command queues from
 * concurrent callers on the same mailbox -- MBX_COMMAND_FLUSH
 * terminates any executing queue with -EPIPE and discards all queued
 * submissions.
 *
 * The conditional flush is safe: PKE/SM2/PQC ioctls do not consume
 * SYS_REF_TEMP from a prior ioctl (unlike DS_EXPORT/DS_IMPORT which
 * may reference a temp key produced by a preceding derivation), so
 * clearing the temp store before them loses no needed state.
 */
static inline bool cmh_mgmt_needs_temp_flush(unsigned int cmd)
{
	unsigned int nr = _IOC_NR(cmd);

	/*
	 * Range invariant: all PKE/SM2/PQC ioctls must have consecutive
	 * NR values between PKE_RSA_ENC (0x10) and SM2_ENC_HASH (0x37).
	 * If a new ioctl is added outside this range, update the bounds
	 * and adjust these assertions.
	 */
	BUILD_BUG_ON(_IOC_NR(CMH_IOCTL_PKE_RSA_ENC) != 0x10);
	BUILD_BUG_ON(_IOC_NR(CMH_IOCTL_SM2_ENC_HASH) != 0x37);

	return nr >= _IOC_NR(CMH_IOCTL_PKE_RSA_ENC) &&
	       nr <= _IOC_NR(CMH_IOCTL_SM2_ENC_HASH);
}

static long cmh_mgmt_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	int ret;

	if (cmh_mgmt_needs_temp_flush(cmd) &&
	    atomic_xchg(&mgmt_temp_dirty, 0)) {
		ret = cmh_tm_flush_mbx(MGMT_MBX);
		if (ret)
			return ret;
	}

	switch (cmd) {
	case CMH_IOCTL_KEY_NEW:
		return cmh_mgmt_key_new(argp);
	case CMH_IOCTL_KEY_WRITE:
		return cmh_mgmt_key_write(argp);
	case CMH_IOCTL_KEY_READ:
		return cmh_mgmt_key_read(argp);
	case CMH_IOCTL_KEY_FIND:
		return cmh_mgmt_key_find(argp);
	case CMH_IOCTL_KEY_GRANT:
		return cmh_mgmt_key_grant(argp, false);
	case CMH_IOCTL_KEY_DELETE:
		return cmh_mgmt_key_grant(argp, true);
	case CMH_IOCTL_DS_EXPORT:
		return cmh_mgmt_ds_export(argp);
	case CMH_IOCTL_DS_IMPORT:
		return cmh_mgmt_ds_import(argp);
	case CMH_IOCTL_KIC_HKDF1:
		return cmh_mgmt_kic_hkdf1(argp);
	case CMH_IOCTL_KIC_HKDF2:
		return cmh_mgmt_kic_hkdf2(argp);
	case CMH_IOCTL_KEY_NEW_RANDOM:
		return cmh_mgmt_key_new_random(argp);
	case CMH_IOCTL_KIC_AES_CMAC_KDF:
		return cmh_mgmt_kic_aes_cmac_kdf(argp);
	case CMH_IOCTL_KIC_DKEK_DERIVE:
		return cmh_mgmt_kic_dkek_derive(argp);
	case CMH_IOCTL_KEY_LIST:
		return cmh_mgmt_key_list(argp);
	case CMH_IOCTL_EAC_READ:
		return cmh_mgmt_eac_read(argp);
	/* PKE operations */
	case CMH_IOCTL_PKE_RSA_ENC:
		return cmh_mgmt_pke_rsa_enc(argp);
	case CMH_IOCTL_PKE_RSA_DEC:
		return cmh_mgmt_pke_rsa_dec(argp);
	case CMH_IOCTL_PKE_RSA_CRT_DEC:
		return cmh_mgmt_pke_rsa_crt_dec(argp);
	case CMH_IOCTL_PKE_RSA_KEYGEN:
		return cmh_mgmt_pke_rsa_keygen(argp);
	case CMH_IOCTL_PKE_ECDSA_SIGN:
		return cmh_mgmt_pke_ecdsa_sign(argp);
	case CMH_IOCTL_PKE_ECDH:
		return cmh_mgmt_pke_ecdh(argp);
	case CMH_IOCTL_PKE_ECDH_KEYGEN:
		return cmh_mgmt_pke_ecdh_keygen(argp);
	case CMH_IOCTL_PKE_EDDSA_SIGN:
		return cmh_mgmt_pke_eddsa_sign(argp);
	case CMH_IOCTL_PKE_EDDSA_VERIFY:
		return cmh_mgmt_pke_eddsa_verify(argp);
	case CMH_IOCTL_PKE_EC_KEYGEN:
		return cmh_mgmt_pke_ec_keygen(argp);
	case CMH_IOCTL_PKE_EC_PUBGEN:
		return cmh_mgmt_pke_ec_pubgen(argp);
	case CMH_IOCTL_PKE_EDDSA_KEYGEN_SCA:
		return cmh_mgmt_pke_eddsa_keygen_sca(argp);
	/* SM2 operations */
	case CMH_IOCTL_SM2_ECDH_KEYGEN:
		return cmh_mgmt_sm2_ecdh_keygen(argp);
	case CMH_IOCTL_SM2_ECDH:
		return cmh_mgmt_sm2_ecdh(argp);
	case CMH_IOCTL_SM2_DEC_POINT:
		return cmh_mgmt_sm2_dec_point(argp);
	case CMH_IOCTL_SM2_ENC_POINT:
		return cmh_mgmt_sm2_enc_point(argp);
	case CMH_IOCTL_SM2_ID_DIGEST:
		return cmh_mgmt_sm2_id_digest(argp);
	case CMH_IOCTL_SM2_ECDH_HASH:
		return cmh_mgmt_sm2_ecdh_hash(argp);
	case CMH_IOCTL_SM2_DEC_HASH:
		return cmh_mgmt_sm2_dec_hash(argp);
	case CMH_IOCTL_SM2_ENC_HASH:
		return cmh_mgmt_sm2_enc_hash(argp);
	/* PQC operations */
	case CMH_IOCTL_ML_KEM_KEYGEN:
		return cmh_mgmt_ml_kem_keygen(argp);
	case CMH_IOCTL_ML_KEM_ENC:
		return cmh_mgmt_ml_kem_enc(argp);
	case CMH_IOCTL_ML_KEM_DEC:
		return cmh_mgmt_ml_kem_dec(argp);
	case CMH_IOCTL_ML_DSA_KEYGEN:
		return cmh_mgmt_ml_dsa_keygen(argp);
	case CMH_IOCTL_ML_DSA_SIGN:
		return cmh_mgmt_ml_dsa_sign(argp);
	case CMH_IOCTL_SLHDSA_KEYGEN:
		return cmh_mgmt_slhdsa_keygen(argp);
	case CMH_IOCTL_SLHDSA_SIGN:
		return cmh_mgmt_slhdsa_sign(argp);
	case CMH_IOCTL_SLHDSA_SIGN_PREHASH:
		return cmh_mgmt_slhdsa_sign_prehash(argp);
	/* DRBG management */
	case CMH_IOCTL_DRBG_CONFIG:
		return cmh_mgmt_drbg_config(argp);
	default:
		return -ENOTTY;
	}
}

/* -- File operations ----------------------- */

/*
 * Capability is checked once at open time.  A privileged process may
 * pass the resulting fd to an unprivileged helper -- this delegation
 * model is intentional and mirrors /dev/kvm, /dev/loop-control, etc.
 */
static int cmh_mgmt_open(struct inode *inode, struct file *file)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return 0;
}

static const struct file_operations cmh_mgmt_fops = {
	.owner          = THIS_MODULE,
	.open           = cmh_mgmt_open,
	.unlocked_ioctl = cmh_mgmt_ioctl,
	.compat_ioctl   = compat_ptr_ioctl,
};

static struct miscdevice cmh_mgmt_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "cmh_mgmt",
	.fops  = &cmh_mgmt_fops,
	.mode  = 0660,
};

static bool cmh_mgmt_registered;

/**
 * cmh_mgmt_register() - Register the /dev/cmh_mgmt misc device
 *
 * Return: 0 on success, negative errno on failure.
 */
int cmh_mgmt_register(void)
{
	int ret;

	/*
	 * ABI size guards -- catch silent layout changes at compile time.
	 * All ioctl structs use only __u32 and __u64 with explicit padding,
	 * guaranteeing identical layout on 32-bit and 64-bit (compat_ptr_ioctl).
	 */
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_key_new) != 32);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_key_write) != 40);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_key_read) != 40);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_key_find) != 32);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_key_list) != 40);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_key_grant) != 40);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_ds_export) != 40);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_ds_import) != 24);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_kic_hkdf1) != 48);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_kic_hkdf2) != 56);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_kic_aes_cmac_kdf) != 48);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_kic_dkek_derive) != 48);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_pke_rsa_enc) != 48);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_pke_rsa_dec) != 56);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_pke_rsa_crt_dec) != 56);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_pke_rsa_keygen) != 64);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_pke_ecdsa_sign) != 40);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_pke_ecdh) != 48);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_pke_ecdh_keygen) != 24);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_pke_eddsa_sign) != 40);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_pke_eddsa_verify) != 40);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_pke_ec_keygen) != 32);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_pke_ec_pubgen) != 24);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_pke_eddsa_keygen_sca) != 32);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_ml_kem_keygen) != 64);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_ml_kem_enc) != 64);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_ml_kem_dec) != 56);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_ml_dsa_keygen) != 56);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_ml_dsa_sign) != 48);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_slhdsa_keygen) != 56);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_slhdsa_sign) != 56);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_slhdsa_sign_prehash) != 64);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_sm2_ecdh_keygen) != 24);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_sm2_ecdh) != 56);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_sm2_dec_point) != 32);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_sm2_enc_point) != 40);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_sm2_id_digest) != 32);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_sm2_ecdh_hash) != 40);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_sm2_dec_hash) != 32);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_sm2_enc_hash) != 32);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_eac_read) != 64);
	BUILD_BUG_ON(sizeof(struct cmh_ioctl_drbg_config) != 16);

	ret = misc_register(&cmh_mgmt_dev);
	if (ret) {
		dev_err(cmh_dev(), "mgmt: misc_register failed (rc=%d)\n", ret);
		return ret;
	}

	cmh_mgmt_registered = true;
	dev_info(cmh_dev(), "mgmt: registered /dev/cmh_mgmt\n");
	return 0;
}

/**
 * cmh_mgmt_unregister() - Unregister the /dev/cmh_mgmt misc device
 */
void cmh_mgmt_unregister(void)
{
	if (!cmh_mgmt_registered)
		return;

	misc_deregister(&cmh_mgmt_dev);
	cmh_mgmt_registered = false;
	dev_info(cmh_dev(), "mgmt: unregistered /dev/cmh_mgmt\n");
}
