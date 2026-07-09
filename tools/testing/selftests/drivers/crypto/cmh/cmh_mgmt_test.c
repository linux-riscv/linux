// SPDX-License-Identifier: GPL-2.0
/*
 * Kselftest for /dev/cmh_mgmt ioctl interface.
 *
 * Tests basic ioctl operations on the CRI CryptoManager Hub management
 * device.  Requires the cmh module loaded on real or emulated hardware.
 *
 * Run:  ./cmh_mgmt_test
 * Output: TAP format (compatible with kselftest harness)
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "kselftest_harness.h"
#include <linux/cmh_mgmt_ioctl.h>

#define CMH_DEV "/dev/cmh_mgmt"

FIXTURE(cmh_mgmt)
{
	int fd;
};

FIXTURE_SETUP(cmh_mgmt)
{
	self->fd = open(CMH_DEV, O_RDWR);
	if (self->fd < 0 && errno == ENOENT)
		SKIP(return, "Device " CMH_DEV " not present (module not loaded?)");
	if (self->fd < 0 && errno == EACCES)
		SKIP(return, "Permission denied -- run as root or with CAP_SYS_ADMIN");
	ASSERT_GE(self->fd, 0);
}

FIXTURE_TEARDOWN(cmh_mgmt)
{
	if (self->fd >= 0)
		close(self->fd);
}

/*
 * Test 1: open and close succeed.
 * If we get here, FIXTURE_SETUP already validated the open.
 */
TEST_F(cmh_mgmt, open_close)
{
	ASSERT_GE(self->fd, 0);
}

/*
 * Test 2: invalid ioctl number returns -ENOTTY.
 */
TEST_F(cmh_mgmt, invalid_ioctl)
{
	int ret;
	unsigned long bogus_cmd = _IOC(_IOC_READ, 'J', 0xFF, 4);

	ret = ioctl(self->fd, bogus_cmd, NULL);
	ASSERT_EQ(ret, -1);
	ASSERT_EQ(errno, ENOTTY);
}

/*
 * Test 3: KEY_NEW with bad version field returns -EINVAL.
 */
TEST_F(cmh_mgmt, bad_version)
{
	struct cmh_ioctl_key_new req;
	int ret;

	memset(&req, 0, sizeof(req));
	req.version = 0; /* invalid */
	req.ds_type = CMH_DS_AES_KEY;
	req.len = 32;
	req.flags = CMH_FLAG_PT;
	req.cid = 0xDEAD;

	ret = ioctl(self->fd, CMH_IOCTL_KEY_NEW, &req);
	ASSERT_EQ(ret, -1);
	ASSERT_EQ(errno, EINVAL);
}

/*
 * Test 4: KEY_NEW creates a key, KEY_DELETE destroys it.
 */
TEST_F(cmh_mgmt, key_new_delete)
{
	struct cmh_ioctl_key_new new_req;
	struct cmh_ioctl_key_grant del_req;
	int ret;

	memset(&new_req, 0, sizeof(new_req));
	new_req.version = CMH_MGMT_V1;
	new_req.ds_type = CMH_DS_AES_KEY;
	new_req.len = 32;
	new_req.flags = CMH_FLAG_PT;
	new_req.cid = 0x5E1F7E57ULL; /* "SELFTEST" */

	ret = ioctl(self->fd, CMH_IOCTL_KEY_NEW, &new_req);
	ASSERT_EQ(ret, 0);
	ASSERT_NE(new_req.ref, (uint64_t)0);

	/* Delete the key */
	memset(&del_req, 0, sizeof(del_req));
	del_req.version = CMH_MGMT_V1;
	del_req.ref = new_req.ref;

	ret = ioctl(self->fd, CMH_IOCTL_KEY_DELETE, &del_req);
	ASSERT_EQ(ret, 0);
}

/*
 * Test 5: KIC HKDF1 key derivation from hardware base key.
 * Requires at least one KIC base key provisioned (KIC_KEY1).
 */
TEST_F(cmh_mgmt, kic_hkdf1)
{
	struct cmh_ioctl_kic_hkdf1 req;
	static const char label[] = "kselftest-label";
	int ret;

	memset(&req, 0, sizeof(req));
	req.version = CMH_MGMT_V1;
	req.key_len = 32;
	req.base_key = CMH_KIC_KEY1;
	req.cid = 0x4B534C46ULL; /* "KSLF" */
	req.label = (uint64_t)(uintptr_t)label;
	req.label_len = sizeof(label) - 1;
	req.flags = CMH_KIC_FLAG_TEMP;

	ret = ioctl(self->fd, CMH_IOCTL_KIC_HKDF1, &req);
	if (ret < 0 && errno == EIO)
		SKIP(return, "KIC base key 1 not provisioned on this device");
	ASSERT_EQ(ret, 0);
	ASSERT_NE(req.ref, (uint64_t)0);
}

/*
 * Test 6: ML-KEM-768 keygen using hardware RNG.
 * Verifies the PQC keygen path end-to-end.
 */
TEST_F(cmh_mgmt, ml_kem_keygen)
{
	struct cmh_ioctl_ml_kem_keygen req;
	/* ML-KEM-768: ek = 384*3+32 = 1184, dk = 768*3+96 = 2400 */
	uint8_t ek[1184];
	uint8_t dk[2400];
	int ret;

	memset(&req, 0, sizeof(req));
	req.version = CMH_MGMT_V1;
	req.k = 3; /* ML-KEM-768 */
	req.flags = CMH_QSE_FLAG_HW_RNG;
	req.seed = 0; /* HW RNG */
	req.z = 0;    /* HW RNG */
	req.ek = (uint64_t)(uintptr_t)ek;
	req.dk = (uint64_t)(uintptr_t)dk;
	req.dk_cid = 0;
	req.dk_ref = 0;

	memset(ek, 0, sizeof(ek));
	memset(dk, 0, sizeof(dk));

	ret = ioctl(self->fd, CMH_IOCTL_ML_KEM_KEYGEN, &req);
	if (ret < 0 && errno == ENODEV)
		SKIP(return, "QSE core not available on this hardware");
	ASSERT_EQ(ret, 0);

	/* Verify output is non-zero (extremely unlikely for random keys) */
	{
		int i, nonzero = 0;

		for (i = 0; i < 64; i++)
			nonzero += (ek[i] != 0);
		ASSERT_GT(nonzero, 0);
	}
}

TEST_HARNESS_MAIN
