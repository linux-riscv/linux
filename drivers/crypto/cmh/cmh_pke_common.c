// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Cryptography Research, Inc. (CRI).
 * CMH LKM -- PKE Common VCQ Builders
 *
 * VCQ builder functions for all PKE core commands.  Each builder
 * populates a single vcq_cmd slot with the appropriate magic,
 * command ID, byte-swap flags, and command-specific payload.
 *
 * RSA commands always use PKE_SWAP_FLAGS (VCQ_FLAG_SWAP_BYTES |
 * VCQ_FLAG_SWAP_WORDS).  EC Weierstrass curves (NIST P-*, Brainpool,
 * secp256k1, SM2) use PKE_SWAP_FLAGS; Edwards curves (25519, 448)
 * use no swap flags.  SM2 commands use per-command flags documented
 * in the eSW ABI.
 *
 * Callers combine these with vcq_set_header() + vcq_add_flush()
 * and submit via cmh_tm_submit_sync().
 */

#include <linux/string.h>

#include "cmh_pke.h"

/**
 * vcq_add_pke_flush() - Add a PKE flush command to a VCQ slot
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 *
 * Populates @slot with a flush command for the specified PKE core.
 */
void vcq_add_pke_flush(struct vcq_cmd *slot, u32 core_id)
{
	vcq_add_flush(slot, core_id);
}

/* RSA */

/**
 * vcq_add_pke_rsa_enc() - Build a VCQ command for RSA public-key encryption
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 * @bits: RSA key size in bits
 * @e_len: Length of the public exponent in bytes
 * @e_dma: DMA address of public exponent buffer
 * @n_dma: DMA address of modulus buffer
 * @m_dma: DMA address of plaintext message buffer
 * @c_dma: DMA address of ciphertext output buffer
 * @flags: VCQ command flags
 */
void vcq_add_pke_rsa_enc(struct vcq_cmd *slot, u32 core_id, u32 bits, u32 e_len,
			 u64 e_dma, u64 n_dma, u64 m_dma, u64 c_dma,
			 u32 flags)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, flags, 1, PKE_CMD_RSA_ENC);
	slot->hwc.pke.cmd_rsa_enc.bits = bits;
	slot->hwc.pke.cmd_rsa_enc.e_len = e_len;
	slot->hwc.pke.cmd_rsa_enc.e = e_dma;
	slot->hwc.pke.cmd_rsa_enc.n = n_dma;
	slot->hwc.pke.cmd_rsa_enc.m = m_dma;
	slot->hwc.pke.cmd_rsa_enc.c = c_dma;
}

/**
 * vcq_add_pke_rsa_dec() - Build a VCQ command for RSA private-key decryption
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 * @bits: RSA key size in bits
 * @e_len: Length of the public exponent in bytes
 * @e_dma: DMA address of public exponent buffer
 * @n_dma: DMA address of modulus buffer
 * @c_dma: DMA address of ciphertext input buffer
 * @m_dma: DMA address of plaintext output buffer
 * @d_ref: Datastore reference for the private exponent
 * @flags: VCQ command flags
 */
void vcq_add_pke_rsa_dec(struct vcq_cmd *slot, u32 core_id, u32 bits, u32 e_len,
			 u64 e_dma, u64 n_dma, u64 c_dma, u64 m_dma,
			 u64 d_ref, u32 flags)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, flags, 1, PKE_CMD_RSA_DEC);
	slot->hwc.pke.cmd_rsa_dec.bits = bits;
	slot->hwc.pke.cmd_rsa_dec.e_len = e_len;
	slot->hwc.pke.cmd_rsa_dec.e = e_dma;
	slot->hwc.pke.cmd_rsa_dec.n = n_dma;
	slot->hwc.pke.cmd_rsa_dec.c = c_dma;
	slot->hwc.pke.cmd_rsa_dec.m = m_dma;
	slot->hwc.pke.cmd_rsa_dec.d = d_ref;
}

/**
 * vcq_add_pke_rsa_crt_dec() - Build a VCQ command for RSA-CRT decryption
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 * @bits: RSA key size in bits
 * @e_len: Length of the public exponent in bytes
 * @e_dma: DMA address of public exponent buffer
 * @n_dma: DMA address of modulus buffer
 * @c_dma: DMA address of ciphertext input buffer
 * @m_dma: DMA address of plaintext output buffer
 * @crt_ref: Datastore reference for CRT private key components
 * @flags: VCQ command flags
 */
void vcq_add_pke_rsa_crt_dec(struct vcq_cmd *slot, u32 core_id, u32 bits, u32 e_len,
			     u64 e_dma, u64 n_dma, u64 c_dma, u64 m_dma,
			     u64 crt_ref, u32 flags)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, flags, 1, PKE_CMD_RSA_CRT_DEC);
	slot->hwc.pke.cmd_rsa_crt_dec.bits = bits;
	slot->hwc.pke.cmd_rsa_crt_dec.e_len = e_len;
	slot->hwc.pke.cmd_rsa_crt_dec.e = e_dma;
	slot->hwc.pke.cmd_rsa_crt_dec.n = n_dma;
	slot->hwc.pke.cmd_rsa_crt_dec.c = c_dma;
	slot->hwc.pke.cmd_rsa_crt_dec.m = m_dma;
	slot->hwc.pke.cmd_rsa_crt_dec.crt = crt_ref;
}

/* ECDSA */

/**
 * vcq_add_pke_ecdsa_verify() - Build a VCQ command for ECDSA signature verification
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 * @curve: Curve identifier (e.g. NIST P-256, P-384, P-521)
 * @dlen: Digest length in bytes
 * @pk_dma: DMA address of public key buffer
 * @dig_dma: DMA address of digest buffer
 * @sig_dma: DMA address of signature buffer
 * @rp_dma: DMA address of r-prime verification output buffer
 * @flags: VCQ command flags
 */
void vcq_add_pke_ecdsa_verify(struct vcq_cmd *slot, u32 core_id, u32 curve, u32 dlen,
			      u64 pk_dma, u64 dig_dma, u64 sig_dma,
			      u64 rp_dma, u32 flags)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, flags, 1, PKE_CMD_ECDSA_VERIFY);
	slot->hwc.pke.cmd_ecdsa_verify.curve = curve;
	slot->hwc.pke.cmd_ecdsa_verify.digest_len = dlen;
	slot->hwc.pke.cmd_ecdsa_verify.public_key = pk_dma;
	slot->hwc.pke.cmd_ecdsa_verify.digest = dig_dma;
	slot->hwc.pke.cmd_ecdsa_verify.signature = sig_dma;
	slot->hwc.pke.cmd_ecdsa_verify.rprime = rp_dma;
}

/**
 * vcq_add_pke_ecdsa_sign() - Build a VCQ command for ECDSA signing
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 * @curve: Curve identifier (e.g. NIST P-256, P-384, P-521)
 * @sklen: Secret key length in bytes
 * @dig_dma: DMA address of digest buffer
 * @sig_dma: DMA address of signature output buffer
 * @sk_ref: Datastore reference for the secret key
 * @dlen: Digest length in bytes
 * @flags: VCQ command flags
 */
void vcq_add_pke_ecdsa_sign(struct vcq_cmd *slot, u32 core_id, u32 curve, u32 sklen,
			    u64 dig_dma, u64 sig_dma, u64 sk_ref,
			    u32 dlen, u32 flags)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, flags, 1, PKE_CMD_ECDSA_SIGN);
	slot->hwc.pke.cmd_ecdsa_sign.curve = curve;
	slot->hwc.pke.cmd_ecdsa_sign.secret_key_len = sklen;
	slot->hwc.pke.cmd_ecdsa_sign.digest = dig_dma;
	slot->hwc.pke.cmd_ecdsa_sign.signature = sig_dma;
	slot->hwc.pke.cmd_ecdsa_sign.secret_key = sk_ref;
	slot->hwc.pke.cmd_ecdsa_sign.digest_len = dlen;
}

/**
 * vcq_add_pke_ecdsa_pubgen() - Build a VCQ command for ECDSA public key generation
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 * @curve: Curve identifier (e.g. NIST P-256, P-384, P-521)
 * @sklen: Secret key length in bytes
 * @pk_dma: DMA address of public key output buffer
 * @sk_ref: Datastore reference for the secret key
 * @flags: VCQ command flags
 *
 * Generates the public key from an existing private key stored in the
 * datastore.
 */
void vcq_add_pke_ecdsa_pubgen(struct vcq_cmd *slot, u32 core_id, u32 curve, u32 sklen,
			      u64 pk_dma, u64 sk_ref, u32 flags)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, flags, 1, PKE_CMD_ECDSA_PUBGEN);
	slot->hwc.pke.cmd_ecdsa_pubgen.curve = curve;
	slot->hwc.pke.cmd_ecdsa_pubgen.secret_key_len = sklen;
	slot->hwc.pke.cmd_ecdsa_pubgen.public_key = pk_dma;
	slot->hwc.pke.cmd_ecdsa_pubgen.secret_key = sk_ref;
}

/**
 * vcq_add_pke_ecdsa_keygen() - Build a VCQ command for ECDSA key pair generation
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 * @curve: Curve identifier (e.g. NIST P-256, P-384, P-521)
 * @sklen: Secret key length in bytes
 * @sk_ref: Datastore reference for the generated secret key
 * @sk_type: Datastore type for the secret key object
 * @flags: VCQ command flags
 */
void vcq_add_pke_ecdsa_keygen(struct vcq_cmd *slot, u32 core_id, u32 curve, u32 sklen,
			      u64 sk_ref, u32 sk_type, u32 flags)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, flags, 1, PKE_CMD_ECDSA_KEYGEN);
	slot->hwc.pke.cmd_ecdsa_keygen.curve = curve;
	slot->hwc.pke.cmd_ecdsa_keygen.secret_key_len = sklen;
	slot->hwc.pke.cmd_ecdsa_keygen.secret_key = sk_ref;
	slot->hwc.pke.cmd_ecdsa_keygen.secret_key_type = sk_type;
}

/* ECDH */

/**
 * vcq_add_pke_ecdh_keygen() - Build a VCQ command for ECDH key pair generation
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 * @curve: Curve identifier (e.g. NIST P-256, P-384, P-521, X25519, X448)
 * @sklen: Secret key length in bytes
 * @pkx_dma: DMA address of public key X-coordinate output buffer
 * @sk_ref: Datastore reference for the generated secret key
 * @flags: VCQ command flags
 */
void vcq_add_pke_ecdh_keygen(struct vcq_cmd *slot, u32 core_id, u32 curve, u32 sklen,
			     u64 pkx_dma, u64 sk_ref, u32 flags)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, flags, 1, PKE_CMD_ECDH_KEYGEN);
	slot->hwc.pke.cmd_ecdh_keygen.curve = curve;
	slot->hwc.pke.cmd_ecdh_keygen.secret_key_len = sklen;
	slot->hwc.pke.cmd_ecdh_keygen.public_key_x = pkx_dma;
	slot->hwc.pke.cmd_ecdh_keygen.secret_key = sk_ref;
}

/**
 * vcq_add_pke_ecdh() - Build a VCQ command for ECDH shared secret computation
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 * @curve: Curve identifier (e.g. NIST P-256, P-384, P-521, X25519, X448)
 * @sklen: Secret key length in bytes
 * @sslen: Shared secret length in bytes
 * @ss_type: Datastore type for the shared secret object
 * @peer_dma: DMA address of peer public key buffer
 * @sk_ref: Datastore reference for the local secret key
 * @ss_ref: Datastore reference for the computed shared secret
 * @flags: VCQ command flags
 */
void vcq_add_pke_ecdh(struct vcq_cmd *slot, u32 core_id, u32 curve, u32 sklen,
		      u32 sslen, u32 ss_type, u64 peer_dma, u64 sk_ref,
		      u64 ss_ref, u32 flags)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, flags, 1, PKE_CMD_ECDH);
	slot->hwc.pke.cmd_ecdh.curve = curve;
	slot->hwc.pke.cmd_ecdh.secret_key_len = sklen;
	slot->hwc.pke.cmd_ecdh.shared_secret_len = sslen;
	slot->hwc.pke.cmd_ecdh.shared_secret_type = ss_type;
	slot->hwc.pke.cmd_ecdh.peer_key_x = peer_dma;
	slot->hwc.pke.cmd_ecdh.secret_key = sk_ref;
	slot->hwc.pke.cmd_ecdh.shared_secret = ss_ref;
}

/* EdDSA */

/**
 * vcq_add_pke_eddsa_verify() - Build a VCQ command for EdDSA signature verification
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 * @curve: Curve identifier (Ed25519 or Ed448)
 * @dlen: Digest (message) length in bytes
 * @pky_dma: DMA address of public key Y-coordinate buffer
 * @dig_dma: DMA address of digest buffer
 * @sig_dma: DMA address of signature buffer
 * @rp_dma: DMA address of r-prime verification output buffer
 * @flags: VCQ command flags
 */
void vcq_add_pke_eddsa_verify(struct vcq_cmd *slot, u32 core_id, u32 curve, u32 dlen,
			      u64 pky_dma, u64 dig_dma, u64 sig_dma,
			      u64 rp_dma, u32 flags)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, flags, 1, PKE_CMD_EDDSA_VERIFY);
	slot->hwc.pke.cmd_eddsa_verify.curve = curve;
	slot->hwc.pke.cmd_eddsa_verify.digest_len = dlen;
	slot->hwc.pke.cmd_eddsa_verify.public_key_y = pky_dma;
	slot->hwc.pke.cmd_eddsa_verify.digest = dig_dma;
	slot->hwc.pke.cmd_eddsa_verify.signature = sig_dma;
	slot->hwc.pke.cmd_eddsa_verify.rprime = rp_dma;
}

/**
 * vcq_add_pke_eddsa_sign() - Build a VCQ command for EdDSA signing
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 * @curve: Curve identifier (Ed25519 or Ed448)
 * @sklen: Secret key length in bytes
 * @dig_dma: DMA address of digest (message) buffer
 * @sig_dma: DMA address of signature output buffer
 * @sk_ref: Datastore reference for the secret key
 * @dlen: Digest (message) length in bytes
 * @flags: VCQ command flags
 */
void vcq_add_pke_eddsa_sign(struct vcq_cmd *slot, u32 core_id, u32 curve, u32 sklen,
			    u64 dig_dma, u64 sig_dma, u64 sk_ref,
			    u32 dlen, u32 flags)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, flags, 1, PKE_CMD_EDDSA_SIGN);
	slot->hwc.pke.cmd_eddsa_sign.curve = curve;
	slot->hwc.pke.cmd_eddsa_sign.secret_key_len = sklen;
	slot->hwc.pke.cmd_eddsa_sign.digest = dig_dma;
	slot->hwc.pke.cmd_eddsa_sign.signature = sig_dma;
	slot->hwc.pke.cmd_eddsa_sign.secret_key = sk_ref;
	slot->hwc.pke.cmd_eddsa_sign.digest_len = dlen;
}

/**
 * vcq_add_pke_eddsa_pubgen() - Build a VCQ command for EdDSA public key generation
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 * @curve: Curve identifier (Ed25519 or Ed448)
 * @sklen: Secret key length in bytes
 * @pky_dma: DMA address of public key Y-coordinate output buffer
 * @sk_ref: Datastore reference for the secret key
 * @flags: VCQ command flags
 *
 * Generates the public key from an existing private key stored in the
 * datastore.
 */
void vcq_add_pke_eddsa_pubgen(struct vcq_cmd *slot, u32 core_id, u32 curve, u32 sklen,
			      u64 pky_dma, u64 sk_ref, u32 flags)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, flags, 1, PKE_CMD_EDDSA_PUBGEN);
	slot->hwc.pke.cmd_eddsa_pubgen.curve = curve;
	slot->hwc.pke.cmd_eddsa_pubgen.secret_key_len = sklen;
	slot->hwc.pke.cmd_eddsa_pubgen.public_key_y = pky_dma;
	slot->hwc.pke.cmd_eddsa_pubgen.secret_key = sk_ref;
}

/**
 * vcq_add_pke_eddsa_keygen_sca() - Build a VCQ command for EdDSA SCA key generation
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 * @curve: Curve identifier (Ed448)
 * @sk_ref: Datastore reference for the input secret key
 * @sca_sk_ref: Datastore reference for the SCA-masked output key
 *
 * Blinds an Ed448 private key into a side-channel-protected masked
 * form.  No byte-swap flags are used (CRI reference uses flags=0).
 */
void vcq_add_pke_eddsa_keygen_sca(struct vcq_cmd *slot, u32 core_id, u32 curve,
				  u64 sk_ref, u64 sca_sk_ref)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, 0, 1,
			      PKE_CMD_EDDSA_PRIV_KEYGEN_SCA);
	slot->hwc.pke.cmd_eddsa_keygen_sca.curve = curve;
	slot->hwc.pke.cmd_eddsa_keygen_sca.secret_key = sk_ref;
	slot->hwc.pke.cmd_eddsa_keygen_sca.sca_secret_key = sca_sk_ref;
}

/* SM2 */

/**
 * vcq_add_pke_sm2_ecdh_keygen() - Build a VCQ command for SM2 ECDH ephemeral key generation
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 * @nonce_dma: DMA address of nonce input buffer
 * @session_key_dma: DMA address of session key output buffer
 * @nonce_len: Nonce length in bytes
 * @flags: VCQ command flags
 */
void vcq_add_pke_sm2_ecdh_keygen(struct vcq_cmd *slot, u32 core_id, u64 nonce_dma,
				 u64 session_key_dma, u32 nonce_len, u32 flags)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, flags, 1,
			      PKE_CMD_SM2_ECDH_KEYGEN);
	slot->hwc.pke.cmd_sm2_ecdh_keygen.nonce = nonce_dma;
	slot->hwc.pke.cmd_sm2_ecdh_keygen.session_key = session_key_dma;
	slot->hwc.pke.cmd_sm2_ecdh_keygen.nonce_len = nonce_len;
}

/**
 * vcq_add_pke_sm2_ecdh() - Build a VCQ command for SM2 ECDH shared secret computation
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 * @nonce_len: Nonce length in bytes
 * @private_key_len: Private key length in bytes
 * @nonce_dma: DMA address of nonce buffer
 * @peer_pk_dma: DMA address of peer public key buffer
 * @peer_sk_dma: DMA address of peer session key buffer
 * @priv_ref: Datastore reference for the local private key
 * @sp_ref: Datastore reference for the shared point output
 * @sp_type: Datastore type for the shared point object
 * @flags: VCQ command flags
 */
void vcq_add_pke_sm2_ecdh(struct vcq_cmd *slot, u32 core_id, u32 nonce_len,
			  u32 private_key_len, u64 nonce_dma,
			  u64 peer_pk_dma, u64 peer_sk_dma,
			  u64 priv_ref, u64 sp_ref, u32 sp_type, u32 flags)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, flags, 1, PKE_CMD_SM2_ECDH);
	slot->hwc.pke.cmd_sm2_ecdh.nonce_len = nonce_len;
	slot->hwc.pke.cmd_sm2_ecdh.private_key_len = private_key_len;
	slot->hwc.pke.cmd_sm2_ecdh.nonce = nonce_dma;
	slot->hwc.pke.cmd_sm2_ecdh.peer_public_key = peer_pk_dma;
	slot->hwc.pke.cmd_sm2_ecdh.peer_session_key = peer_sk_dma;
	slot->hwc.pke.cmd_sm2_ecdh.private_key = priv_ref;
	slot->hwc.pke.cmd_sm2_ecdh.shared_point = sp_ref;
	slot->hwc.pke.cmd_sm2_ecdh.shared_point_type = sp_type;
}

/**
 * vcq_add_pke_sm2_dec_point() - Build a VCQ command for SM2 decryption point multiplication
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 * @ct_len: Ciphertext length in bytes
 * @pk_len: Private key length in bytes
 * @ct_dma: DMA address of ciphertext input buffer
 * @dp_dma: DMA address of decryption point output buffer
 * @priv_ref: Datastore reference for the private key
 * @flags: VCQ command flags
 */
void vcq_add_pke_sm2_dec_point(struct vcq_cmd *slot, u32 core_id, u32 ct_len,
			       u32 pk_len, u64 ct_dma, u64 dp_dma,
			       u64 priv_ref, u32 flags)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, flags, 1, PKE_CMD_SM2_DEC_POINT);
	slot->hwc.pke.cmd_sm2_dec_point.ciphertext_len = ct_len;
	slot->hwc.pke.cmd_sm2_dec_point.private_key_len = pk_len;
	slot->hwc.pke.cmd_sm2_dec_point.ciphertext = ct_dma;
	slot->hwc.pke.cmd_sm2_dec_point.dec_point = dp_dma;
	slot->hwc.pke.cmd_sm2_dec_point.private_key = priv_ref;
}

/**
 * vcq_add_pke_sm2_enc_point() - Build a VCQ command for SM2 encryption point multiplication
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 * @nonce_dma: DMA address of nonce buffer
 * @pk_dma: DMA address of public key buffer
 * @ct_dma: DMA address of ciphertext header output buffer
 * @ep_dma: DMA address of encryption point output buffer
 * @nonce_len: Nonce length in bytes
 * @flags: VCQ command flags
 */
void vcq_add_pke_sm2_enc_point(struct vcq_cmd *slot, u32 core_id, u64 nonce_dma,
			       u64 pk_dma, u64 ct_dma, u64 ep_dma,
			       u32 nonce_len, u32 flags)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, flags, 1, PKE_CMD_SM2_ENC_POINT);
	slot->hwc.pke.cmd_sm2_enc_point.nonce = nonce_dma;
	slot->hwc.pke.cmd_sm2_enc_point.public_key = pk_dma;
	slot->hwc.pke.cmd_sm2_enc_point.ciphertext = ct_dma;
	slot->hwc.pke.cmd_sm2_enc_point.enc_point = ep_dma;
	slot->hwc.pke.cmd_sm2_enc_point.nonce_len = nonce_len;
}

/**
 * vcq_add_pke_sm2_id_digest() - Build a VCQ command for SM2 identity digest computation
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 * @id_dma: DMA address of identity string buffer
 * @pk_dma: DMA address of public key buffer
 * @dig_dma: DMA address of digest output buffer
 * @id_len: Identity string length in bytes
 * @flags: VCQ command flags
 */
void vcq_add_pke_sm2_id_digest(struct vcq_cmd *slot, u32 core_id, u64 id_dma,
			       u64 pk_dma, u64 dig_dma, u32 id_len,
			       u32 flags)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, flags, 1, PKE_CMD_SM2_ID_DIGEST);
	slot->hwc.pke.cmd_sm2_id_digest.id = id_dma;
	slot->hwc.pke.cmd_sm2_id_digest.public_key = pk_dma;
	slot->hwc.pke.cmd_sm2_id_digest.digest = dig_dma;
	slot->hwc.pke.cmd_sm2_id_digest.id_len = id_len;
}

/**
 * vcq_add_pke_sm2_ecdh_hash() - Build a VCQ command for SM2 ECDH key derivation hash
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 * @peer_dig_dma: DMA address of peer identity digest buffer
 * @dig_dma: DMA address of local identity digest buffer
 * @sp_ref: Datastore reference for the shared point
 * @sk_ref: Datastore reference for the derived shared key output
 * @sk_type: Datastore type for the shared key object
 * @flags: VCQ command flags
 */
void vcq_add_pke_sm2_ecdh_hash(struct vcq_cmd *slot, u32 core_id, u64 peer_dig_dma,
			       u64 dig_dma, u64 sp_ref, u64 sk_ref,
			       u32 sk_type, u32 flags)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, flags, 1, PKE_CMD_SM2_ECDH_HASH);
	slot->hwc.pke.cmd_sm2_ecdh_hash.peer_id_digest = peer_dig_dma;
	slot->hwc.pke.cmd_sm2_ecdh_hash.id_digest = dig_dma;
	slot->hwc.pke.cmd_sm2_ecdh_hash.shared_point = sp_ref;
	slot->hwc.pke.cmd_sm2_ecdh_hash.shared_key = sk_ref;
	slot->hwc.pke.cmd_sm2_ecdh_hash.shared_key_type = sk_type;
}

/**
 * vcq_add_pke_sm2_dec_hash() - Build a VCQ command for SM2 decryption hash verification
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 * @ct_dma: DMA address of ciphertext input buffer
 * @dp_dma: DMA address of decryption point buffer
 * @pt_dma: DMA address of plaintext output buffer
 * @ct_len: Ciphertext length in bytes
 * @flags: VCQ command flags
 */
void vcq_add_pke_sm2_dec_hash(struct vcq_cmd *slot, u32 core_id, u64 ct_dma,
			      u64 dp_dma, u64 pt_dma, u32 ct_len, u32 flags)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, flags, 1, PKE_CMD_SM2_DEC_HASH);
	slot->hwc.pke.cmd_sm2_dec_hash.ciphertext = ct_dma;
	slot->hwc.pke.cmd_sm2_dec_hash.dec_point = dp_dma;
	slot->hwc.pke.cmd_sm2_dec_hash.plaintext = pt_dma;
	slot->hwc.pke.cmd_sm2_dec_hash.ciphertext_len = ct_len;
}

/**
 * vcq_add_pke_sm2_enc_hash() - Build a VCQ command for SM2 encryption hash computation
 * @slot: VCQ command slot to populate
 * @core_id: PKE hardware core ID
 * @msg_dma: DMA address of plaintext message buffer
 * @ep_dma: DMA address of encryption point buffer
 * @ct_dma: DMA address of ciphertext output buffer
 * @msg_len: Message length in bytes
 * @flags: VCQ command flags
 */
void vcq_add_pke_sm2_enc_hash(struct vcq_cmd *slot, u32 core_id, u64 msg_dma,
			      u64 ep_dma, u64 ct_dma, u32 msg_len, u32 flags)
{
	memset(slot, 0, sizeof(*slot));
	slot->magic = VCQ_CMD_MAGIC;
	slot->id = VCQ_CMD_ID(core_id, flags, 1, PKE_CMD_SM2_ENC_HASH);
	slot->hwc.pke.cmd_sm2_enc_hash.message = msg_dma;
	slot->hwc.pke.cmd_sm2_enc_hash.enc_point = ep_dma;
	slot->hwc.pke.cmd_sm2_enc_hash.ciphertext = ct_dma;
	slot->hwc.pke.cmd_sm2_enc_hash.message_len = msg_len;
}
