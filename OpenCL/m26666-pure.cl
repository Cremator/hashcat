/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes-gcm.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct pbkdf2_sha1_tmp
{
  u32  ipad[5];
  u32  opad[5];
  u32  dgst[32];
  u32  out[32];
} pbkdf2_sha1_tmp_t;

typedef struct zfs_crypto
{
  u32 salt_buf[2];   // 64-bit salt
  u32 iv_buf[3];     // 96-bit IV
  u32 mac[4];        // 128-bit MAC
  u32 master_key[8]; // 256-bit encrypted master key
  u32 guid[2];       // 64-bit GUID
  u32 ddoobj;        // DDOBJ reference
  u32 refcount;      // Reference count
  u32 suite;         // Encryption suite
  u32 hmac_key[16];  // 512-bit HMAC key
} zfs_crypto_t;

DECLSPEC void hmac_sha1_run_V (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad, PRIVATE_AS u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = 0x80000000;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 20) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);
}

KERNEL_FQ void m26666_init (KERN_ATTR_TMPS_ESALT (pbkdf2_sha1_tmp_t, zfs_crypto_t))
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  sha1_hmac_ctx_t sha1_hmac_ctx;
  sha1_hmac_init_global_swap (&sha1_hmac_ctx, pws[gid].i, pws[gid].pw_len);

  for (int i = 0; i < 5; i++)
  {
    tmps[gid].ipad[i] = sha1_hmac_ctx.ipad.h[i];
    tmps[gid].opad[i] = sha1_hmac_ctx.opad.h[i];
  }

  // Process salt
  sha1_hmac_update_global_swap (&sha1_hmac_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  for (u32 i = 0, j = 1; i < 20; i += 5, j += 1)
  {
    sha1_hmac_ctx_t sha1_hmac_ctx2 = sha1_hmac_ctx;

    u32 w0[4] = { j, 0, 0, 0 };
    u32 w1[4] = { 0 };
    u32 w2[4] = { 0 };
    u32 w3[4] = { 0 };

    sha1_hmac_update_64 (&sha1_hmac_ctx2, w0, w1, w2, w3, 4);
    sha1_hmac_final (&sha1_hmac_ctx2);

    tmps[gid].dgst[i + 0] = sha1_hmac_ctx2.opad.h[0];
    tmps[gid].dgst[i + 1] = sha1_hmac_ctx2.opad.h[1];
    tmps[gid].dgst[i + 2] = sha1_hmac_ctx2.opad.h[2];
    tmps[gid].dgst[i + 3] = sha1_hmac_ctx2.opad.h[3];
    tmps[gid].dgst[i + 4] = sha1_hmac_ctx2.opad.h[4];

    tmps[gid].out[i + 0] = tmps[gid].dgst[i + 0];
    tmps[gid].out[i + 1] = tmps[gid].dgst[i + 1];
    tmps[gid].out[i + 2] = tmps[gid].dgst[i + 3];
    tmps[gid].out[i + 3] = tmps[gid].dgst[i + 4];
  }
}

KERNEL_FQ void m26666_loop (KERN_ATTR_TMPS_ESALT (pbkdf2_sha1_tmp_t, zfs_crypto_t))
{
  const u64 gid = get_global_id (0);
  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u32x ipad[5], opad[5];
  for (int i = 0; i < 5; i++)
  {
    ipad[i] = packv (tmps, ipad, gid, i);
    opad[i] = packv (tmps, opad, gid, i);
  }

  for (u32 i = 0; i < 10; i += 5)
  {
    u32x dgst[5], out[5];
    for (int k = 0; k < 5; k++)
    {
      dgst[k] = packv (tmps, dgst, gid, i + k);
      out[k]  = packv (tmps, out,  gid, i + k);
    }

    for (u32 j = 0; j < LOOP_CNT; j++)
    {
      u32x w0[4] = { dgst[0], dgst[1], dgst[2], dgst[3] };
      u32x w1[4] = { dgst[4], 0, 0, 0 };
      u32x w2[4] = { 0 };
      u32x w3[4] = { 0 };

      hmac_sha1_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      for (int k = 0; k < 5; k++) out[k] ^= dgst[k];
    }

    for (int k = 0; k < 5; k++)
    {
      unpackv (tmps, dgst, gid, i + k, dgst[k]);
      unpackv (tmps, out,  gid, i + k, out[k]);
    }
  }
}

KERNEL_FQ void m26666_comp (KERN_ATTR_TMPS_ESALT (pbkdf2_sha1_tmp_t, zfs_crypto_t))
{
  const u64 gid = get_global_id (0);
  if (gid >= GID_CNT) return;

  u32 ukey[8];
  for (int i = 0; i < 8; i++) ukey[i] = tmps[gid].out[i];

  u32 key[60] = { 0 }, subKey[4] = { 0 };
  AES_GCM_Init (ukey, 256, key, subKey, s_te0, s_te1, s_te2, s_te3, s_te4);

  u32 iv[3];
  for (int i = 0; i < 3; i++) iv[i] = esalt_bufs[DIGESTS_OFFSET_HOST].iv_buf[i];

  u32 J0[4] = { 0 };
  AES_GCM_Prepare_J0 (iv, 12, subKey, J0);

  u32 T[4] = { 0 }, S[4] = { 0 };
  AES_GCM_GHASH_GLOBAL (subKey, NULL, 0, esalt_bufs[DIGESTS_OFFSET_HOST].master_key, 32, S);
  AES_GCM_GCTR (key, J0, S, 16, T, s_te0, s_te1, s_te2, s_te3, s_te4);

  const u32 r0 = T[0] ^ esalt_bufs[DIGESTS_OFFSET_HOST].mac[0];
  const u32 r1 = T[1] ^ esalt_bufs[DIGESTS_OFFSET_HOST].mac[1];
  const u32 r2 = T[2] ^ esalt_bufs[DIGESTS_OFFSET_HOST].mac[2];
  const u32 r3 = T[3] ^ esalt_bufs[DIGESTS_OFFSET_HOST].mac[3];

  #define il_pos 0
  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
