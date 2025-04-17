/**
 * module_26666.c - Hashcat plugin for ZFS PBKDF2-HMAC-SHA1 + AES-256-GCM
 * Based on module_26600.c template
 *
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

 #include "common.h"
 #include "types.h"
 #include "modules.h"
 #include "bitops.h"
 #include "convert.h"
 #include "shared.h"
 #include "memory.h"
 
 // --- module parameters ---
 static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
 static const u32   DGST_POS0      = 0;
 static const u32   DGST_POS1      = 1;
 static const u32   DGST_POS2      = 2;
 static const u32   DGST_POS3      = 3;
 static const u32   DGST_SIZE      = DGST_SIZE_4_4;
 static const u32   HASH_CATEGORY  = HASH_CATEGORY_GENERIC_KDF;
 static const char *HASH_NAME      = "ZFS PBKDF2-HMAC-SHA1 + AES-256-GCM";
 static const u64   KERN_TYPE      = 26666;
 static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
 static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE | OPTS_TYPE_PT_GENERATE_LE;
 static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
 static const char *ST_PASS        = "password123";
 static const char *ST_HASH        = "$zfs$350000*cc38eb75d61a1ae7*41959b311d9e84844661821c*ee96a312f27d6f7d90c6b92c2161684d*bb83d28b874348abce7fe123a2401abbd64d2c79df2397e3d7302081f2c56365";
 
 #define SIGNATURE_ZFS       "$zfs$"
 #define SALT_LEN            8
 #define IV_LEN              12
 #define TAG_LEN             16
 #define CT_LEN              32
 
 // --- esalt struct ---
 typedef struct zfs_esalt {
   u32 iterations;
   u8  salt_buf[SALT_LEN];
   u8  iv_buf[IV_LEN];
   u8  tag_buf[TAG_LEN];
   u8  ct_buf[CT_LEN];
 } zfs_esalt_t;
 
 // --- module function prototypes ---
 u32   module_attack_exec           (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
 u32   module_dgst_pos0             (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
 u32   module_dgst_pos1             (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
 u32   module_dgst_pos2             (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
 u32   module_dgst_pos3             (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
 u32   module_dgst_size             (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
 u32   module_hash_category         (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
 const char *module_hash_name        (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
 u64   module_kern_type             (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
 u32   module_opti_type             (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
 u64   module_opts_type             (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
 u32   module_salt_type             (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
 const char *module_st_hash          (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
 const char *module_st_pass          (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
 u64   module_esalt_size            (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
 u64   module_tmp_size              (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
 u32   module_pw_min                (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
 u32   module_pw_max                (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
 int   module_hash_decode           (const hashconfig_t *, void *, salt_t *, void *, void *, hashinfo_t *, const char *, const int);
 int   module_hash_encode           (const hashconfig_t *, const void *, const salt_t *, const void *, const void *, const hashinfo_t *, char *, const int);
 int   module_hash_init_selftest    (const hashconfig_t *, const user_options_t *, const user_options_extra_t *, void *);
 char *module_jit_build_options     (const hashconfig_t *, const user_options_t *, const user_options_extra_t *, const hashes_t *, const hc_device_param_t *);
 int   module_benchmark_esalt       (const hashconfig_t *, const user_options_t *, const user_options_extra_t *, const salt_t *);
 int   module_benchmark_hook_salt   (const hashconfig_t *, const user_options_t *, const user_options_extra_t *, const salt_t *);
 int   module_mask_ms_count         (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
 int   module_mask_cs_count         (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
 int   module_build_plain_postprocess (const hashconfig_t *, const user_options_t *, const user_options_extra_t *);
 int   module_hash_encode_potfile   (const hashconfig_t *, const void *, const salt_t *, const void *, const void *, const hashinfo_t *, char *, const int);
 void  module_init                  (module_ctx_t *);
 
 // --- module constants implementation ---
 u32 module_attack_exec    (const hashconfig_t *hc, const user_options_t *uo, const user_options_extra_t *ue) { return ATTACK_EXEC; }
 u32 module_dgst_pos0      (const hashconfig_t *hc, const user_options_t *uo, const user_options_extra_t *ue) { return DGST_POS0; }
 u32 module_dgst_pos1      (const hashconfig_t *hc, const user_options_t *uo, const user_options_extra_t *ue) { return DGST_POS1; }
 u32 module_dgst_pos2      (const hashconfig_t *hc, const user_options_t *uo, const user_options_extra_t *ue) { return DGST_POS2; }
 u32 module_dgst_pos3      (const hashconfig_t *hc, const user_options_t *uo, const user_options_extra_t *ue) { return DGST_POS3; }
 u32 module_dgst_size      (const hashconfig_t *hc, const user_options_t *uo, const user_options_extra_t *ue) { return DGST_SIZE; }
 u32 module_hash_category  (const hashconfig_t *hc, const user_options_t *uo, const user_options_extra_t *ue) { return HASH_CATEGORY; }
 const char *module_hash_name(const hashconfig_t *hc, const user_options_t *uo, const user_options_extra_t *ue) { return HASH_NAME; }
 u64 module_kern_type      (const hashconfig_t *hc, const user_options_t *uo, const user_options_extra_t *ue) { return KERN_TYPE; }
 u32 module_opti_type      (const hashconfig_t *hc, const user_options_t *uo, const user_options_extra_t *ue) { return OPTI_TYPE; }
 u64 module_opts_type      (const hashconfig_t *hc, const user_options_t *uo, const user_options_extra_t *ue) { return OPTS_TYPE; }
 u32 module_salt_type      (const hashconfig_t *hc, const user_options_t *uo, const user_options_extra_t *ue) { return SALT_TYPE; }
 const char *module_st_hash  (const_hashconfig_t *hc, const user_options_t *uo, const user_options_extra_t *ue) { return ST_HASH; }
 const char *module_st_pass  (const_hashconfig_t *hc, const user_options_t *uo, const user_options_extra_t *ue) { return ST_PASS; }
 
 // --- helper functions ---
 int module_hash_init_selftest(const hashconfig_t *hc, const user_options_t *uo, const user_options_extra_t *ue, void *esalt_buf)
 {
   return module_hash_decode(hc, NULL, &(salt_t){0}, esalt_buf, NULL, NULL, ST_HASH, strlen(ST_HASH));
 }
 
 char *module_jit_build_options(const hashconfig_t *hc, const user_options_t *uo, const user_options_extra_t *ue, const hashes_t *hashes, const hc_device_param_t *dp)
 {
   char *jit_opts = NULL;
   if (dp->opencl_platform_vendor_id == VENDOR_ID_APPLE) return NULL;
   if (dp->opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP ||
       (dp->opencl_device_vendor_id == VENDOR_ID_AMD && dp->has_vperm))
   {
     hc_asprintf(&jit_opts, "-D _unroll");
   }
   return jit_opts;
 }
 
 int module_benchmark_esalt(const hashconfig_t *hc, const user_options_t *uo, const user_options_extra_t *ue, const salt_t *salt) { return BENCHMARK_ENONE; }
 int module_benchmark_hook_salt(const hashconfig_t *hc, const user_options_t *uo, const user_options_extra_t *ue, const salt_t *salt) { return BENCHMARK_HOOK_SALT_TO_GPU; }
 int module_mask_ms_count(const hashconfig_t *hc, const user_options_t *uo, const user_options_extra_t *ue) { return MASK_MS_SIX; }
 int module_mask_cs_count(const hashconfig_t *hc, const user_options_t *uo, const user_options_extra_t *ue) { return MASK_CS_ALL; }
 int module_build_plain_postprocess(const hashconfig_t *hc, const user_options_t *uo, const user_options_extra_t *ue) { return BUILD_PLAIN_POSTPROCESS_DISABLE; }
 int module_hash_encode_potfile(const hashconfig_t *hc, const void *d, const salt_t *salt, const void *esalt, const void *hsalt, const hashinfo_t *hi, char *line_buf, const int line_size) { return snprintf(line_buf, line_size, "%s", ST_HASH); }
 
 // --- core decode & encode ---
 int module_hash_decode(const hashconfig_t *hc, void *digest_buf, salt_t *salt, void *esalt_buf, void *hs, hashinfo_t *hi, const char *line_buf, const int line_len)
 {
   hc_token_t token = { 0 };
   token.token_cnt    = 6;
   token.signatures_cnt    = 1;
   token.signatures_buf[0] = SIGNATURE_ZFS;
 
   token.len[0]     = strlen(SIGNATURE_ZFS);
   token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_SIGNATURE;
   token.sep[1]     = '*'; token.len_min[1] = 1; token.len_max[1] = 10; token.attr[1] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;
   token.sep[2]     = '*'; token.len[2] = SALT_LEN*2; token.attr[2] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;
   token.sep[3]     = '*'; token.len[3] = IV_LEN*2;  token.attr[3] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;
   token.sep[4]     = '*'; token.len[4] = TAG_LEN*2; token.attr[4] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;
   token.sep[5]     = '*'; token.len[5] = CT_LEN*2;  token.attr[5] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;
 
   int rc = input_tokenizer((u8 *) line_buf, line_len, &token);
   if (rc != PARSER_OK) return rc;
 
   zfs_esalt_t *z = (zfs_esalt_t *) esalt_buf;
   const char *p;
 
   // iterations
   p = token.buf[1]; z->iterations = (u32) strtoul(p, NULL, 10); salt->salt_iter = z->iterations;
 
   // salt
   p = token.buf[2]; hex_to_bin(p, z->salt_buf, SALT_LEN); memcpy(salt->salt_buf, z->salt_buf, SALT_LEN); salt->salt_len = SALT_LEN;
 
   // iv
   p = token.buf[3]; hex_to_bin(p, z->iv_buf, IV_LEN);
 
   // tag
   p = token.buf[4]; hex_to_bin(p, z->tag_buf, TAG_LEN);
 
   // ct
   p = token.buf[5]; hex_to_bin(p, z->ct_buf, CT_LEN);
 
   return PARSER_OK;
 }
 
 int module_hash_encode(const hashconfig_t *hc, const void *d, const salt_t *salt, const void *esalt_buf, const void *hs, const hashinfo_t *hi, char *line_buf, const int line_size)
 {
   // minimal: not used
   return 0;
 }
 
 void module_init(module_ctx_t *module_ctx)
 {
   module_ctx->module_interface_version       = MODULE_INTERFACE_VERSION_CURRENT;
   module_ctx->module_attack_exec             = module_attack_exec;
   module_ctx->module_dgst_pos0               = module_dgst_pos0;
   module_ctx->module_dgst_pos1               = module_dgst_pos1;
   module_ctx->module_dgst_pos2               = module_dgst_pos2;
   module_ctx->module_dgst_pos3               = module_dgst_pos3;
   module_ctx->module_dgst_size               = module_dgst_size;
   module_ctx->module_hash_category           = module_hash_category;
   module_ctx->module_hash_name               = module_hash_name;
   module_ctx->module_kern_type               = module_kern_type;
   module_ctx->module_opti_type               = module_opti_type;
   module_ctx->module_opts_type               = module_opts_type;
   module_ctx->module_salt_type               = module_salt_type;
   module_ctx->module_st_hash                 = module_st_hash;
   module_ctx->module_st_pass                 = module_st_pass;
   module_ctx->module_esalt_size              = module_esalt_size;
   module_ctx->module_tmp_size                = module_tmp_size;
   module_ctx->module_pw_min                  = module_pw_min;
   module_ctx->module_pw_max                  = module_pw_max;
   module_ctx->module_hash_decode             = module_hash_decode;
   module_ctx->module_hash_encode             = module_hash_encode;
   module_ctx->module_hash_init_selftest      = module_hash_init_selftest;
   module_ctx->module_jit_build_options       = module_jit_build_options;
   module_ctx->module_benchmark_esalt         = module_benchmark_esalt;
   module_ctx->module_benchmark_hook_salt     = module_benchmark_hook_salt;
   module_ctx->module_mask_ms_count           = module_mask_ms_count;
   module_ctx->module_mask_cs_count           = module_mask_cs_count;
   module_ctx->module_build_plain_postprocess = module_build_plain_postprocess;
   module_ctx->module_hash_encode_potfile     = module_hash_encode_potfile;
 }
 