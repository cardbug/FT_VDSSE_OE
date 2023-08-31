#ifndef AE_CRYPTO_H
#define AE_CRYPTO_H

#include "mbedtls/aes.h"

#define BPI 8
#define L_TABLE_SZ 16
#define AES_KEY_SIZE 16
#define OCB_TAG_LEN 8

#define unequal_blocks(x, y) ((((x).l ^ (y).l) | ((x).r ^ (y).r)) != 0)

/* Return status codes: Negative return values indicate an error occurred.
 * For full explanations of error values, consult the implementation's
 * documentation.                                                          */
#define AE_SUCCESS (0)        /* Indicates successful completion of call  */
#define AE_INVALID (-1)       /* Indicates bad tag during decryption      */
#define AE_NOT_SUPPORTED (-2) /* Indicates unsupported option requested   */

/* Flags: When data can be processed "incrementally", these flags are used
 * to indicate whether the submitted data is the last or not.               */
#define AE_FINALIZE (1) /* This is the last of data                  */
#define AE_PENDING (0)  /* More data of is coming                    */

#define getL(_ctx, _tz) ((_ctx)->L[_tz])
#define restrict __restrict__
typedef struct
{
    mbedtls_aes_context aes; // mbed TLS AES context
} e_ctx;

typedef struct
{
    uint64_t l, r;
} block;

typedef struct
{
    block offset;        /* Memory correct               */
    block checksum;      /* Memory correct               */
    block Lstar;         /* Memory correct               */
    block Ldollar;       /* Memory correct               */
    block L[L_TABLE_SZ]; /* Memory correct               */
    block ad_checksum;   /* Memory correct               */
    block ad_offset;     /* Memory correct               */
    block cached_Top;    /* Memory correct               */
    uint64_t KtopStr[3]; /* Register correct, each item  */
    uint32_t ad_blocks_processed;
    uint32_t blocks_processed;
    mbedtls_aes_context decrypt_key;
    mbedtls_aes_context encrypt_key;
} ae_ctx;

#define ntz(x) __builtin_ctz((unsigned)(x)) // x末尾0的个数，__builtin_clz(x)：x前导0的个数。

#define bswap32(x)                                          \
    ((((x)&0xff000000u) >> 24) | (((x)&0x00ff0000u) >> 8) | \
     (((x)&0x0000ff00u) << 8) | (((x)&0x000000ffu) << 24))

static inline uint64_t bswap64(uint64_t x)
{
    union
    {
        uint64_t u64;
        uint32_t u32[2];
    } in, out;
    in.u64 = x;
    out.u32[0] = bswap32(in.u32[1]);
    out.u32[1] = bswap32(in.u32[0]);
    return out.u64;
}

static inline block zero_block(void)
{
    const block t = {0, 0};
    return t;
}

// typedef struct _ae_ctx ae_ctx;


void mbedtls_AES_ecb_encrypt_blks(block *blks, unsigned nblks, mbedtls_aes_context *ctx);
void mbedtls_AES_encrypt(const unsigned char *in, unsigned char *out, mbedtls_aes_context *key);
void mbedtls_AES_decrypt(const unsigned char *in, unsigned char *out, mbedtls_aes_context *key);
void aes_ctr32_encrypt_blocks(const unsigned char *in, unsigned char *out, size_t blocks, e_ctx *ctx, const unsigned char *ivec);
void aes_encrypt(const unsigned char *in, unsigned char *out, mbedtls_aes_context *ctx);


e_ctx *e_allocate(void *misc); /* Allocate ae_ctx, set optional ptr   */
int e_init(e_ctx *ctx, const void *key, int key_len);
int fencrypt1(e_ctx *restrict ctx, const void *restrict nonce, const void *pt, int pt_len, void *ct);
// int encrypt_ctr(e_ctx *ctx, const unsigned char *nonce, const unsigned char *pt, size_t pt_len, unsigned char *ct);
int encrypt_ctr(e_ctx *ctx, const void *restrict nonce, const void *pt, int pt_len, void *ct);
int decrypt_ctr(e_ctx *ctx, const void *nonce, const void *ct, int ct_len, void *pt);
void e_free(e_ctx *ctx); /* Deallocate ae_ctx struct            */
int e_clear(e_ctx *ctx); /* Undo initialization                 */

ae_ctx *ae_allocate(void *misc); /* Allocate ae_ctx, set optional ptr   */
int ae_init(ae_ctx *ctx, const void *key, int key_len);
/* --------------------------------------------------------------------------
 *
 * Initialize an ae_ctx context structure.
 *
 * Parameters:
 *  ctx       - Pointer to an ae_ctx structure to be initialized
 *  key       - Pointer to user-supplied key
 *  key_len   - Length of key supplied, in bytes
 *  nonce_len - Length of nonces to be used for this key, in bytes
 *  tag_len   - Length of tags to be produced for this key, in bytes
 *
 * Returns:
 *  AE_SUCCESS       - Success. Ctx ready for use.
 *  AE_NOT_SUPPORTED - An unsupported length was supplied. Ctx is untouched.
 *  Otherwise        - Error. Check implementation documentation for codes.
 *
 * ----------------------------------------------------------------------- */
int ae_encrypt(ae_ctx *ctx, const void *nonce, const void *pt, int pt_len, void *ct, void *tag);
/* --------------------------------------------------------------------------
 *
 * Encrypt plaintext; provide for authentication of ciphertext/associated data.
 *
 * Parameters:
 *  ctx    - Pointer to an ae_ctx structure initialized by ae_init.
 *  nonce  - Pointer to a nonce_len (defined in ae_init) byte nonce.
 *  pt     - Pointer to plaintext bytes to be encrypted.
 *  pt_len - number of bytes pointed to by pt.
 *  ad     - Pointer to associated data.
 *  ad_len - number of bytes pointed to by ad.
 *  ct     - Pointer to buffer to receive ciphertext encryption.
 *  tag    - Pointer to receive authentication tag; or NULL
 *           if tag is to be bundled into the ciphertext.
 *  final  - Non-zero if this call completes the plaintext being encrypted.
 *
 * If nonce!=NULL then a message is being initiated. If final!=0
 * then a message is being finalized. If final==0 or nonce==NULL
 * then the incremental interface is being used. If nonce!=NULL and
 * ad_len<0, then use same ad as last message.
 *
 * Returns:
 *  non-negative     - Number of bytes written to ct.
 *  AE_NOT_SUPPORTED - Usage mode unsupported (eg, incremental and/or sticky).
 *  Otherwise        - Error. Check implementation documentation for codes.
 *
 * ----------------------------------------------------------------------- */
int ae_decrypt(ae_ctx *ctx, const void *nonce, const void *ct, int ct_len, void *pt, const void *tag);
/* --------------------------------------------------------------------------
 *
 * Decrypt ciphertext; provide authenticity of plaintext and associated data.
 *
 * Parameters:
 *  ctx    - Pointer to an ae_ctx structure initialized by ae_init.
 *  nonce  - Pointer to a nonce_len (defined in ae_init) byte nonce.
 *  ct     - Pointer to ciphertext bytes to be decrypted.
 *  ct_len - number of bytes pointed to by ct.
 *  ad     - Pointer to associated data.
 *  ad_len - number of bytes pointed to by ad.
 *  pt     - Pointer to buffer to receive plaintext decryption.
 *  tag    - Pointer to tag_len (defined in ae_init) bytes; or NULL
 *           if tag is bundled into the ciphertext.
 *  final  - Non-zero if this call completes the ciphertext being decrypted.
 *
 * If nonce!=NULL then "ct" points to the start of a ciphertext. If final!=0
 * then "in" points to the final piece of ciphertext. If final==0 or nonce==
 * NULL then the incremental interface is being used. If nonce!=NULL and
 * ad_len<0, then use same ad as last message.
 *
 * Returns:
 *  non-negative     - Number of bytes written to pt.
 *  AE_INVALID       - Authentication failure.
 *  AE_NOT_SUPPORTED - Usage mode unsupported (eg, incremental and/or sticky).
 *  Otherwise        - Error. Check implementation documentation for codes.
 *
 * NOTE !!! NOTE !!! -- The ciphertext should be assumed possibly inauthentic
 *                      until it has been completely written and it is
 *                      verified that this routine did not return AE_INVALID.
 *
 * ----------------------------------------------------------------------- */
void ae_free(ae_ctx *ctx); /* Deallocate ae_ctx struct            */
int ae_clear(ae_ctx *ctx); /* Undo initialization                 */
int ae_ctx_sizeof(void);   /* Return sizeof(ae_ctx)               */
/* ae_allocate() allocates an ae_ctx structure, but does not initialize it.
 * ae_free() deallocates an ae_ctx structure, but does not zeroize it.
 * ae_clear() zeroes sensitive values associated with an ae_ctx structure
 * and deallocates any auxiliary structures allocated during ae_init().
 * ae_ctx_sizeof() returns sizeof(ae_ctx), to aid in any static allocations.
 */

#endif // MBEDTLS_SRC_H
