#include "mbedtls/aes.h"
#include "mbedtls_src.h"
#include <cstdlib> // 对于 malloc, free
#include <cstring> // 对于 memcpy, memset
#include <map>
#include <iostream>
#include <string>

static int constant_time_memcmp(const void *av, const void *bv, size_t n)
{
    const uint8_t *a = (const uint8_t *)av;
    const uint8_t *b = (const uint8_t *)bv;
    uint8_t result = 0;
    size_t i;

    for (i = 0; i < n; i++)
    {
        result |= *a ^ *b;
        a++;
        b++;
    }

    return (int)result;
}

void mbedtls_AES_ecb_encrypt_blks(block *blks, unsigned nblks, mbedtls_aes_context *ctx)
{
    for (unsigned i = 0; i < nblks; ++i)
    {
        mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, (const unsigned char *)&blks[i], (unsigned char *)&blks[i]);
    }
}

void mbedtls_AES_ecb_decrypt_blks(block *blks, unsigned nblks, mbedtls_aes_context *ctx)
{
    for (unsigned i = 0; i < nblks; ++i)
    {
        mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_DECRYPT, (const unsigned char *)&blks[i], (unsigned char *)&blks[i]);
    }
}

void mbedtls_AES_encrypt(const unsigned char *in, unsigned char *out, mbedtls_aes_context *key)
{
    mbedtls_aes_crypt_ecb(key, MBEDTLS_AES_ENCRYPT, in, out);
}

void mbedtls_AES_decrypt(const unsigned char *in, unsigned char *out, mbedtls_aes_context *key)
{
    mbedtls_aes_crypt_ecb(key, MBEDTLS_AES_DECRYPT, in, out);
}

static inline block xor_block(block x, block y)
{
    x.l ^= y.l;
    x.r ^= y.r;
    return x;
}

static inline block swap_if_le(block b)
{
    const union
    {
        unsigned x;
        unsigned char endian;
    } little = {1};
    if (little.endian)
    {
        block r;
        r.l = bswap64(b.l);
        r.r = bswap64(b.r);
        return r;
    }
    else
        return b;
}

static inline block double_block(block b)
{
    uint64_t t = (uint64_t)((int64_t)b.l >> 63);
    b.l = (b.l + b.l) ^ (b.r >> 63);
    b.r = (b.r + b.r) ^ (t & 135);
    return b;
}

block gen_offset(uint64_t KtopStr[3], unsigned bot)
{
    block rval;
    if (bot != 0)
    {
        rval.l = (KtopStr[0] << bot) | (KtopStr[1] >> (64 - bot));
        rval.r = (KtopStr[1] << bot) | (KtopStr[2] >> (64 - bot));
    }
    else
    {
        rval.l = KtopStr[0];
        rval.r = KtopStr[1];
    }
    return swap_if_le(rval);
}

/*-------------------------------------------------AES-------------------------------------------------*/
/*-----------------------------------------------------------------------------------------------------*/

e_ctx *e_allocate(void *misc)
{
    void *p;
    (void)misc; /* misc unused in this implementation */
    p = malloc(sizeof(e_ctx));
    return (e_ctx *)p;
}

int e_init(e_ctx *ctx, const void *key, int key_len)
{
    /* Initialize encryption key using mbed TLS */
    return mbedtls_aes_setkey_enc(&ctx->aes, (unsigned char *)key, key_len * 8);
}

void aes_ctr32_encrypt_blocks(const unsigned char *in, unsigned char *out, size_t blocks, e_ctx *ctx, const unsigned char *ivec)
{
    unsigned char nonce_counter[16];
    memcpy(nonce_counter, ivec, 16); // 使用ivec作为nonce_counter的值
    size_t length = blocks * 16;     // 每个块16字节

    // 使用mbedTLS AES CTR进行加密
    unsigned char stream_block[16];
    size_t nc_off = 0;
    mbedtls_aes_crypt_ctr(&ctx->aes, length, &nc_off, nonce_counter, stream_block, in, out);
}

void aes_encrypt(const unsigned char *in, unsigned char *out, mbedtls_aes_context *ctx)
{
    mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, in, out);
}

int fencrypt1(e_ctx *restrict ctx, const void *restrict nonce, const void *pt, int pt_len, void *ct)
{
    union
    {
        unsigned char u8[16];
        uint32_t u32[4];
        block bl;
    } ctr;

    if (pt_len <= 16)
    {
        ctr.bl = zero_block();
        memcpy(ctr.u8, (char *)pt, pt_len);
        aes_ctr32_encrypt_blocks(ctr.u8, (unsigned char *)ct, 1, ctx, (const unsigned char *)nonce);
    }
    else
    {
        unsigned char *tmp = (unsigned char *)malloc(pt_len); // 分配临时缓冲区
        aes_ctr32_encrypt_blocks((const unsigned char *)pt, tmp, pt_len / 16, ctx, (const unsigned char *)nonce);
        memcpy(ct, tmp, 16);
        free(tmp); // 释放临时缓冲区
    }

    return (int)pt_len;
}

void e_free(e_ctx *ctx)
{
    free(ctx);
}

int e_clear(e_ctx *ctx) /* Zero ae_ctx and undo initialization          */
{
    memset(ctx, 0, sizeof(e_ctx));
    return 1;
}
/*-------------------------------------------------AE-------------------------------------------------*/
/*----------------------------------------------------------------------------------------------------*/

int ae_init(ae_ctx *ctx, const void *key, int key_len)
{
    unsigned i;
    block tmp_blk;
    // mbedtls_aes_context aes_ctx;

    key_len = 16;
    // 初始化Mbed TLS的AES加密上下文并设置密钥
    mbedtls_aes_setkey_enc(&ctx->encrypt_key, (unsigned char *)key, key_len * 8);
    mbedtls_aes_setkey_enc(&ctx->decrypt_key, (unsigned char *)key, key_len * 8);
    // 将Mbed TLS的AES上下文存储在自定义结构中

    // 零化需要零化的东西
    ctx->cached_Top = ctx->ad_checksum = zero_block();
    ctx->ad_blocks_processed = 0;

    // 计算与密钥相关的值
    mbedtls_AES_encrypt((unsigned char *)&ctx->cached_Top,
                        (unsigned char *)&ctx->Lstar, &ctx->encrypt_key);
    tmp_blk = swap_if_le(ctx->Lstar);
    tmp_blk = double_block(tmp_blk);
    ctx->Ldollar = swap_if_le(tmp_blk);
    tmp_blk = double_block(tmp_blk);
    ctx->L[0] = swap_if_le(tmp_blk);
    for (i = 1; i < L_TABLE_SZ; i++)
    {
        tmp_blk = double_block(tmp_blk);
        ctx->L[i] = swap_if_le(tmp_blk);
    }
    return AE_SUCCESS;
}

int ae_encrypt(ae_ctx *ctx, const void *nonce, const void *pt, int pt_len, void *ct, void *tag)
{
    const union
    {
        unsigned x;
        unsigned char endian;
    } little = {1};
    union
    {
        uint32_t u32[4];
        uint8_t u8[16];
        block bl;
    } tmp;
    block offset, checksum;
    unsigned i, k, idx;
    block *ctp = (block *)ct;
    const block *ptp = (block *)pt;

    // 初始化mbedtls_aes_context
    // mbedtls_aes_setkey_enc(ctx, &cctx->encrypt_key, AES_KEY_SIZE * 8); // 假设AES_KEY_SIZE是密钥长度

    /* When nonce is non-null we know that this is the start of a new message.
     * If so, update cached AES if needed and initialize offsets/checksums.
     */
    if (nonce)
    { /* Indicates start of new message */

        /* Replace cached nonce Top if needed */
        tmp.bl = zero_block();
        tmp.u32[0] = (little.endian ? 0x01000000 : 0x00000001);
        /*tmp.u32[1] = ((uint32_t *)nonce)[0];
        tmp.u32[2] = ((uint32_t *)nonce)[1];*/
        tmp.u32[3] = *((uint32_t *)nonce);
        idx = (unsigned)(tmp.u8[15] & 0x3f); /* Get low 6 bits of nonce  */
        tmp.u8[15] = tmp.u8[15] & 0xc0;      /* Zero low 6 bits of nonce */
        if (unequal_blocks(tmp.bl, ctx->cached_Top))
        {                             /* Cached?       */
            ctx->cached_Top = tmp.bl; /* Update cache, KtopStr    */
            // AES_encrypt(tmp.u8, (unsigned char *)&ctx->KtopStr, &ctx->encrypt_key);
            mbedtls_AES_encrypt(tmp.u8, (unsigned char *)&ctx->KtopStr, &ctx->encrypt_key);
            if (little.endian)
            { /* Make Register Correct    */
                ctx->KtopStr[0] = bswap64(ctx->KtopStr[0]);
                ctx->KtopStr[1] = bswap64(ctx->KtopStr[1]);
            }
            ctx->KtopStr[2] = ctx->KtopStr[0] ^
                              (ctx->KtopStr[0] << 8) ^ (ctx->KtopStr[1] >> 56);
        }

        /* Initialize offset and checksum */
        ctx->offset = gen_offset(ctx->KtopStr, idx);
        ctx->ad_offset = ctx->checksum = zero_block();
        ctx->ad_blocks_processed = ctx->blocks_processed = 0;
        ctx->ad_checksum = zero_block();
        // block_num = 0;
    }

    /* Encrypt plaintext data BPI blocks at a time.
     */
    offset = ctx->offset;
    checksum = ctx->checksum;
    i = pt_len / (BPI * 16);
    if (i)
    {
        block oa[BPI];
        unsigned block_num = ctx->blocks_processed;
        oa[BPI - 1] = offset;
        do
        {
            block ta[BPI];
            block_num += BPI;
            oa[0] = xor_block(oa[BPI - 1], ctx->L[0]);
            ta[0] = xor_block(oa[0], ptp[0]);
            checksum = xor_block(checksum, ptp[0]);
            oa[1] = xor_block(oa[0], ctx->L[1]);
            ta[1] = xor_block(oa[1], ptp[1]);
            checksum = xor_block(checksum, ptp[1]);
            oa[2] = xor_block(oa[1], ctx->L[0]);
            ta[2] = xor_block(oa[2], ptp[2]);
            checksum = xor_block(checksum, ptp[2]);
#if BPI == 4
            oa[3] = xor_block(oa[2], getL(ctx, ntz(block_num)));
            ta[3] = xor_block(oa[3], ptp[3]);
            checksum = xor_block(checksum, ptp[3]);
#elif BPI == 8
            oa[3] = xor_block(oa[2], ctx->L[2]);
            ta[3] = xor_block(oa[3], ptp[3]);
            checksum = xor_block(checksum, ptp[3]);
            oa[4] = xor_block(oa[1], ctx->L[2]);
            ta[4] = xor_block(oa[4], ptp[4]);
            checksum = xor_block(checksum, ptp[4]);
            oa[5] = xor_block(oa[0], ctx->L[2]);
            ta[5] = xor_block(oa[5], ptp[5]);
            checksum = xor_block(checksum, ptp[5]);
            oa[6] = xor_block(oa[7], ctx->L[2]);
            ta[6] = xor_block(oa[6], ptp[6]);
            checksum = xor_block(checksum, ptp[6]);
            oa[7] = xor_block(oa[6], getL(ctx, ntz(block_num)));
            ta[7] = xor_block(oa[7], ptp[7]);
            checksum = xor_block(checksum, ptp[7]);
#endif
            mbedtls_AES_ecb_encrypt_blks(ta, BPI, &ctx->encrypt_key);
            ctp[0] = xor_block(ta[0], oa[0]);
            ctp[1] = xor_block(ta[1], oa[1]);
            ctp[2] = xor_block(ta[2], oa[2]);
            ctp[3] = xor_block(ta[3], oa[3]);
#if (BPI == 8)
            ctp[4] = xor_block(ta[4], oa[4]);
            ctp[5] = xor_block(ta[5], oa[5]);
            ctp[6] = xor_block(ta[6], oa[6]);
            ctp[7] = xor_block(ta[7], oa[7]);
#endif
            ptp += BPI;
            ctp += BPI;
        } while (--i);
        ctx->offset = offset = oa[BPI - 1];
        ctx->blocks_processed = block_num;
        ctx->checksum = checksum;
    }

    // offset = oa[BPI-1];

    block ta[BPI + 1], oa[BPI];

    /* Process remaining plaintext and compute its tag contribution    */
    unsigned remaining = ((unsigned)pt_len) % (BPI * 16);
    // remaining = ((unsigned)pt_len) % (BPI*16);                              // remaining = 16
    k = 0;
    if (remaining)
    {
#if (BPI == 8)
        if (remaining >= 64)
        {
            oa[0] = xor_block(offset, ctx->L[0]);
            ta[0] = xor_block(oa[0], ptp[0]);
            checksum = xor_block(checksum, ptp[0]);
            oa[1] = xor_block(oa[0], ctx->L[1]);
            ta[1] = xor_block(oa[1], ptp[1]);
            checksum = xor_block(checksum, ptp[1]);
            oa[2] = xor_block(oa[1], ctx->L[0]);
            ta[2] = xor_block(oa[2], ptp[2]);
            checksum = xor_block(checksum, ptp[2]);
            offset = oa[3] = xor_block(oa[2], ctx->L[2]);
            ta[3] = xor_block(offset, ptp[3]);
            checksum = xor_block(checksum, ptp[3]);
            remaining -= 64;
            k = 4;
        }
#endif
        if (remaining >= 32)
        {
            oa[k] = xor_block(offset, ctx->L[0]);
            ta[k] = xor_block(oa[k], ptp[k]);
            checksum = xor_block(checksum, ptp[k]);
            offset = oa[k + 1] = xor_block(oa[k], ctx->L[1]);
            ta[k + 1] = xor_block(offset, ptp[k + 1]);
            checksum = xor_block(checksum, ptp[k + 1]);
            remaining -= 32;
            k += 2;
        }
        if (remaining >= 16)
        {
            offset = oa[k] = xor_block(offset, ctx->L[0]);
            ta[k] = xor_block(offset, ptp[k]);
            checksum = xor_block(checksum, ptp[k]);
            remaining -= 16;
            ++k;
        }
        if (remaining)
        {
            tmp.bl = zero_block();
            memcpy(tmp.u8, ptp + k, remaining);
            tmp.u8[remaining] = (unsigned char)0x80u;
            checksum = xor_block(checksum, tmp.bl);
            ta[k] = offset = xor_block(offset, ctx->Lstar);
            ++k;
        }
    }
    offset = xor_block(offset, ctx->Ldollar); /* Part of tag gen */
    ta[k] = xor_block(offset, checksum);      /* Part of tag gen */
    mbedtls_AES_ecb_encrypt_blks(ta, k + 1, &ctx->encrypt_key);
    // offset = xor_block(ta[k], ad_checksum);   /* Part of tag gen */
    offset = xor_block(ta[k], ctx->ad_checksum);
    if (remaining)
    {
        --k;
        tmp.bl = xor_block(tmp.bl, ta[k]);
        memcpy(ctp + k, tmp.u8, remaining);
    }
    switch (k)
    {
#if (BPI == 8)
    case 7:
        ctp[6] = xor_block(ta[6], oa[6]);
    case 6:
        ctp[5] = xor_block(ta[5], oa[5]);
    case 5:
        ctp[4] = xor_block(ta[4], oa[4]);
    case 4:
        ctp[3] = xor_block(ta[3], oa[3]);
#endif
    case 3:
        ctp[2] = xor_block(ta[2], oa[2]);
    case 2:
        ctp[1] = xor_block(ta[1], oa[1]);
    case 1:
        ctp[0] = xor_block(ta[0], oa[0]);
    }
    // tmp.bl = offset;
    /* Tag is placed at the correct location
     */

    if (tag)
    {
#if (OCB_TAG_LEN == 16)
        *(block *)tag = offset;
#elif (OCB_TAG_LEN > 0)
        memcpy((char *)tag, &offset, OCB_TAG_LEN);
#else
        memcpy((char *)tag, &offset, ctx->tag_len);
#endif
    }
    else
    {
#if (OCB_TAG_LEN > 0)
        memcpy((char *)ct + pt_len, &offset, OCB_TAG_LEN);
        pt_len += OCB_TAG_LEN;
#else
        memcpy((char *)ct + pt_len, &offset, ctx->tag_len);
        pt_len += ctx->tag_len;
#endif
    }

    return (int)pt_len;
}

int ae_decrypt(ae_ctx *ctx, const void *nonce, const void *ct, int ct_len, void *pt, const void *tag)
{
    const union
    {
        unsigned x;
        unsigned char endian;
    } little = {1};
    union
    {
        uint32_t u32[4];
        uint8_t u8[16];
        block bl;
    } tmp;
    block offset, checksum;
    unsigned idx, i, k;
    block *ptp = (block *)pt;
    const block *ctp = (block *)ct;

    if (nonce)
    { /* Indicates start of new message */

        /* Replace cached nonce Top if needed */
        tmp.bl = zero_block();
        tmp.u32[0] = (little.endian ? 0x01000000 : 0x00000001);
        /*tmp.u32[1] = ((uint32_t *)nonce)[0];
        tmp.u32[2] = ((uint32_t *)nonce)[1];*/
        tmp.u32[3] = *((uint32_t *)nonce);
        idx = (unsigned)(tmp.u8[15] & 0x3f); /* Get low 6 bits of nonce  */
        tmp.u8[15] = tmp.u8[15] & 0xc0;      /* Zero low 6 bits of nonce */
        if (unequal_blocks(tmp.bl, ctx->cached_Top))
        {                             /* Cached?       */
            ctx->cached_Top = tmp.bl; /* Update cache, KtopStr    */
            mbedtls_AES_encrypt(tmp.u8, (unsigned char *)&ctx->KtopStr, &ctx->encrypt_key);
            if (little.endian)
            { /* Make Register Correct    */
                ctx->KtopStr[0] = bswap64(ctx->KtopStr[0]);
                ctx->KtopStr[1] = bswap64(ctx->KtopStr[1]);
            }
            ctx->KtopStr[2] = ctx->KtopStr[0] ^
                              (ctx->KtopStr[0] << 8) ^ (ctx->KtopStr[1] >> 56);
        }

        /* Initialize offset and checksum */
        ctx->offset = gen_offset(ctx->KtopStr, idx);
        ctx->ad_offset = ctx->checksum = zero_block();
        ctx->ad_blocks_processed = ctx->blocks_processed = 0;
        ctx->ad_checksum = zero_block();
    }

    offset = ctx->offset;
    checksum = ctx->checksum;
    i = ct_len / (BPI * 16);
    if (i)
    {
        block oa[BPI];
        unsigned block_num = ctx->blocks_processed;
        oa[BPI - 1] = offset;
        do
        {
            block ta[BPI];
            block_num += BPI;
            oa[0] = xor_block(oa[BPI - 1], ctx->L[0]);
            ta[0] = xor_block(oa[0], ctp[0]);
            oa[1] = xor_block(oa[0], ctx->L[1]);
            ta[1] = xor_block(oa[1], ctp[1]);
            oa[2] = xor_block(oa[1], ctx->L[0]);
            ta[2] = xor_block(oa[2], ctp[2]);
#if BPI == 4
            oa[3] = xor_block(oa[2], getL(ctx, ntz(block_num)));
            ta[3] = xor_block(oa[3], ctp[3]);
#elif BPI == 8
            oa[3] = xor_block(oa[2], ctx->L[2]);
            ta[3] = xor_block(oa[3], ctp[3]);
            oa[4] = xor_block(oa[1], ctx->L[2]);
            ta[4] = xor_block(oa[4], ctp[4]);
            oa[5] = xor_block(oa[0], ctx->L[2]);
            ta[5] = xor_block(oa[5], ctp[5]);
            oa[6] = xor_block(oa[7], ctx->L[2]);
            ta[6] = xor_block(oa[6], ctp[6]);
            oa[7] = xor_block(oa[6], getL(ctx, ntz(block_num)));
            ta[7] = xor_block(oa[7], ctp[7]);
#endif
            mbedtls_AES_ecb_decrypt_blks(ta, BPI, &ctx->decrypt_key);
            ptp[0] = xor_block(ta[0], oa[0]);
            checksum = xor_block(checksum, ptp[0]);
            ptp[1] = xor_block(ta[1], oa[1]);
            checksum = xor_block(checksum, ptp[1]);
            ptp[2] = xor_block(ta[2], oa[2]);
            checksum = xor_block(checksum, ptp[2]);
            ptp[3] = xor_block(ta[3], oa[3]);
            checksum = xor_block(checksum, ptp[3]);
#if (BPI == 8)
            ptp[4] = xor_block(ta[4], oa[4]);
            checksum = xor_block(checksum, ptp[4]);
            ptp[5] = xor_block(ta[5], oa[5]);
            checksum = xor_block(checksum, ptp[5]);
            ptp[6] = xor_block(ta[6], oa[6]);
            checksum = xor_block(checksum, ptp[6]);
            ptp[7] = xor_block(ta[7], oa[7]);
            checksum = xor_block(checksum, ptp[7]);
#endif
            ptp += BPI;
            ctp += BPI;
        } while (--i);
        ctx->offset = offset = oa[BPI - 1];
        ctx->blocks_processed = block_num;
        ctx->checksum = checksum;
    }
    block ta[BPI + 1], oa[BPI];

    /* Process remaining plaintext and compute its tag contribution    */
    unsigned remaining = ((unsigned)ct_len) % (BPI * 16);
    k = 0; /* How many blocks in ta[] need ECBing */
    if (remaining)
    {
#if (BPI == 8)
        if (remaining >= 64)
        {
            oa[0] = xor_block(offset, ctx->L[0]);
            ta[0] = xor_block(oa[0], ctp[0]);
            oa[1] = xor_block(oa[0], ctx->L[1]);
            ta[1] = xor_block(oa[1], ctp[1]);
            oa[2] = xor_block(oa[1], ctx->L[0]);
            ta[2] = xor_block(oa[2], ctp[2]);
            offset = oa[3] = xor_block(oa[2], ctx->L[2]);
            ta[3] = xor_block(offset, ctp[3]);
            remaining -= 64;
            k = 4;
        }
#endif
        if (remaining >= 32)
        {
            oa[k] = xor_block(offset, ctx->L[0]);
            ta[k] = xor_block(oa[k], ctp[k]);
            offset = oa[k + 1] = xor_block(oa[k], ctx->L[1]);
            ta[k + 1] = xor_block(offset, ctp[k + 1]);
            remaining -= 32;
            k += 2;
        }
        if (remaining >= 16)
        {
            offset = oa[k] = xor_block(offset, ctx->L[0]);
            ta[k] = xor_block(offset, ctp[k]);
            remaining -= 16;
            ++k;
        }
        if (remaining)
        {
            block pad;
            offset = xor_block(offset, ctx->Lstar);
            mbedtls_AES_encrypt((unsigned char *)&offset, tmp.u8, &ctx->encrypt_key);
            pad = tmp.bl;
            memcpy(tmp.u8, ctp + k, remaining);
            tmp.bl = xor_block(tmp.bl, pad);
            tmp.u8[remaining] = (unsigned char)0x80u;
            memcpy(ptp + k, tmp.u8, remaining);
            checksum = xor_block(checksum, tmp.bl);
        }
    }
    mbedtls_AES_ecb_decrypt_blks(ta, k, &ctx->decrypt_key);
    switch (k)
    {
#if (BPI == 8)
    case 7:
        ptp[6] = xor_block(ta[6], oa[6]);
        checksum = xor_block(checksum, ptp[6]);
    case 6:
        ptp[5] = xor_block(ta[5], oa[5]);
        checksum = xor_block(checksum, ptp[5]);
    case 5:
        ptp[4] = xor_block(ta[4], oa[4]);
        checksum = xor_block(checksum, ptp[4]);
    case 4:
        ptp[3] = xor_block(ta[3], oa[3]);
        checksum = xor_block(checksum, ptp[3]);
#endif
    case 3:
        ptp[2] = xor_block(ta[2], oa[2]);
        checksum = xor_block(checksum, ptp[2]);
    case 2:
        ptp[1] = xor_block(ta[1], oa[1]);
        checksum = xor_block(checksum, ptp[1]);
    case 1:
        ptp[0] = xor_block(ta[0], oa[0]);
        checksum = xor_block(checksum, ptp[0]);
    }

    /* Calculate expected tag */
    offset = xor_block(offset, ctx->Ldollar);
    tmp.bl = xor_block(offset, checksum);
    mbedtls_AES_encrypt(tmp.u8, tmp.u8, &ctx->encrypt_key);
    tmp.bl = xor_block(tmp.bl, ctx->ad_checksum); /* Full tag */

    /* Compare with proposed tag, change ct_len if invalid */
    if ((OCB_TAG_LEN == 16) && tag)
    {
        if (unequal_blocks(tmp.bl, *(block *)tag))
            ct_len = AE_INVALID;
    }
    else
    {
#if (OCB_TAG_LEN > 0)
        int len = OCB_TAG_LEN;
#else
        int len = ctx->tag_len;
#endif
        if (tag)
        {
            if (constant_time_memcmp(tag, tmp.u8, len) != 0)
                ct_len = AE_INVALID;
        }
        else
        {
            if (constant_time_memcmp((char *)ct + ct_len, tmp.u8, len) != 0)
                ct_len = AE_INVALID;
        }
    }
    return ct_len;
}

ae_ctx *ae_allocate(void *misc)
{
    void *p;
    (void)misc; /* misc unused in this implementation */
    p = malloc(sizeof(ae_ctx));
    return (ae_ctx *)p;
}

void ae_free(ae_ctx *ctx)
{
    free(ctx);
}

/* ----------------------------------------------------------------------- */

int ae_clear(ae_ctx *ctx) /* Zero ae_ctx and undo initialization          */
{
    memset(ctx, 0, sizeof(ae_ctx));
    return AE_SUCCESS;
}

int ae_ctx_sizeof(void)
{
    return (int)sizeof(ae_ctx);
}

int encrypt_ctr(e_ctx *ctx, const void *restrict nonce, const void *pt, int pt_len, void *ct)
{
    union
    {
        unsigned char u8[16];
        uint32_t u32[4];
        block bl;
    } ctr;
    unsigned remaining;
    aes_ctr32_encrypt_blocks((const unsigned char *)pt, (unsigned char *)ct, pt_len / 16, ctx, (const unsigned char *)nonce);
    remaining = pt_len % 16;
    if (remaining)
    {
        ctr.bl = *(block *)nonce;
        ctr.u32[3] += pt_len / 16;
        aes_encrypt(ctr.u8, ctr.u8, &ctx->aes);
        ctr.bl = xor_block(ctr.bl, ((block *)pt)[pt_len / 16]);
        memcpy((block *)ct + (pt_len / 16), ctr.u8, remaining);
    }
    return (int)pt_len;
}

int decrypt_ctr(e_ctx *ctx, const void *nonce, const void *ct, int ct_len, void *pt)
{

    union
    {
        unsigned char u8[16];
        uint32_t u32[4];
        block bl;
    } ctr;
    unsigned remaining;
    if (ct_len >= 16)
    {
        // aes_ctr32_encrypt_blocks(ct,pt,ct_len/16,&ctx->aes,nonce);
        aes_ctr32_encrypt_blocks((const unsigned char *)ct, (unsigned char *)pt, ct_len / 16, ctx, (const unsigned char *)nonce);
    }
    remaining = ct_len % 16;
    if (remaining)
    {
        ctr.bl = *(block *)nonce;
        ctr.u32[3] += ct_len / 16;
        aes_encrypt(ctr.u8, ctr.u8, &ctx->aes);
        ctr.bl = xor_block(ctr.bl, ((block *)ct)[ct_len / 16]);
        memcpy((block *)pt + (ct_len / 16), ctr.u8, remaining);
    }
    return (int)ct_len;
}