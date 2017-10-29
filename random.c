/* random.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/random.h>

#include <wolfssl/wolfcrypt/error-crypt.h>

/* Use HASHDRGB with SHA256 */
#include <wolfssl/wolfcrypt/sha256.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #include <wolfcrypt/src/misc.c>
#endif

/* Start NIST DRBG code */

#define OUTPUT_BLOCK_LEN  (SHA256_DIGEST_SIZE)
#define MAX_REQUEST_LEN   (0x10000)
#define RESEED_INTERVAL   (1000000)
#define SECURITY_STRENGTH (256)
#define ENTROPY_SZ        (SECURITY_STRENGTH/8)
#define NONCE_SZ          (ENTROPY_SZ/2)
#define ENTROPY_NONCE_SZ  (ENTROPY_SZ+NONCE_SZ)

/* Internal return codes */
#define DRBG_SUCCESS      0
#define DRBG_ERROR        1
#define DRBG_FAILURE      2
#define DRBG_NEED_RESEED  3
#define DRBG_CONT_FAILURE 4

/* RNG health states */
#define DRBG_NOT_INIT     0
#define DRBG_OK           1
#define DRBG_FAILED       2
#define DRBG_CONT_FAILED  3


enum {
    drbgInitC     = 0,
    drbgReseed    = 1,
    drbgGenerateW = 2,
    drbgGenerateH = 3,
    drbgInitV
};

typedef struct DRBG {
    word32 reseedCtr;
    word32 lastBlock;
    byte V[DRBG_SEED_LEN];
    byte C[DRBG_SEED_LEN];
    byte   matchCount;
} DRBG;

/* Hash Derivation Function */
/* Returns: DRBG_SUCCESS or DRBG_FAILURE */
static int Hash_df(DRBG* drbg, byte* out, word32 outSz, byte type,
                                                  const byte* inA, word32 inASz,
                                                  const byte* inB, word32 inBSz)
{
    byte ctr;
    int i;
    int len;
    word32 bits = (outSz * 8); /* reverse byte order */
    Sha256 sha;
    byte digest[SHA256_DIGEST_SIZE];

    (void)drbg;
    #ifdef LITTLE_ENDIAN_ORDER
        bits = ByteReverseWord32(bits);
    #endif
    len = (outSz / OUTPUT_BLOCK_LEN)
        + ((outSz % OUTPUT_BLOCK_LEN) ? 1 : 0);

    for (i = 0, ctr = 1; i < len; i++, ctr++)
    {
        if (wc_InitSha256(&sha) != 0)
            return DRBG_FAILURE;

        if (wc_Sha256Update(&sha, &ctr, sizeof(ctr)) != 0)
            return DRBG_FAILURE;

        if (wc_Sha256Update(&sha, (byte*)&bits, sizeof(bits)) != 0)
            return DRBG_FAILURE;

        /* churning V is the only string that doesn't have the type added */
        if (type != drbgInitV)
            if (wc_Sha256Update(&sha, &type, sizeof(type)) != 0)
                return DRBG_FAILURE;

        if (wc_Sha256Update(&sha, inA, inASz) != 0)
            return DRBG_FAILURE;

        if (inB != NULL && inBSz > 0)
            if (wc_Sha256Update(&sha, inB, inBSz) != 0)
                return DRBG_FAILURE;

        if (wc_Sha256Final(&sha, digest) != 0)
            return DRBG_FAILURE;

        if (outSz > OUTPUT_BLOCK_LEN) {
            XMEMCPY(out, digest, OUTPUT_BLOCK_LEN);
            outSz -= OUTPUT_BLOCK_LEN;
            out += OUTPUT_BLOCK_LEN;
        }
        else {
            XMEMCPY(out, digest, outSz);
        }
    }
    ForceZero(digest, sizeof(digest));

    return DRBG_SUCCESS;
}


/* Returns: DRBG_SUCCESS or DRBG_FAILURE */
static int Hash_DRBG_Reseed(DRBG* drbg, const byte* entropy, word32 entropySz)
{
    byte seed[DRBG_SEED_LEN];

    if (Hash_df(drbg, seed, sizeof(seed), drbgReseed, drbg->V, sizeof(drbg->V),
                                          entropy, entropySz) != DRBG_SUCCESS) {
        return DRBG_FAILURE;
    }

    XMEMCPY(drbg->V, seed, sizeof(drbg->V));
    ForceZero(seed, sizeof(seed));

    if (Hash_df(drbg, drbg->C, sizeof(drbg->C), drbgInitC, drbg->V,
                                    sizeof(drbg->V), NULL, 0) != DRBG_SUCCESS) {
        return DRBG_FAILURE;
    }

    drbg->reseedCtr = 1;
    drbg->lastBlock = 0;
    drbg->matchCount = 0;
    return DRBG_SUCCESS;
}

static INLINE void array_add_one(byte* data, word32 dataSz)
{
    int i;

    for (i = dataSz - 1; i >= 0; i--)
    {
        data[i]++;
        if (data[i] != 0) break;
    }
}


/* Returns: DRBG_SUCCESS or DRBG_FAILURE */
static int Hash_gen(DRBG* drbg, byte* out, word32 outSz, const byte* V)
{
    byte data[DRBG_SEED_LEN];
    int i;
    int len;
    word32 checkBlock;
    Sha256 sha;
    byte digest[SHA256_DIGEST_SIZE];

    /* Special case: outSz is 0 and out is NULL. wc_Generate a block to save for
     * the continuous test. */

    if (outSz == 0) outSz = 1;

    len = (outSz / OUTPUT_BLOCK_LEN) + ((outSz % OUTPUT_BLOCK_LEN) ? 1 : 0);

    XMEMCPY(data, V, sizeof(data));
    for (i = 0; i < len; i++) {
        if (wc_InitSha256(&sha) != 0 ||
            wc_Sha256Update(&sha, data, sizeof(data)) != 0 ||
            wc_Sha256Final(&sha, digest) != 0) {

            return DRBG_FAILURE;
        }

        XMEMCPY(&checkBlock, digest, sizeof(word32));
        if (drbg->reseedCtr > 1 && checkBlock == drbg->lastBlock) {
            if (drbg->matchCount == 1) {
                return DRBG_CONT_FAILURE;
            }
            else {
                if (i == len) {
                    len++;
                }
                drbg->matchCount = 1;
            }
        }
        else {
            drbg->matchCount = 0;
            drbg->lastBlock = checkBlock;
        }

        if (outSz >= OUTPUT_BLOCK_LEN) {
            XMEMCPY(out, digest, OUTPUT_BLOCK_LEN);
            outSz -= OUTPUT_BLOCK_LEN;
            out += OUTPUT_BLOCK_LEN;
            array_add_one(data, DRBG_SEED_LEN);
        }
        else if (out != NULL && outSz != 0) {
            XMEMCPY(out, digest, outSz);
            outSz = 0;
        }
    }
    ForceZero(data, sizeof(data));

    return DRBG_SUCCESS;
}


static INLINE void array_add(byte* d, word32 dLen, const byte* s, word32 sLen)
{
    word16 carry = 0;

    if (dLen > 0 && sLen > 0 && dLen >= sLen) {
        int sIdx, dIdx;

        for (sIdx = sLen - 1, dIdx = dLen - 1; sIdx >= 0; dIdx--, sIdx--)
        {
            carry += d[dIdx] + s[sIdx];
            d[dIdx] = (byte)carry;
            carry >>= 8;
        }

        for (; carry != 0 && dIdx >= 0; dIdx--) {
            carry += d[dIdx];
            d[dIdx] = (byte)carry;
            carry >>= 8;
        }
    }
}


/* Returns: DRBG_SUCCESS, DRBG_NEED_RESEED, or DRBG_FAILURE */
static int Hash_DRBG_Generate(DRBG* drbg, byte* out, word32 outSz)
{
    int ret = DRBG_NEED_RESEED;
    Sha256 sha;
    byte digest[SHA256_DIGEST_SIZE];

    if (drbg->reseedCtr != RESEED_INTERVAL) {
        byte type = drbgGenerateH;
        word32 reseedCtr = drbg->reseedCtr;

        ret = Hash_gen(drbg, out, outSz, drbg->V);
        if (ret == DRBG_SUCCESS) {
            if (wc_InitSha256(&sha) != 0 ||
                wc_Sha256Update(&sha, &type, sizeof(type)) != 0 ||
                wc_Sha256Update(&sha, drbg->V, sizeof(drbg->V)) != 0 ||
                wc_Sha256Final(&sha, digest) != 0) {

                ret = DRBG_FAILURE;
            }
            else {
                array_add(drbg->V, sizeof(drbg->V), digest, sizeof(digest));
                array_add(drbg->V, sizeof(drbg->V), drbg->C, sizeof(drbg->C));
                #ifdef LITTLE_ENDIAN_ORDER
                    reseedCtr = ByteReverseWord32(reseedCtr);
                #endif
                array_add(drbg->V, sizeof(drbg->V),
                                          (byte*)&reseedCtr, sizeof(reseedCtr));
                ret = DRBG_SUCCESS;
            }
            drbg->reseedCtr++;
        }
    }
    ForceZero(digest, sizeof(digest));

    return ret;
}


/* Returns: DRBG_SUCCESS or DRBG_FAILURE */
static int Hash_DRBG_Instantiate(DRBG* drbg, const byte* seed, word32 seedSz,
                                             const byte* nonce, word32 nonceSz)
{
    int ret = DRBG_FAILURE;

    XMEMSET(drbg, 0, sizeof(DRBG));

    if (Hash_df(drbg, drbg->V, sizeof(drbg->V), drbgInitV, seed, seedSz,
                                              nonce, nonceSz) == DRBG_SUCCESS &&
        Hash_df(drbg, drbg->C, sizeof(drbg->C), drbgInitC, drbg->V,
                                    sizeof(drbg->V), NULL, 0) == DRBG_SUCCESS) {

        drbg->reseedCtr = 1;
        drbg->lastBlock = 0;
        drbg->matchCount = 0;
        ret = DRBG_SUCCESS;
    }

    return ret;
}


/* Returns: DRBG_SUCCESS or DRBG_FAILURE */
static int Hash_DRBG_Uninstantiate(DRBG* drbg)
{
    word32 i;
    int    compareSum = 0;
    byte*  compareDrbg = (byte*)drbg;

    ForceZero(drbg, sizeof(DRBG));

    for (i = 0; i < sizeof(DRBG); i++)
        compareSum |= compareDrbg[i] ^ 0;

    return (compareSum == 0) ? DRBG_SUCCESS : DRBG_FAILURE;
}

/* End NIST DRBG Code */


/* Get seed and key cipher */
int wc_InitRng(WC_RNG* rng)
{
    int ret = BAD_FUNC_ARG;

    if (rng != NULL) {
        byte entropy[ENTROPY_NONCE_SZ];

        rng->drbg =
                (struct DRBG*)XMALLOC(sizeof(DRBG), NULL, DYNAMIC_TYPE_RNG);
        if (rng->drbg == NULL) {
            ret = MEMORY_E;
        }
        /* This doesn't use a separate nonce. The entropy input will be
         * the default size plus the size of the nonce making the seed
         * size. */
        else if (wc_GenerateSeed(&rng->seed,
                                          entropy, ENTROPY_NONCE_SZ) == 0 &&
                 Hash_DRBG_Instantiate(rng->drbg,
                      entropy, ENTROPY_NONCE_SZ, NULL, 0) == DRBG_SUCCESS) {

            ret = Hash_DRBG_Generate(rng->drbg, NULL, 0);
        }
        else
            ret = DRBG_FAILURE;

        ForceZero(entropy, ENTROPY_NONCE_SZ);

        if (ret == DRBG_SUCCESS) {
            rng->status = DRBG_OK;
            ret = 0;
        }
        else if (ret == DRBG_CONT_FAILURE) {
            rng->status = DRBG_CONT_FAILED;
            ret = DRBG_CONT_FIPS_E;
        }
        else if (ret == DRBG_FAILURE) {
            rng->status = DRBG_FAILED;
            ret = RNG_FAILURE_E;
        }
        else {
            rng->status = DRBG_FAILED;
        }
    }

    return ret;
}


/* place a generated block in output */
int wc_RNG_GenerateBlock(WC_RNG* rng, byte* output, word32 sz)
{
    int ret;

    if (rng == NULL || output == NULL || sz > MAX_REQUEST_LEN)
        return BAD_FUNC_ARG;

    if (rng->status != DRBG_OK)
        return RNG_FAILURE_E;

    ret = Hash_DRBG_Generate(rng->drbg, output, sz);

    if (ret == DRBG_NEED_RESEED) {
        byte entropy[ENTROPY_SZ];

        if (wc_GenerateSeed(&rng->seed, entropy, ENTROPY_SZ) == 0 &&
            Hash_DRBG_Reseed(rng->drbg, entropy, ENTROPY_SZ)
                                                          == DRBG_SUCCESS) {

            ret = Hash_DRBG_Generate(rng->drbg, NULL, 0);
            if (ret == DRBG_SUCCESS)
                ret = Hash_DRBG_Generate(rng->drbg, output, sz);
        }
        else
            ret = DRBG_FAILURE;

        ForceZero(entropy, ENTROPY_SZ);
    }

    if (ret == DRBG_SUCCESS) {
        ret = 0;
    }
    else if (ret == DRBG_CONT_FAILURE) {
        ret = DRBG_CONT_FIPS_E;
        rng->status = DRBG_CONT_FAILED;
    }
    else {
        ret = RNG_FAILURE_E;
        rng->status = DRBG_FAILED;
    }

    return ret;
}


int wc_RNG_GenerateByte(WC_RNG* rng, byte* b)
{
    return wc_RNG_GenerateBlock(rng, b, 1);
}


int wc_FreeRng(WC_RNG* rng)
{
    int ret = BAD_FUNC_ARG;

    if (rng != NULL) {
        if (rng->drbg != NULL) {
            if (Hash_DRBG_Uninstantiate(rng->drbg) == DRBG_SUCCESS)
                ret = 0;
            else
                ret = RNG_FAILURE_E;

            XFREE(rng->drbg, NULL, DYNAMIC_TYPE_RNG);
            rng->drbg = NULL;
        }

        rng->status = DRBG_NOT_INIT;
    }

    return ret;
}

#include <stdint.h>

int WolfSSL_GenerateSeed(uint8_t *output, uint32_t sz);

int wc_GenerateSeed(OS_Seed* os, byte* output, word32 sz)
{
    return WolfSSL_GenerateSeed(output, sz);
}

