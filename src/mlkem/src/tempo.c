#include "utils/includes.h"
#include "utils/common.h"
#include "crypto/crypto.h"
#include "sys.h"
#if defined(MLK_SYS_X86_64_AVX2) || defined(MLK_SYS_X86_64_AVX512)
#include <immintrin.h>
#endif
#include "tempo.h"
#include "symmetric.h"
#include "poly_k.h"
#include "indcpa.h"
#include "kem.h"

#ifdef MLK_CONFIG_TEMPO_FLS185
#define FLS_ITER 185
#define FLS_XOF_BLOCKS 4
#else
#define FLS_ITER 280
#define FLS_XOF_BLOCKS 5
#endif

// https://github.com/afonsoarriaga/ProjectTempo
#define lt_1mask_16(x, y) (uint16_t)((((int16_t)x) - ((int16_t)y)) >> 15)         // 0xffffffff if  x < y, 0x00000000 otherwise
#define diff_1mask_16(x, y) (uint16_t)((0 - ((int16_t)((x ^ y) & 0x7fff))) >> 15) // 0xffffffff if x != y, 0x00000000 otherwise
#define eq_1mask_16(x, y) (uint16_t)(~diff_1mask_16(x, y))                        // 0xffffffff if x == y, 0x00000000 otherwise

#define diff_1mask_32(x, y) (uint32_t)((0 - ((int32_t)((x ^ y) & 0x7fffffff))) >> 31)
#define eq_1mask_32(x, y) (uint32_t)(~diff_1mask_32(x, y))

#define h_fls MLK_ADD_PARAM_SET(h_fls)
static int h_fls(
    mlk_polyvec *v,
    const uint8_t *seed,
    int transposed,
    int n)
{
    uint8_t buf[FLS_XOF_BLOCKS * SHAKE128_RATE];
    uint8_t ext_seed[MLKEM_SYMBYTES + 2];
    memcpy(ext_seed, seed, MLKEM_SYMBYTES);
    int ret = 1;
    for (uint8_t y = 0; y < n; y++)
    {
        ext_seed[MLKEM_SYMBYTES + !transposed] = y;
        for (uint8_t x = 0; x < MLKEM_K; x++)
        {
            ext_seed[MLKEM_SYMBYTES + transposed] = x;
            mlk_xof_ctx ctx;
            mlk_xof_absorb(&ctx, ext_seed, sizeof(ext_seed));
            mlk_xof_squeezeblocks(buf, FLS_XOF_BLOCKS, &ctx);
            uint16_t ctr = 0;
            for (int i = 0, j = 0; i < FLS_ITER; i++, j += 3)
            {
                uint16_t d[2];
                d[0] = ((buf[j + 0] >> 0) |
                        ((uint16_t)buf[j + 1] << 8)) &
                       0xFFF;
                d[1] = ((buf[j + 1] >> 4) |
                        ((uint16_t)buf[j + 2] << 4)) &
                       0xFFF;
                for (int k = 0; k < 2; k++)
                {
                    uint16_t d_ok = lt_1mask_16(d[k], MLKEM_Q);
#if defined(MLK_SYS_X86_64_AVX512)
                    uint16_t d_k = d[k] & d_ok;
                    uint8_t *coeffs = (uint8_t *)v[y].vec[x].coeffs;
                    uint32_t vec = ctr >> 5;
                    uint32_t lane = 1 << (ctr & 31);
                    for (uint32_t m = 0; m < 8; m++, coeffs += 64)
                    {
                        uint32_t mask = eq_1mask_32(vec, m);
                        __m512i coeffs_avx = _mm512_load_si512(coeffs);
                        coeffs_avx = _mm512_mask_set1_epi16(
                            coeffs_avx,
                            lane & mask,
                            (int16_t)d_k);
                        _mm512_store_si512(coeffs, coeffs_avx);
                    }
#elif defined(MLK_SYS_X86_64_AVX2)
                    uint16_t d_k = d[k] & d_ok;
                    uint8_t *coeffs = (uint8_t *)v[y].vec[x].coeffs;
                    uint16_t vec = ctr >> 4;
                    __m256i lane_avx = _mm256_cmpeq_epi16(
                        _mm256_setr_epi16(
                            0, 1, 2, 3, 4, 5, 6, 7,
                            8, 9, 10, 11, 12, 13, 14, 15),
                        _mm256_set1_epi16(ctr & 15));
                    __m256i d_avx = _mm256_set1_epi16((int16_t)d_k);
                    d_avx = _mm256_and_si256(d_avx, lane_avx);
                    for (uint16_t m = 0; m < 16; m++, coeffs += 32)
                    {
                        uint16_t mask = eq_1mask_16(vec, m);
                        __m256i mask_avx = _mm256_set1_epi16((int16_t)mask);
                        __m256i d_mask_avx = _mm256_and_si256(d_avx, mask_avx);
                        __m256i coeffs_avx = _mm256_load_si256((const __m256i *)coeffs);
                        mask_avx = _mm256_and_si256(mask_avx, lane_avx);
                        coeffs_avx = _mm256_andnot_si256(mask_avx, coeffs_avx);
                        coeffs_avx = _mm256_or_si256(coeffs_avx, d_mask_avx);
                        _mm256_store_si256((__m256i *)coeffs, coeffs_avx);
                    }
#else
                    int16_t *coeffs = v[y].vec[x].coeffs;
                    for (uint16_t m = 0; m < MLKEM_N; m++)
                    {
                        uint16_t match = eq_1mask_16(m, ctr);
                        coeffs[m] = (int16_t)((~match & (uint16_t)coeffs[m]) |
                                              (match & d[k]));
                    }
#endif
                    ctr += d_ok & 1;
                }
            }
#ifdef MLK_CONFIG_TEMPO_FLS185
            ret &= (ctr >> 8);
#endif
            mlk_xof_release(&ctx);
        }
    }
    mlk_zeroize(buf, sizeof(buf));
    mlk_zeroize(ext_seed, sizeof(ext_seed));
    return ret;
}

#define h_1 MLK_ADD_PARAM_SET(h_1)
static int h_1(
    mlk_polyvec *r,
    const uint8_t *sid,
    const uint8_t *pwd,
    const uint8_t *seed,
    const uint8_t *r_seed)
{
    int ret = 0;
    const size_t inlen = TEMPO_LEN_SID +
                         TEMPO_LEN_PWD +
                         MLKEM_SYMBYTES +
                         TEMPO_3LAMBDA;
    uint8_t input[inlen];
    uint8_t output[MLKEM_SYMBYTES];
    size_t i = 0;
    memcpy(input, sid, TEMPO_LEN_SID);
    memcpy(input + (i += TEMPO_LEN_SID), pwd, TEMPO_LEN_PWD);
    memcpy(input + (i += TEMPO_LEN_PWD), seed, MLKEM_SYMBYTES);
    memcpy(input + (i += MLKEM_SYMBYTES), r_seed, TEMPO_3LAMBDA);
    const uint8_t *inptr = input;
    if (sha256_vector(1, &inptr, &inlen, output) != 0)
    {
        ret = MLK_ERR_DIGEST_FAIL;
        goto cleanup;
    }
    ret = h_fls(r, output, 0, 1);
cleanup:
    mlk_zeroize(input, inlen);
    mlk_zeroize(output, MLKEM_SYMBYTES);
    return ret;
}

#define h_2 MLK_ADD_PARAM_SET(h_2)
static int h_2(
    uint8_t *v_hash,
    const uint8_t *sid,
    const uint8_t *pwd,
    const uint8_t *seed,
    const uint8_t *v_buf)
{
    const size_t inlen = TEMPO_LEN_SID +
                         TEMPO_LEN_PWD +
                         MLKEM_SYMBYTES +
                         MLKEM_POLYVECBYTES;
    uint8_t input[inlen];
    size_t i = 0;
    memcpy(input, sid, TEMPO_LEN_SID);
    memcpy(input + (i += TEMPO_LEN_SID), pwd, TEMPO_LEN_PWD);
    memcpy(input + (i += TEMPO_LEN_PWD), seed, MLKEM_SYMBYTES);
    memcpy(input + (i += MLKEM_SYMBYTES), v_buf, MLKEM_POLYVECBYTES);
    mlk_shake256(v_hash, TEMPO_3LAMBDA, input, inlen);
    mlk_zeroize(input, inlen);
    return 0;
}

#define h_tag MLK_ADD_PARAM_SET(h_tag)
static int h_tag(
    uint8_t *tag,
    const uint8_t *ctr,
    const uint8_t *pk,
    const uint8_t *own_msg,
    const uint8_t *peer_msg,
    const uint8_t *ss,
    const uint8_t *sid,
    const uint8_t *pwd)
{
    const size_t inlen = 2 +
                         TEMPO_LEN_SID +
                         TEMPO_LEN_PWD +
                         MLKEM_INDCCA_LEN_PUBLIC_KEY +
                         TEMPO_LEN_MSG +
                         TEMPO_LEN_MSG +
                         MLKEM_SSBYTES;
    uint8_t input[inlen];
    size_t i = 0;
    memcpy(input, ctr, 2);
    memcpy(input + (i += 2), sid, TEMPO_LEN_SID);
    memcpy(input + (i += TEMPO_LEN_SID), pwd, TEMPO_LEN_PWD);
    memcpy(input + (i += TEMPO_LEN_PWD), pk, MLKEM_INDCCA_LEN_PUBLIC_KEY);
    memcpy(input + (i += MLKEM_INDCCA_LEN_PUBLIC_KEY), own_msg, TEMPO_LEN_MSG);
    memcpy(input + (i += TEMPO_LEN_MSG), peer_msg, TEMPO_LEN_MSG);
    memcpy(input + (i += TEMPO_LEN_MSG), ss, MLKEM_SSBYTES);
    mlk_shake256(tag, TEMPO_LEN_TAG, input, inlen);
    mlk_zeroize(input, inlen);
    return 0;
}

#define h_key MLK_ADD_PARAM_SET(h_key)
static int h_key(
    uint8_t *mk,
    const uint8_t *pk,
    const uint8_t *req,
    const uint8_t *res,
    const uint8_t *ss,
    const uint8_t *sid,
    const uint8_t *pwd)
{
    int ret = 0;
    const size_t inlen = TEMPO_LEN_SID +
                         TEMPO_LEN_PWD +
                         MLKEM_INDCCA_LEN_PUBLIC_KEY +
                         TEMPO_LEN_MSG +
                         TEMPO_LEN_MSG +
                         MLKEM_SSBYTES;
    uint8_t input[inlen];
    size_t i = 0;
    memcpy(input, sid, TEMPO_LEN_SID);
    memcpy(input + (i += TEMPO_LEN_SID), pwd, TEMPO_LEN_PWD);
    memcpy(input + (i += TEMPO_LEN_PWD), pk, MLKEM_INDCCA_LEN_PUBLIC_KEY);
    memcpy(input + (i += MLKEM_INDCCA_LEN_PUBLIC_KEY), req, TEMPO_LEN_MSG);
    memcpy(input + (i += TEMPO_LEN_MSG), res, TEMPO_LEN_MSG);
    memcpy(input + (i += TEMPO_LEN_MSG), ss, MLKEM_SSBYTES);
    const uint8_t *inptr = input;
    if (sha256_vector(1, &inptr, &inlen, mk) != 0)
    {
        ret = MLK_ERR_DIGEST_FAIL;
    }
    mlk_zeroize(input, inlen);
    return ret;
}

MLK_EXTERNAL_API
int mlk_tempo_keygen(
    uint8_t *req,
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t *sid,
    const uint8_t *pwd)
{
    int ret = 0;
    uint8_t *apk_u = req;
    uint8_t *apk_v = apk_u + TEMPO_3LAMBDA;
    uint8_t *apk_seed = apk_v + MLKEM_POLYVECBYTES;
    mlk_polyvec r;
    mlk_polyvec t;
    uint8_t poly[MLKEM_POLYVECBYTES];
    uint8_t r_seed[TEMPO_3LAMBDA];
    uint8_t v_hash[TEMPO_3LAMBDA];
    ret = mlk_kem_keypair(pk, sk);
    if (ret != 0)
    {
        goto cleanup;
    }
    memcpy(apk_seed, pk + MLKEM_POLYVECBYTES, MLKEM_SYMBYTES);
    memcpy(poly, pk, MLKEM_POLYVECBYTES);
    int fls_ret;
    do
    {
        if (mlk_randombytes(r_seed, TEMPO_3LAMBDA) != 0)
        {
            ret = MLK_ERR_RNG_FAIL;
            goto cleanup;
        }
        fls_ret = h_1(&r, sid, pwd, apk_seed, r_seed);
        if (fls_ret < 0)
        {
            ret = fls_ret;
            goto cleanup;
        }
    } while (fls_ret != 1);
    mlk_polyvec_frombytes(&t, poly);
    mlk_polyvec_add(&t, &r);
    mlk_polyvec_reduce(&t);
    mlk_polyvec_tobytes(req + TEMPO_3LAMBDA, &t);
    ret = h_2(v_hash, sid, pwd, apk_seed, apk_v);
    if (ret != 0)
    {
        goto cleanup;
    }
    for (int i = 0; i < TEMPO_3LAMBDA; i++)
    {
        apk_u[i] = v_hash[i] ^ r_seed[i];
    }
cleanup:
    mlk_zeroize(&r, sizeof(r));
    mlk_zeroize(&t, sizeof(t));
    mlk_zeroize(poly, sizeof(poly));
    mlk_zeroize(r_seed, sizeof(r_seed));
    mlk_zeroize(v_hash, sizeof(v_hash));
    return ret;
}

MLK_EXTERNAL_API
int mlk_tempo_encaps(
    uint8_t *res,
    uint8_t *pk,
    uint8_t *ss,
    const uint8_t *req,
    const uint8_t *sid,
    const uint8_t *pwd)
{
    int ret = 0;
    const uint8_t *apk_u = req;
    const uint8_t *apk_v = apk_u + TEMPO_3LAMBDA;
    const uint8_t *apk_seed = apk_v + MLKEM_POLYVECBYTES;
    mlk_polyvec r;
    mlk_polyvec v;
    uint8_t r_seed[TEMPO_3LAMBDA];
    uint8_t v_hash[TEMPO_3LAMBDA];
#ifdef MLK_CONFIG_TEMPO_FLS185
    mlk_polyvec rx;
    uint8_t rx_seed[MLKEM_SYMBYTES];
#endif
    ret = mlk_kem_check_pk(apk_v);
    if (ret != 0)
    {
        goto cleanup;
    }
    ret = h_2(v_hash, sid, pwd, apk_seed, apk_v);
    if (ret != 0)
    {
        goto cleanup;
    }
    for (int i = 0; i < TEMPO_3LAMBDA; i++)
    {
        r_seed[i] = v_hash[i] ^ apk_u[i];
    }
    mlk_polyvec_frombytes(&v, apk_v);
    int fls_ret = h_1(&r, sid, pwd, apk_seed, r_seed);
    if (fls_ret < 0)
    {
        ret = fls_ret;
        goto cleanup;
    }
#ifdef MLK_CONFIG_TEMPO_FLS185
    if (mlk_randombytes(rx_seed, MLKEM_SYMBYTES) != 0)
    {
        ret = MLK_ERR_RNG_FAIL;
        goto cleanup;
    }
    mlk_gen_vector(&rx, rx_seed, 0);
    mlk_polyvec_sub_mask(&v, &rx, &r, fls_ret);
#else
    mlk_polyvec_sub(&v, &r);
#endif
    mlk_polyvec_reduce(&v);
    mlk_polyvec_tobytes(pk, &v);
    memcpy(pk + MLKEM_POLYVECBYTES, apk_seed, MLKEM_SYMBYTES);
    mlk_zeroize(
        res + MLKEM_INDCCA_LEN_CIPHERTEXT,
        TEMPO_LEN_MSG - MLKEM_INDCCA_LEN_CIPHERTEXT);
    ret = mlk_kem_enc_valid_pk(res, ss, pk);
cleanup:
    mlk_zeroize(&r, sizeof(r));
    mlk_zeroize(&v, sizeof(v));
    mlk_zeroize(r_seed, TEMPO_3LAMBDA);
    mlk_zeroize(v_hash, TEMPO_3LAMBDA);
#ifdef MLK_CONFIG_TEMPO_FLS185
    mlk_zeroize(&rx, sizeof(rx));
    mlk_zeroize(rx_seed, MLKEM_SYMBYTES);
#endif
    return ret;
}

MLK_EXTERNAL_API
int mlk_tempo_decaps(
    uint8_t *ss,
    const uint8_t *sk,
    const uint8_t *res)
{
    return mlk_kem_dec(ss, res, sk);
}

MLK_EXTERNAL_API
int mlk_tempo_confirm(
    uint8_t *tag,
    const uint8_t *ctr,
    const uint8_t *pk,
    const uint8_t *sk,
    const uint8_t *req,
    const uint8_t *res,
    const uint8_t *ss,
    const uint8_t *sid,
    const uint8_t *pwd)
{
    if (sk == NULL)
    {
        return h_tag(tag, ctr, pk, res, req, ss, sid, pwd);
    }
    else
    {
        return h_tag(tag, ctr, pk, req, res, ss, sid, pwd);
    }
}

MLK_EXTERNAL_API
int mlk_tempo_verify(
    const uint8_t *peer_tag,
    const uint8_t *peer_ctr,
    const uint8_t *pk,
    const uint8_t *sk,
    const uint8_t *req,
    const uint8_t *res,
    const uint8_t *ss,
    const uint8_t *sid,
    const uint8_t *pwd)
{
    uint8_t t[TEMPO_LEN_TAG];
    int ret;
    if (sk == NULL)
    {
        ret = h_tag(t, peer_ctr, pk, req, res, ss, sid, pwd);
    }
    else
    {
        ret = h_tag(t, peer_ctr, pk, res, req, ss, sid, pwd);
    }
    if (ret == 0)
    {
        ret = mlk_ct_memcmp(t, peer_tag, TEMPO_LEN_TAG) == 0 ? 1 : 0;
    }
    mlk_zeroize(t, TEMPO_LEN_TAG);
    return ret;
}

MLK_EXTERNAL_API
int mlk_tempo_finish(
    uint8_t *mk,
    const uint8_t *pk,
    const uint8_t *req,
    const uint8_t *res,
    const uint8_t *ss,
    const uint8_t *sid,
    const uint8_t *pwd)
{
    return h_key(mk, pk, req, res, ss, sid, pwd);
}

#undef h_fls
#undef h_1
#undef h_2
#undef h_tag
#undef h_key
