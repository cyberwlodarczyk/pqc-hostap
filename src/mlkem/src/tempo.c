#include "tempo.h"
#include "symmetric.h"
#include "kem.h"

#define h_fls MLK_ADD_PARAM_SET(h_fls)
static void h_fls(
    mlk_polyvec *a,
    const uint8_t *seed)
{
    mlk_xof_ctx ctx;
    uint8_t buf[5 * SHAKE128_RATE];
    uint8_t ext_seed[MLKEM_SYMBYTES + 2];
    memcpy(ext_seed, seed, MLKEM_SYMBYTES);
    ext_seed[MLKEM_SYMBYTES + 1] = 0;
    for (uint8_t x = 0; x < MLKEM_K; x++)
    {
        ext_seed[MLKEM_SYMBYTES + 0] = x;
        mlk_xof_absorb(&ctx, ext_seed, sizeof(ext_seed));
        mlk_xof_squeezeblocks(buf, 5, &ctx);
        int ctr = 0;
        for (int i = 0, buf_i = 0; i <= 279; i++, buf_i += 3)
        {
            uint16_t d[2];
            int d_ok[2];
            d[0] = ((buf[buf_i + 0] >> 0) |
                    ((uint16_t)buf[buf_i + 1] << 8)) &
                   0xFFF;
            d[1] = ((buf[buf_i + 1] >> 4) |
                    ((uint16_t)buf[buf_i + 2] << 4)) &
                   0xFFF;
            d_ok[0] = (d[0] < MLKEM_Q);
            d_ok[1] = (d[1] < MLKEM_Q);
            for (int d_i = 0; d_i < 2; d_i++)
            {
                int flag = 0;
                for (int j = 0; j < MLKEM_N; j++)
                {
                    int match = (j == ctr);
                    int mask = match * d_ok[d_i];
                    int16_t *coeffs = a->vec[x].coeffs;
                    coeffs[j] = (int16_t)(coeffs[j] * (1 - mask) + d[d_i] * mask);
                    flag += mask;
                }
                ctr += flag;
            }
        }
    }
    mlk_xof_release(&ctx);
    mlk_zeroize(buf, sizeof(buf));
    mlk_zeroize(ext_seed, sizeof(ext_seed));
}

#define h_1 MLK_ADD_PARAM_SET(h_1)
static void h_1(
    mlk_polyvec *r,
    const uint8_t *sid,
    const uint8_t *pwd,
    const uint8_t *seed,
    const uint8_t *r_seed)
{
    const size_t inlen = TEMPO_LEN_SID +
                         TEMPO_LEN_PWD +
                         MLKEM_SYMBYTES +
                         TEMPO_3LAMBDA;
    const size_t outlen = MLKEM_SYMBYTES;
    uint8_t input[inlen];
    uint8_t output[outlen];
    size_t i = 0;
    memcpy(input, sid, TEMPO_LEN_SID);
    memcpy(input + (i += TEMPO_LEN_SID), pwd, TEMPO_LEN_PWD);
    memcpy(input + (i += TEMPO_LEN_PWD), seed, MLKEM_SYMBYTES);
    memcpy(input + (i += MLKEM_SYMBYTES), r_seed, TEMPO_3LAMBDA);
    mlk_shake256(output, outlen, input, inlen);
    h_fls(r, output);
    mlk_zeroize(input, inlen);
    mlk_zeroize(output, outlen);
}

#define h_2 MLK_ADD_PARAM_SET(h_2)
static void h_2(
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
}

#define h_confirm MLK_ADD_PARAM_SET(h_confirm)
static inline void h_confirm(
    uint8_t *tag_a,
    uint8_t *tag_b,
    uint8_t *shared_secret,
    const uint8_t *sid,
    const uint8_t *pwd,
    const uint8_t *public_key,
    const uint8_t *apk,
    const uint8_t *ciphertext,
    const uint8_t *emphemeral_key)
{
    const size_t inlen = TEMPO_LEN_SID +
                         TEMPO_LEN_PWD +
                         MLKEM_INDCCA_LEN_PUBLIC_KEY +
                         TEMPO_LEN_APK +
                         MLKEM_INDCCA_LEN_CIPHERTEXT +
                         MLKEM_SSBYTES;
    const size_t outlen = 2 * TEMPO_LEN_TAG + TEMPO_SSBYTES;
    uint8_t input[inlen];
    uint8_t output[outlen];
    size_t i = 0;
    memcpy(input, sid, TEMPO_LEN_SID);
    memcpy(input + (i += TEMPO_LEN_SID), pwd, TEMPO_LEN_PWD);
    memcpy(input + (i += TEMPO_LEN_PWD), public_key, MLKEM_INDCCA_LEN_PUBLIC_KEY);
    memcpy(input + (i += MLKEM_INDCCA_LEN_PUBLIC_KEY), apk, TEMPO_LEN_APK);
    memcpy(input + (i += TEMPO_LEN_APK), ciphertext, MLKEM_INDCCA_LEN_CIPHERTEXT);
    memcpy(input + (i += MLKEM_INDCCA_LEN_CIPHERTEXT), emphemeral_key, MLKEM_SSBYTES);
    mlk_shake256(output, outlen, input, inlen);
    memcpy(tag_a, output, TEMPO_LEN_TAG);
    memcpy(tag_b, output + TEMPO_LEN_TAG, TEMPO_LEN_TAG);
    memcpy(shared_secret, output + 2 * TEMPO_LEN_TAG, TEMPO_SSBYTES);
    mlk_zeroize(input, inlen);
    mlk_zeroize(output, outlen);
}

MLK_EXTERNAL_API
int mlk_tempo_keygen(
    uint8_t *public_key,
    uint8_t *secret_key,
    uint8_t *apk,
    const uint8_t *sid,
    const uint8_t *pwd)
{
    int ret = mlk_kem_keypair(public_key, secret_key) != 0;
    if (ret != 0)
    {
        return ret;
    }
    uint8_t poly[MLKEM_POLYVECBYTES];
    uint8_t *apk_u = apk;
    uint8_t *apk_v = apk_u + TEMPO_3LAMBDA;
    uint8_t *apk_seed = apk_v + MLKEM_POLYVECBYTES;
    memcpy(apk_seed, public_key + MLKEM_POLYVECBYTES, MLKEM_SYMBYTES);
    memcpy(poly, public_key, MLKEM_POLYVECBYTES);
    uint8_t r_seed[TEMPO_3LAMBDA];
    if (mlk_randombytes(r_seed, TEMPO_3LAMBDA) != 0)
    {
        ret = MLK_ERR_RNG_FAIL;
        goto cleanup;
    }
    mlk_polyvec r;
    h_1(&r, sid, pwd, apk_seed, r_seed);
    mlk_polyvec t;
    mlk_polyvec_frombytes(&t, poly);
    mlk_polyvec_add(&t, &r);
    mlk_polyvec_reduce(&t);
    mlk_polyvec_tobytes(apk + TEMPO_3LAMBDA, &t);
    uint8_t v_hash[TEMPO_3LAMBDA];
    h_2(v_hash, sid, pwd, apk_seed, apk_v);
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
void mlk_tempo_encaps(
    uint8_t *public_key,
    uint8_t *ciphertext,
    uint8_t *ephemeral_key,
    const uint8_t *sid,
    const uint8_t *pwd,
    const uint8_t *apk)
{
    uint8_t v_hash[TEMPO_3LAMBDA];
    const uint8_t *apk_u = apk;
    const uint8_t *apk_v = apk_u + TEMPO_3LAMBDA;
    const uint8_t *apk_seed = apk_v + MLKEM_POLYVECBYTES;
    h_2(v_hash, sid, pwd, apk_seed, apk_v);
    uint8_t r_seed[TEMPO_3LAMBDA];
    for (int i = 0; i < TEMPO_3LAMBDA; i++)
    {
        r_seed[i] = v_hash[i] ^ apk_u[i];
    }
    mlk_polyvec r;
    h_1(&r, sid, pwd, apk_seed, r_seed);
    mlk_polyvec v;
    mlk_polyvec_frombytes(&v, apk_v);
    mlk_polyvec_sub(&v, &r);
    mlk_polyvec_reduce(&v);
    uint8_t poly[MLKEM_POLYVECBYTES];
    mlk_polyvec_tobytes(poly, &v);
    memcpy(public_key + MLKEM_POLYVECBYTES, apk_seed, MLKEM_SYMBYTES);
    memcpy(public_key, poly, MLKEM_POLYVECBYTES);
    mlk_kem_enc(ciphertext, ephemeral_key, public_key);
    mlk_zeroize(&r, sizeof(r));
    mlk_zeroize(&v, sizeof(v));
    mlk_zeroize(r_seed, TEMPO_3LAMBDA);
    mlk_zeroize(v_hash, TEMPO_3LAMBDA);
    mlk_zeroize(poly, MLKEM_POLYVECBYTES);
}

MLK_EXTERNAL_API
void mlk_tempo_decaps(
    uint8_t *ephemeral_key,
    const uint8_t *secret_key,
    const uint8_t *ciphertext)
{
    mlk_kem_dec(ephemeral_key, ciphertext, secret_key);
}

MLK_EXTERNAL_API
void mlk_tempo_confirm(
    uint8_t *tag_a,
    uint8_t *tag_b,
    uint8_t *shared_secret,
    const uint8_t *sid,
    const uint8_t *pwd,
    const uint8_t *apk,
    const uint8_t *ciphertext,
    const uint8_t *public_key,
    const uint8_t *ephemeral_key)
{
    h_confirm(
        tag_a,
        tag_b,
        shared_secret,
        sid,
        pwd,
        apk,
        ciphertext,
        public_key,
        ephemeral_key);
}

MLK_EXTERNAL_API
int mlk_tempo_verify(const uint8_t *tag, const uint8_t *peer_tag)
{
    return mlk_ct_memcmp(tag, peer_tag, TEMPO_LEN_TAG);
}

#undef h_fls
#undef h_1
#undef h_2
#undef h_confirm
