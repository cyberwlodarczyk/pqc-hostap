/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* References
 * ==========
 *
 * - [FIPS140_3_IG]
 *   Implementation Guidance for FIPS 140-3 and the Cryptographic Module
 *   Validation Program
 *   National Institute of Standards and Technology
 *   https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-ig-announcements
 *
 * - [FIPS203]
 *   FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism Standard
 *   National Institute of Standards and Technology
 *   https://csrc.nist.gov/pubs/fips/203/final
 *
 * - [REF]
 *   CRYSTALS-Kyber C reference implementation
 *   Bos, Ducas, Kiltz, Lepoint, Lyubashevsky, Schanck, Schwabe, Seiler, Stehlé
 *   https://github.com/pq-crystals/kyber/tree/main/ref
 */

#include "kem.h"

#include "indcpa.h"
#include "randombytes.h"
#include "symmetric.h"
#include "verify.h"

/* Parameter set namespacing
 * This is to facilitate building multiple instances
 * of mlkem-native (e.g. with varying security levels)
 * within a single compilation unit. */
#define mlk_check_pct MLK_ADD_PARAM_SET(mlk_check_pct)
/* End of parameter set namespacing */

/* Reference: Not implemented in the reference implementation @[REF]. */
MLK_EXTERNAL_API
MLK_MUST_CHECK_RETURN_VALUE
int mlk_kem_check_pk(const uint8_t pk[MLKEM_INDCCA_LEN_PUBLIC_KEY])
{
  int ret = 0;
  mlk_polyvec p;
  uint8_t p_reencoded[MLKEM_POLYVECBYTES];

  mlk_polyvec_frombytes(&p, pk);
  mlk_polyvec_reduce(&p);
  mlk_polyvec_tobytes(p_reencoded, &p);

  /* We use a constant-time memcmp here to avoid having to
   * declassify the PK before the PCT has succeeded. */
  ret = mlk_ct_memcmp(pk, p_reencoded, MLKEM_POLYVECBYTES) ? MLK_ERR_FAIL : 0;

  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  mlk_zeroize(p_reencoded, MLKEM_POLYVECBYTES);
  mlk_zeroize(&p, sizeof(mlk_polyvec));
  return ret;
}

/* Reference: Not implemented in the reference implementation @[REF]. */
MLK_EXTERNAL_API
MLK_MUST_CHECK_RETURN_VALUE
int mlk_kem_check_sk(const uint8_t sk[MLKEM_INDCCA_LEN_SECRET_KEY])
{
  int ret = 0;
  uint8_t test[MLKEM_SYMBYTES];

  /*
   * The parts of `sk` being hashed and compared here are public, so
   * no public information is leaked through the runtime or the return value
   * of this function.
   */

  /* Declassify the public part of the secret key */
  MLK_CT_TESTING_DECLASSIFY(sk + MLKEM_INDCPA_LEN_SECRET_KEY,
                            MLKEM_INDCCA_LEN_PUBLIC_KEY);
  MLK_CT_TESTING_DECLASSIFY(
      sk + MLKEM_INDCCA_LEN_SECRET_KEY - 2 * MLKEM_SYMBYTES, MLKEM_SYMBYTES);

  mlk_hash_h(test, sk + MLKEM_INDCPA_LEN_SECRET_KEY,
             MLKEM_INDCCA_LEN_PUBLIC_KEY);
  /* This doesn't have to be a constant-time memcmp, but it's the only place
   * in the library where a normal memcmp would be used otherwise, so for sake
   * of minimizing stdlib dependency, we use our constant-time one anyway. */
  ret = mlk_ct_memcmp(sk + MLKEM_INDCCA_LEN_SECRET_KEY - 2 * MLKEM_SYMBYTES,
                      test, MLKEM_SYMBYTES)
            ? MLK_ERR_FAIL
            : 0;

  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  mlk_zeroize(test, MLKEM_SYMBYTES);
  return ret;
}

MLK_MUST_CHECK_RETURN_VALUE
static int mlk_check_pct(uint8_t const pk[MLKEM_INDCCA_LEN_PUBLIC_KEY],
                         uint8_t const sk[MLKEM_INDCCA_LEN_SECRET_KEY])
    __contract__(
        requires(memory_no_alias(pk, MLKEM_INDCCA_LEN_PUBLIC_KEY))
            requires(memory_no_alias(sk, MLKEM_INDCCA_LEN_SECRET_KEY))
                ensures(return_value == 0 || return_value == MLK_ERR_FAIL ||
                        return_value == MLK_ERR_RNG_FAIL));

#if defined(MLK_CONFIG_KEYGEN_PCT)
/* Specification:
 * Partially implements 'Pairwise Consistency Test' @[FIPS140_3_IG, p.87] and
 * @[FIPS203, Section 7.1, Pairwise Consistency]. */

/* Reference: Not implemented in the reference implementation @[REF]. */
MLK_MUST_CHECK_RETURN_VALUE
static int mlk_check_pct(uint8_t const pk[MLKEM_INDCCA_LEN_PUBLIC_KEY],
                         uint8_t const sk[MLKEM_INDCCA_LEN_SECRET_KEY])
{
  int ret = 0;
  uint8_t ct[MLKEM_INDCCA_LEN_CIPHERTEXT];
  uint8_t ss_enc[MLKEM_SSBYTES];
  uint8_t ss_dec[MLKEM_SSBYTES];

  ret = mlk_kem_enc(ct, ss_enc, pk);
  if (ret != 0)
  {
    goto cleanup;
  }

  ret = mlk_kem_dec(ss_dec, ct, sk);
  if (ret != 0)
  {
    goto cleanup;
  }

#if defined(MLK_CONFIG_KEYGEN_PCT_BREAKAGE_TEST)
  /* Deliberately break PCT for testing purposes */
  if (mlk_break_pct())
  {
    ss_enc[0] = ~ss_enc[0];
  }
#endif /* MLK_CONFIG_KEYGEN_PCT_BREAKAGE_TEST */

  ret = mlk_ct_memcmp(ss_enc, ss_dec, MLKEM_SSBYTES);
  /* The result of the PCT is public. */
  MLK_CT_TESTING_DECLASSIFY(&ret, sizeof(ret));

  if (ret != 0)
  {
    ret = MLK_ERR_FAIL;
  }

cleanup:

  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  mlk_zeroize(ss_dec, MLKEM_SSBYTES);
  mlk_zeroize(ss_enc, MLKEM_SSBYTES);
  mlk_zeroize(ct, MLKEM_INDCCA_LEN_CIPHERTEXT);
  return ret;
}
#else  /* MLK_CONFIG_KEYGEN_PCT */
MLK_MUST_CHECK_RETURN_VALUE
static int mlk_check_pct(uint8_t const pk[MLKEM_INDCCA_LEN_PUBLIC_KEY],
                         uint8_t const sk[MLKEM_INDCCA_LEN_SECRET_KEY])
{
  /* Skip PCT */
  ((void)pk);
  ((void)sk);
  return 0;
}
#endif /* !MLK_CONFIG_KEYGEN_PCT */

/* Reference: `crypto_kem_keypair_derand()` in the reference implementation
 *            @[REF].
 *            - We optionally include PCT which is not present in
 *              the reference code. */
MLK_EXTERNAL_API
int mlk_kem_keypair_derand(uint8_t pk[MLKEM_INDCCA_LEN_PUBLIC_KEY],
                           uint8_t sk[MLKEM_INDCCA_LEN_SECRET_KEY],
                           const uint8_t coins[2 * MLKEM_SYMBYTES])
{
  mlk_indcpa_keypair_derand(pk, sk, coins);

  mlk_memcpy(sk + MLKEM_INDCPA_LEN_SECRET_KEY, pk, MLKEM_INDCCA_LEN_PUBLIC_KEY);
  mlk_hash_h(sk + MLKEM_INDCCA_LEN_SECRET_KEY - 2 * MLKEM_SYMBYTES, pk,
             MLKEM_INDCCA_LEN_PUBLIC_KEY);
  /* Value z for pseudo-random output on reject */
  mlk_memcpy(sk + MLKEM_INDCCA_LEN_SECRET_KEY - MLKEM_SYMBYTES,
             coins + MLKEM_SYMBYTES, MLKEM_SYMBYTES);

  /* Declassify public key */
  MLK_CT_TESTING_DECLASSIFY(pk, MLKEM_INDCCA_LEN_PUBLIC_KEY);

  /* Pairwise Consistency Test (PCT) @[FIPS140_3_IG, p.87] */
  int ret = mlk_check_pct(pk, sk);
  if (ret != 0)
  {
    mlk_zeroize(pk, MLKEM_INDCCA_LEN_PUBLIC_KEY);
    mlk_zeroize(sk, MLKEM_INDCCA_LEN_SECRET_KEY);
  }
  return ret;
}

#if !defined(MLK_CONFIG_NO_RANDOMIZED_API)
/* Reference: `crypto_kem_keypair()` in the reference implementation @[REF]
 *            - We zeroize the stack buffer */
MLK_EXTERNAL_API
int mlk_kem_keypair(uint8_t pk[MLKEM_INDCCA_LEN_PUBLIC_KEY],
                    uint8_t sk[MLKEM_INDCCA_LEN_SECRET_KEY])
{
  int ret = 0;
  uint8_t coins[2 * MLKEM_SYMBYTES];

  /* Acquire necessary randomness, and mark it as secret. */
  if (mlk_randombytes(coins, 2 * MLKEM_SYMBYTES) != 0)
  {
    ret = MLK_ERR_RNG_FAIL;
    goto cleanup;
  }

  MLK_CT_TESTING_SECRET(coins, 2 * MLKEM_SYMBYTES);

  ret = mlk_kem_keypair_derand(pk, sk, coins);

cleanup:
  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  mlk_zeroize(coins, 2 * MLKEM_SYMBYTES);
  return ret;
}
#endif /* !MLK_CONFIG_NO_RANDOMIZED_API */

/* Reference: `crypto_kem_enc_derand()` in the reference implementation @[REF]
 *            - We include public key check
 *            - We include stack buffer zeroization */
MLK_EXTERNAL_API
int mlk_kem_enc_derand(uint8_t ct[MLKEM_INDCCA_LEN_CIPHERTEXT],
                       uint8_t ss[MLKEM_SSBYTES],
                       const uint8_t pk[MLKEM_INDCCA_LEN_PUBLIC_KEY],
                       const uint8_t coins[MLKEM_SYMBYTES])
{
  int ret = 0;
  uint8_t buf[2 * MLKEM_SYMBYTES];
  uint8_t kr[2 * MLKEM_SYMBYTES];

  /* Specification: Implements @[FIPS203, Section 7.2, Modulus check] */
  ret = mlk_kem_check_pk(pk);
  if (ret != 0)
  {
    goto cleanup;
  }

  mlk_memcpy(buf, coins, MLKEM_SYMBYTES);

  /* Multitarget countermeasure for coins + contributory KEM */
  mlk_hash_h(buf + MLKEM_SYMBYTES, pk, MLKEM_INDCCA_LEN_PUBLIC_KEY);
  mlk_hash_g(kr, buf, 2 * MLKEM_SYMBYTES);

  /* coins are in kr+MLKEM_SYMBYTES */
  ret = mlk_indcpa_enc(ct, buf, pk, kr + MLKEM_SYMBYTES);
  if (ret != 0)
  {
    goto cleanup;
  }

  mlk_memcpy(ss, kr, MLKEM_SYMBYTES);

cleanup:
  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  mlk_zeroize(kr, 2 * MLKEM_SYMBYTES);
  mlk_zeroize(buf, 2 * MLKEM_SYMBYTES);
  return ret;
}

#if !defined(MLK_CONFIG_NO_RANDOMIZED_API)
/* Reference: `crypto_kem_enc()` in the reference implementation @[REF]
 *            - We include stack buffer zeroization */
MLK_EXTERNAL_API
int mlk_kem_enc(uint8_t ct[MLKEM_INDCCA_LEN_CIPHERTEXT],
                uint8_t ss[MLKEM_SSBYTES],
                const uint8_t pk[MLKEM_INDCCA_LEN_PUBLIC_KEY])
{
  int ret = 0;
  uint8_t coins[MLKEM_SYMBYTES];

  if (mlk_randombytes(coins, MLKEM_SYMBYTES) != 0)
  {
    ret = MLK_ERR_RNG_FAIL;
    goto cleanup;
  }

  MLK_CT_TESTING_SECRET(coins, MLKEM_SYMBYTES);

  ret = mlk_kem_enc_derand(ct, ss, pk, coins);

cleanup:
  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  mlk_zeroize(coins, MLKEM_SYMBYTES);
  return ret;
}
#endif /* !MLK_CONFIG_NO_RANDOMIZED_API */

/* Reference: `crypto_kem_dec()` in the reference implementation @[REF]
 *            - We include secret key check
 *            - We include stack buffer zeroization */
MLK_EXTERNAL_API
int mlk_kem_dec(uint8_t ss[MLKEM_SSBYTES],
                const uint8_t ct[MLKEM_INDCCA_LEN_CIPHERTEXT],
                const uint8_t sk[MLKEM_INDCCA_LEN_SECRET_KEY])
{
  int ret = 0;
  uint8_t fail;
  const uint8_t *pk = sk + MLKEM_INDCPA_LEN_SECRET_KEY;
  uint8_t buf[2 * MLKEM_SYMBYTES];
  uint8_t kr[2 * MLKEM_SYMBYTES];
  uint8_t tmp[MLKEM_SYMBYTES + MLKEM_INDCCA_LEN_CIPHERTEXT];

  /* Specification: Implements @[FIPS203, Section 7.3, Hash check] */
  ret = mlk_kem_check_sk(sk);
  if (ret != 0)
  {
    goto cleanup;
  }

  ret = mlk_indcpa_dec(buf, ct, sk);
  if (ret != 0)
  {
    goto cleanup;
  }

  /* Multitarget countermeasure for coins + contributory KEM */
  mlk_memcpy(buf + MLKEM_SYMBYTES,
             sk + MLKEM_INDCCA_LEN_SECRET_KEY - 2 * MLKEM_SYMBYTES,
             MLKEM_SYMBYTES);
  mlk_hash_g(kr, buf, 2 * MLKEM_SYMBYTES);

  /* Recompute and compare ciphertext */
  /* coins are in kr+MLKEM_SYMBYTES */
  ret = mlk_indcpa_enc(tmp, buf, pk, kr + MLKEM_SYMBYTES);
  if (ret != 0)
  {
    goto cleanup;
  }

  fail = mlk_ct_memcmp(ct, tmp, MLKEM_INDCCA_LEN_CIPHERTEXT);

  /* Compute rejection key */
  mlk_memcpy(tmp, sk + MLKEM_INDCCA_LEN_SECRET_KEY - MLKEM_SYMBYTES,
             MLKEM_SYMBYTES);
  mlk_memcpy(tmp + MLKEM_SYMBYTES, ct, MLKEM_INDCCA_LEN_CIPHERTEXT);
  mlk_hash_j(ss, tmp, MLKEM_SYMBYTES + MLKEM_INDCCA_LEN_CIPHERTEXT);

  /* Copy true key to return buffer if fail is 0 */
  mlk_ct_cmov_zero(ss, kr, MLKEM_SYMBYTES, fail);

cleanup:
  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  mlk_zeroize(tmp, MLKEM_SYMBYTES + MLKEM_INDCCA_LEN_CIPHERTEXT);
  mlk_zeroize(kr, 2 * MLKEM_SYMBYTES);
  mlk_zeroize(buf, 2 * MLKEM_SYMBYTES);

  return ret;
}

/* To facilitate single-compilation-unit (SCU) builds, undefine all macros.
 * Don't modify by hand -- this is auto-generated by scripts/autogen. */
#undef mlk_check_pct
