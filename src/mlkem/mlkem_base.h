/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* References
 * ==========
 *
 * - [FIPS203]
 *   FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism Standard
 *   National Institute of Standards and Technology
 *   https://csrc.nist.gov/pubs/fips/203/final
 */

#ifndef MLK_H
#define MLK_H

/*
 * Public API for mlkem-native.
 *
 * This header defines the public API of a single build of mlkem-native.
 *
 * Make sure the configuration file is in the include path
 * (this is "config.h" by default, or MLK_CONFIG_FILE if defined).
 *
 * # Multi-level builds
 *
 * This header specifies a build of mlkem-native for a fixed security level.
 * If you need multiple security levels, leave the security level unspecified
 * in the configuration file and include this header multiple times, setting
 * MLK_CONFIG_PARAMETER_SET accordingly for each, and #undef'ing the MLK_H
 * guard to allow multiple inclusions.
 *
 * # Legacy configuration (deprecated)
 *
 * Instead of providing the config file used for the build, you can
 * alternatively set the following configuration options prior to
 * including this header.
 *
 * This method of configuration is deprecated.
 * It will be removed in mlkem-native-v2.
 *
 * - MLK_CONFIG_API_PARAMETER_SET [required]
 *
 *   The parameter set used for the build; 512, 768, or 1024.
 *
 * - MLK_CONFIG_API_NAMESPACE_PREFIX [required]
 *
 *   The namespace prefix used for the build.
 *
 *   NOTE:
 *   For a multi-level build, you must include the 512/768/1024 suffixes
 *   in MLK_CONFIG_API_NAMESPACE_PREFIX.
 *
 * - MLK_CONFIG_API_NO_SUPERCOP [optional]
 *
 *   By default, this header will also expose the mlkem-native API in the
 *   SUPERCOP naming convention crypto_kem_xxx. If you don't want/need this,
 *   set MLK_CONFIG_API_NO_SUPERCOP. You must set this for a multi-level build.
 *
 * - MLK_CONFIG_API_CONSTANTS_ONLY [optional]
 *
 *   If you don't want this header to expose any function declarations,
 *   but only constants for the sizes of key material, set
 *   MLK_CONFIG_API_CONSTANTS_ONLY. In this case, you don't need to set
 *   MLK_CONFIG_API_PARAMETER_SET or MLK_CONFIG_API_NAMESPACE_PREFIX,
 *   nor include a configuration.
 *
 * - MLK_CONFIG_API_QUALIFIER [optional]
 *
 *   Qualifier to apply to external API.
 *
 ******************************************************************************/

/******************************* Key sizes ************************************/

/* Sizes of cryptographic material, per parameter set */
/* See mlkem/common.h for the arithmetic expressions giving rise to these */
/* check-magic: off */
#define MLKEM512_LEN_SECRET_KEY 1632
#define MLKEM512_LEN_PUBLIC_KEY 800
#define MLKEM512_LEN_CIPHERTEXT 768
#define TEMPO512_LEN_SECRET_KEY MLKEM512_LEN_SECRET_KEY
#define TEMPO512_LEN_PUBLIC_KEY MLKEM512_LEN_PUBLIC_KEY
#define TEMPO512_LEN_CIPHERTEXT MLKEM512_LEN_CIPHERTEXT
#define TEMPO512_LEN_MSG 848
#define TEMPO512_LEN_TAG 32

#define MLKEM768_LEN_SECRET_KEY 2400
#define MLKEM768_LEN_PUBLIC_KEY 1184
#define MLKEM768_LEN_CIPHERTEXT 1088
#define TEMPO768_LEN_SECRET_KEY MLKEM768_LEN_SECRET_KEY
#define TEMPO768_LEN_PUBLIC_KEY MLKEM768_LEN_PUBLIC_KEY
#define TEMPO768_LEN_CIPHERTEXT MLKEM768_LEN_CIPHERTEXT
#define TEMPO768_LEN_MSG 1256
#define TEMPO768_LEN_TAG 48

#define MLKEM1024_LEN_SECRET_KEY 3168
#define MLKEM1024_LEN_PUBLIC_KEY 1568
#define MLKEM1024_LEN_CIPHERTEXT 1568
#define TEMPO1024_LEN_SECRET_KEY MLKEM1024_LEN_SECRET_KEY
#define TEMPO1024_LEN_PUBLIC_KEY MLKEM1024_LEN_PUBLIC_KEY
#define TEMPO1024_LEN_CIPHERTEXT MLKEM1024_LEN_CIPHERTEXT
#define TEMPO1024_LEN_MSG 1664
#define TEMPO1024_LEN_TAG 64

/* check-magic: on */

/* Size of randomness coins in bytes (level-independent) */
#define MLKEM_SYMBYTES 32
#define MLKEM512_SYMBYTES MLKEM_SYMBYTES
#define MLKEM768_SYMBYTES MLKEM_SYMBYTES
#define MLKEM1024_SYMBYTES MLKEM_SYMBYTES
/* Size of shared secret in bytes (level-independent) */
#define MLKEM_LEN_SHARED_SECRET 32
#define MLKEM512_LEN_SHARED_SECRET MLKEM_LEN_SHARED_SECRET
#define MLKEM768_LEN_SHARED_SECRET MLKEM_LEN_SHARED_SECRET
#define MLKEM1024_LEN_SHARED_SECRET MLKEM_LEN_SHARED_SECRET

#define TEMPO512_LEN_SHARED_SECRET 32
#define TEMPO768_LEN_SHARED_SECRET 32
#define TEMPO1024_LEN_SHARED_SECRET 32

#define TEMPO_LEN_COUNTER 2
#define TEMPO_LEN_SHARED_SECRET MLKEM_LEN_SHARED_SECRET
#define TEMPO_LEN_MASTER_KEY 32
#define TEMPO_LEN_SID 32
#define TEMPO_LEN_PWD 32

/* Sizes of cryptographic material, as a function of LVL=512,768,1024 */
#define MLKEM_LEN_SECRET_KEY_(LVL) MLKEM##LVL##_LEN_SECRET_KEY
#define MLKEM_LEN_PUBLIC_KEY_(LVL) MLKEM##LVL##_LEN_PUBLIC_KEY
#define MLKEM_LEN_CIPHERTEXT_(LVL) MLKEM##LVL##_LEN_CIPHERTEXT
#define TEMPO_LEN_SECRET_KEY_(LVL) TEMPO##LVL##_LEN_SECRET_KEY
#define TEMPO_LEN_PUBLIC_KEY_(LVL) TEMPO##LVL##_LEN_PUBLIC_KEY
#define TEMPO_LEN_CIPHERTEXT_(LVL) TEMPO##LVL##_LEN_CIPHERTEXT
#define TEMPO_LEN_MSG_(LVL) TEMPO##LVL##_LEN_MSG
#define TEMPO_LEN_TAG_(LVL) TEMPO##LVL##_LEN_TAG
#define MLKEM_LEN_SECRET_KEY(LVL) MLKEM_LEN_SECRET_KEY_(LVL)
#define MLKEM_LEN_PUBLIC_KEY(LVL) MLKEM_LEN_PUBLIC_KEY_(LVL)
#define MLKEM_LEN_CIPHERTEXT(LVL) MLKEM_LEN_CIPHERTEXT_(LVL)
#define TEMPO_LEN_SECRET_KEY(LVL) TEMPO_LEN_SECRET_KEY_(LVL)
#define TEMPO_LEN_PUBLIC_KEY(LVL) TEMPO_LEN_PUBLIC_KEY_(LVL)
#define TEMPO_LEN_CIPHERTEXT(LVL) TEMPO_LEN_CIPHERTEXT_(LVL)
#define TEMPO_LEN_MSG(LVL) TEMPO_LEN_MSG_(LVL)
#define TEMPO_LEN_TAG(LVL) TEMPO_LEN_TAG_(LVL)

/****************************** Error codes ***********************************/

/* Generic failure condition */
#define MLK_ERR_FAIL -1
/* An rng failure occured. Might be due to insufficient entropy or
 * system misconfiguration. */
#define MLK_ERR_RNG_FAIL -3

#define MLK_ERR_DIGEST_FAIL -4

/****************************** Function API **********************************/

#define MLK_API_CONCAT_(x, y) x##y
#define MLK_API_CONCAT(x, y) MLK_API_CONCAT_(x, y)
#define MLK_API_CONCAT_UNDERSCORE(x, y) MLK_API_CONCAT(MLK_API_CONCAT(x, _), y)

#if !defined(MLK_CONFIG_API_PARAMETER_SET)
/* Recommended configuration via same config file as used for the build. */

/* For now, we derive the legacy API configuration MLK_CONFIG_API_XXX from
 * the config file. In mlkem-native-v2, this will be removed and we will
 * exclusively work with MLK_CONFIG_XXX. */

/* You need to make sure the config file is in the include path. */
#if defined(MLK_CONFIG_FILE)
#include MLK_CONFIG_FILE
#else
#include "mlkem_config.h"
#endif

#define MLK_CONFIG_API_PARAMETER_SET MLK_CONFIG_PARAMETER_SET

#if defined(MLK_CONFIG_MULTILEVEL_BUILD)
#define MLK_CONFIG_API_NAMESPACE_PREFIX \
    MLK_API_CONCAT(MLK_CONFIG_NAMESPACE_PREFIX, MLK_CONFIG_PARAMETER_SET)
#define MLK_CONFIG_API_TEMPO_NAMESPACE_PREFIX \
    MLK_API_CONCAT(MLK_CONFIG_TEMPO_NAMESPACE_PREFIX, MLK_CONFIG_PARAMETER_SET)
#else
#define MLK_CONFIG_API_NAMESPACE_PREFIX MLK_CONFIG_NAMESPACE_PREFIX
#define MLK_CONFIG_API_TEMPO_NAMESPACE_PREFIX MLK_CONFIG_TEMPO_NAMESPACE_PREFIX
#endif

#if defined(MLK_CONFIG_NO_SUPERCOP)
#define MLK_CONFIG_API_NO_SUPERCOP
#endif

#if defined(MLK_CONFIG_CONSTANTS_ONLY)
#define MLK_CONFIG_API_CONSTANTS_ONLY
#endif

#if defined(MLK_CONFIG_EXTERNAL_API_QUALIFIER)
#define MLK_CONFIG_API_QUALIFIER MLK_CONFIG_EXTERNAL_API_QUALIFIER
#endif

#else /* !MLK_CONFIG_API_PARAMETER_SET */

#define MLK_API_LEGACY_CONFIG

#endif /* MLK_CONFIG_API_PARAMETER_SET */

#define MLK_API_NAMESPACE(sym) \
    MLK_API_CONCAT_UNDERSCORE(MLK_CONFIG_API_NAMESPACE_PREFIX, sym)

#define MLK_API_TEMPO_NAMESPACE(sym) \
    MLK_API_CONCAT_UNDERSCORE(MLK_CONFIG_API_TEMPO_NAMESPACE_PREFIX, sym)

#if defined(__GNUC__) || defined(clang)
#define MLK_API_MUST_CHECK_RETURN_VALUE __attribute__((warn_unused_result))
#else
#define MLK_API_MUST_CHECK_RETURN_VALUE
#endif

#if defined(MLK_CONFIG_API_QUALIFIER)
#define MLK_API_QUALIFIER MLK_CONFIG_API_QUALIFIER
#else
#define MLK_API_QUALIFIER
#endif

#if !defined(MLK_CONFIG_API_CONSTANTS_ONLY)

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /*************************************************
     * Name:        crypto_kem_keypair_derand
     *
     * Description: Generates public and private key
     *              for CCA-secure ML-KEM key encapsulation mechanism
     *
     * Arguments:   - uint8_t pk[]: pointer to output public key, an array of
     *                 length MLKEM{512,768,1024}_LEN_PUBLIC_KEY bytes.
     *              - uint8_t sk[]: pointer to output private key, an array of
     *                  of MLKEM{512,768,1024}_LEN_SECRET_KEY bytes.
     *              - uint8_t *coins: pointer to input randomness, an array of
     *                  2*MLKEM_SYMBYTES uniformly random bytes.
     *
     * Returns:     - 0: On success
     *              - MLK_ERR_FAIL: If MLK_CONFIG_KEYGEN_PCT is enabled and the
     *                  PCT failed.
     *
     * Specification: Implements @[FIPS203, Algorithm 16, ML-KEM.KeyGen_Internal]
     *
     **************************************************/
    MLK_API_QUALIFIER
    MLK_API_MUST_CHECK_RETURN_VALUE
    int MLK_API_NAMESPACE(keypair_derand)(
        uint8_t pk[MLKEM_LEN_PUBLIC_KEY(MLK_CONFIG_API_PARAMETER_SET)],
        uint8_t sk[MLKEM_LEN_SECRET_KEY(MLK_CONFIG_API_PARAMETER_SET)],
        const uint8_t coins[2 * MLKEM_SYMBYTES]);

#if !defined(MLK_CONFIG_NO_RANDOMIZED_API)
    /*************************************************
     * Name:        crypto_kem_keypair
     *
     * Description: Generates public and private key
     *              for CCA-secure ML-KEM key encapsulation mechanism
     *
     * Arguments:   - uint8_t *pk: pointer to output public key, an array of
     *                 MLKEM{512,768,1024}_LEN_PUBLIC_KEY bytes.
     *              - uint8_t *sk: pointer to output private key, an array of
     *                 MLKEM{512,768,1024}_LEN_SECRET_KEY bytes.
     *
     * Returns:     - 0: On success
     *              - MLK_ERR_FAIL: If MLK_CONFIG_KEYGEN_PCT is enabled and the
     *                  PCT failed.
     *              - MLK_ERR_RNG_FAIL: Random number generation failed.
     *
     * Specification: Implements @[FIPS203, Algorithm 19, ML-KEM.KeyGen]
     *
     **************************************************/
    MLK_API_QUALIFIER
    MLK_API_MUST_CHECK_RETURN_VALUE
    int MLK_API_NAMESPACE(keypair)(
        uint8_t pk[MLKEM_LEN_PUBLIC_KEY(MLK_CONFIG_API_PARAMETER_SET)],
        uint8_t sk[MLKEM_LEN_SECRET_KEY(MLK_CONFIG_API_PARAMETER_SET)]);
#endif /* !MLK_CONFIG_NO_RANDOMIZED_API */

    /*************************************************
     * Name:        crypto_kem_enc_derand
     *
     * Description: Generates cipher text and shared
     *              secret for given public key
     *
     * Arguments:   - uint8_t *ct: pointer to output cipher text, an array of
     *                 MLKEM{512,768,1024}_LEN_CIPHERTEXT bytes.
     *              - uint8_t *ss: pointer to output shared secret, an array of
     *                 MLKEM_LEN_SHARED_SECRET bytes.
     *              - const uint8_t *pk: pointer to input public key, an array of
     *                 MLKEM{512,768,1024}_LEN_PUBLIC_KEY bytes.
     *              - const uint8_t *coins: pointer to input randomness, an array of
     *                 MLKEM_SYMBYTES bytes.
     *
     * Returns: - 0 on success
     *          - MLK_ERR_FAIL: If the 'modulus check' @[FIPS203, Section 7.2]
     *              for the public key fails.
     *
     * Specification: Implements @[FIPS203, Algorithm 17, ML-KEM.Encaps_Internal]
     *
     **************************************************/
    MLK_API_QUALIFIER
    MLK_API_MUST_CHECK_RETURN_VALUE
    int MLK_API_NAMESPACE(enc_derand)(
        uint8_t ct[MLKEM_LEN_CIPHERTEXT(MLK_CONFIG_API_PARAMETER_SET)],
        uint8_t ss[MLKEM_LEN_SHARED_SECRET],
        const uint8_t pk[MLKEM_LEN_PUBLIC_KEY(MLK_CONFIG_API_PARAMETER_SET)],
        const uint8_t coins[MLKEM_SYMBYTES]);

#if !defined(MLK_CONFIG_NO_RANDOMIZED_API)
    /*************************************************
     * Name:        crypto_kem_enc
     *
     * Description: Generates cipher text and shared
     *              secret for given public key
     *
     * Arguments:   - uint8_t *ct: pointer to output cipher text, an array of
     *                 MLKEM{512,768,1024}_LEN_CIPHERTEXT bytes.
     *              - uint8_t *ss: pointer to output shared secret, an array of
     *                 MLKEM_LEN_SHARED_SECRET bytes.
     *              - const uint8_t *pk: pointer to input public key, an array of
     *                 MLKEM{512,768,1024}_LEN_PUBLIC_KEY bytes.
     *
     * Returns: - 0 on success
     *          - MLK_ERR_FAIL: If the 'modulus check' @[FIPS203, Section 7.2]
     *              for the public key fails.
     *          - MLK_ERR_RNG_FAIL: Random number generation failed.
     *
     * Specification: Implements @[FIPS203, Algorithm 20, ML-KEM.Encaps]
     *
     **************************************************/
    MLK_API_QUALIFIER
    MLK_API_MUST_CHECK_RETURN_VALUE
    int MLK_API_NAMESPACE(enc)(
        uint8_t ct[MLKEM_LEN_CIPHERTEXT(MLK_CONFIG_API_PARAMETER_SET)],
        uint8_t ss[MLKEM_LEN_SHARED_SECRET],
        const uint8_t pk[MLKEM_LEN_PUBLIC_KEY(MLK_CONFIG_API_PARAMETER_SET)]);
#endif /* !MLK_CONFIG_NO_RANDOMIZED_API */

    /*************************************************
     * Name:        crypto_kem_dec
     *
     * Description: Generates shared secret for given
     *              cipher text and private key
     *
     * Arguments:   - uint8_t *ss: pointer to output shared secret, an array of
     *                 MLKEM_LEN_SHARED_SECRET bytes.
     *              - const uint8_t *ct: pointer to input cipher text, an array of
     *                 MLKEM{512,768,1024}_LEN_CIPHERTEXT bytes.
     *              - const uint8_t *sk: pointer to input private key, an array of
     *                 MLKEM{512,768,1024}_LEN_SECRET_KEY bytes.
     *
     * Returns: - 0 on success
     *          - MLK_ERR_FAIL: If the 'hash check' @[FIPS203, Section 7.3]
     *              for the secret key fails.
     *
     * Specification: Implements @[FIPS203, Algorithm 21, ML-KEM.Decaps]
     *
     **************************************************/
    MLK_API_QUALIFIER
    MLK_API_MUST_CHECK_RETURN_VALUE
    int MLK_API_NAMESPACE(dec)(
        uint8_t ss[MLKEM_LEN_SHARED_SECRET],
        const uint8_t ct[MLKEM_LEN_CIPHERTEXT(MLK_CONFIG_API_PARAMETER_SET)],
        const uint8_t sk[MLKEM_LEN_SECRET_KEY(MLK_CONFIG_API_PARAMETER_SET)]);

    /*************************************************
     * Name:        crypto_kem_check_pk
     *
     * Description: Implements modulus check mandated by FIPS 203,
     *              i.e., ensures that coefficients are in [0,q-1].
     *
     * Arguments:   - const uint8_t *pk: pointer to input public key, an array of
     *                 MLKEM{512,768,1024}_LEN_PUBLIC_KEY bytes.
     *
     * Returns: - 0 on success
     *          - MLK_ERR_FAIL: If the modulus check failed.
     *
     * Specification: Implements @[FIPS203, Section 7.2, 'modulus check']
     *
     **************************************************/
    MLK_API_QUALIFIER
    MLK_API_MUST_CHECK_RETURN_VALUE
    int MLK_API_NAMESPACE(check_pk)(
        const uint8_t pk[MLKEM_LEN_PUBLIC_KEY(MLK_CONFIG_API_PARAMETER_SET)]);

    /*************************************************
     * Name:        crypto_kem_check_sk
     *
     * Description: Implements public key hash check mandated by FIPS 203,
     *              i.e., ensures that
     *              sk[768𝑘+32 ∶ 768𝑘+64] = H(pk)= H(sk[384𝑘 : 768𝑘+32])
     *
     * Arguments:   - const uint8_t *sk: pointer to input private key, an array of
     *                 MLKEM{512,768,1024}_LEN_SECRET_KEY bytes.
     *
     * Returns: - 0 on success
     *          - MLK_ERR_FAIL: If the public key hash check failed.
     *
     * Specification: Implements @[FIPS203, Section 7.3, 'hash check']
     *
     **************************************************/
    MLK_API_QUALIFIER
    MLK_API_MUST_CHECK_RETURN_VALUE
    int MLK_API_NAMESPACE(check_sk)(
        const uint8_t sk[MLKEM_LEN_SECRET_KEY(MLK_CONFIG_API_PARAMETER_SET)]);

    MLK_API_QUALIFIER
    MLK_API_MUST_CHECK_RETURN_VALUE
    int MLK_API_TEMPO_NAMESPACE(keygen)(
        uint8_t req[TEMPO_LEN_MSG(MLK_CONFIG_API_PARAMETER_SET)],
        uint8_t pk[TEMPO_LEN_PUBLIC_KEY(MLK_CONFIG_API_PARAMETER_SET)],
        uint8_t sk[TEMPO_LEN_SECRET_KEY(MLK_CONFIG_API_PARAMETER_SET)],
        const uint8_t sid[TEMPO_LEN_SID],
        const uint8_t pwd[TEMPO_LEN_PWD]);

    MLK_API_QUALIFIER
    MLK_API_MUST_CHECK_RETURN_VALUE
    int MLK_API_TEMPO_NAMESPACE(encaps)(
        uint8_t res[TEMPO_LEN_MSG(MLK_CONFIG_API_PARAMETER_SET)],
        uint8_t pk[TEMPO_LEN_PUBLIC_KEY(MLK_CONFIG_API_PARAMETER_SET)],
        uint8_t ss[TEMPO_LEN_SHARED_SECRET],
        const uint8_t req[TEMPO_LEN_MSG(MLK_CONFIG_API_PARAMETER_SET)],
        const uint8_t sid[TEMPO_LEN_SID],
        const uint8_t pwd[TEMPO_LEN_PWD]);

    MLK_API_QUALIFIER
    MLK_API_MUST_CHECK_RETURN_VALUE
    int MLK_API_TEMPO_NAMESPACE(decaps)(
        uint8_t ss[TEMPO_LEN_SHARED_SECRET],
        const uint8_t sk[TEMPO_LEN_SECRET_KEY(MLK_CONFIG_API_PARAMETER_SET)],
        const uint8_t res[TEMPO_LEN_MSG(MLK_CONFIG_API_PARAMETER_SET)]);

    MLK_API_QUALIFIER
    MLK_API_MUST_CHECK_RETURN_VALUE
    int MLK_API_TEMPO_NAMESPACE(confirm)(
        uint8_t tag[TEMPO_LEN_TAG(MLK_CONFIG_API_PARAMETER_SET)],
        const uint8_t ctr[TEMPO_LEN_COUNTER],
        const uint8_t pk[TEMPO_LEN_PUBLIC_KEY(MLK_CONFIG_API_PARAMETER_SET)],
        const uint8_t sk[TEMPO_LEN_SECRET_KEY(MLK_CONFIG_API_PARAMETER_SET)],
        const uint8_t req[TEMPO_LEN_MSG(MLK_CONFIG_API_PARAMETER_SET)],
        const uint8_t res[TEMPO_LEN_MSG(MLK_CONFIG_API_PARAMETER_SET)],
        const uint8_t ss[TEMPO_LEN_SHARED_SECRET],
        const uint8_t sid[TEMPO_LEN_SID],
        const uint8_t pwd[TEMPO_LEN_PWD]);

    MLK_API_QUALIFIER
    MLK_API_MUST_CHECK_RETURN_VALUE
    int MLK_API_TEMPO_NAMESPACE(verify)(
        const uint8_t peer_tag[TEMPO_LEN_TAG(MLK_CONFIG_API_PARAMETER_SET)],
        const uint8_t peer_ctr[TEMPO_LEN_COUNTER],
        const uint8_t pk[TEMPO_LEN_PUBLIC_KEY(MLK_CONFIG_API_PARAMETER_SET)],
        const uint8_t sk[TEMPO_LEN_SECRET_KEY(MLK_CONFIG_API_PARAMETER_SET)],
        const uint8_t req[TEMPO_LEN_MSG(MLK_CONFIG_API_PARAMETER_SET)],
        const uint8_t res[TEMPO_LEN_MSG(MLK_CONFIG_API_PARAMETER_SET)],
        const uint8_t ss[TEMPO_LEN_SHARED_SECRET],
        const uint8_t sid[TEMPO_LEN_SID],
        const uint8_t pwd[TEMPO_LEN_PWD]);

    MLK_API_QUALIFIER
    MLK_API_MUST_CHECK_RETURN_VALUE
    int MLK_API_TEMPO_NAMESPACE(finish)(
        uint8_t mk[TEMPO_LEN_MASTER_KEY],
        const uint8_t pk[TEMPO_LEN_PUBLIC_KEY(MLK_CONFIG_API_PARAMETER_SET)],
        const uint8_t req[TEMPO_LEN_MSG(MLK_CONFIG_API_PARAMETER_SET)],
        const uint8_t res[TEMPO_LEN_MSG(MLK_CONFIG_API_PARAMETER_SET)],
        const uint8_t ss[TEMPO_LEN_SHARED_SECRET],
        const uint8_t sid[TEMPO_LEN_SID],
        const uint8_t pwd[TEMPO_LEN_PWD]);

#ifdef __cplusplus
}
#endif

/****************************** SUPERCOP API *********************************/

#if !defined(MLK_CONFIG_API_NO_SUPERCOP)
/* Export API in SUPERCOP naming scheme CRYPTO_xxx / crypto_kem_xxx */
#define CRYPTO_LEN_SECRET_KEY MLKEM_LEN_SECRET_KEY(MLK_CONFIG_API_PARAMETER_SET)
#define CRYPTO_LEN_PUBLIC_KEY MLKEM_LEN_PUBLIC_KEY(MLK_CONFIG_API_PARAMETER_SET)
#define CRYPTO_LEN_CIPHERTEXT \
    MLKEM_LEN_CIPHERTEXT(MLK_CONFIG_API_PARAMETER_SET)
#define CRYPTO_SYMBYTES MLKEM_SYMBYTES
#define CRYPTO_BYTES MLKEM_LEN_SHARED_SECRET

#define crypto_kem_keypair_derand MLK_API_NAMESPACE(keypair_derand)
#define crypto_kem_keypair MLK_API_NAMESPACE(keypair)
#define crypto_kem_enc_derand MLK_API_NAMESPACE(enc_derand)
#define crypto_kem_enc MLK_API_NAMESPACE(enc)
#define crypto_kem_dec MLK_API_NAMESPACE(dec)
#define crypto_kem_check_pk MLK_API_NAMESPACE(check_pk)
#define crypto_kem_check_sk MLK_API_NAMESPACE(check_sk)

#else /* !MLK_CONFIG_API_NO_SUPERCOP */

/* If the SUPERCOP API is not needed, we can undefine the various helper macros
 * above. Otherwise, they are needed for lazy evaluation of crypto_kem_xxx. */
#if !defined(MLK_API_LEGACY_CONFIG)
#undef MLK_CONFIG_API_PARAMETER_SET
#undef MLK_CONFIG_API_NAMESPACE_PREFIX
#undef MLK_CONFIG_API_NO_SUPERCOP
#undef MLK_CONFIG_API_CONSTANTS_ONLY
#undef MLK_CONFIG_API_QUALIFIER
#endif /* !MLK_API_LEGACY_CONFIG */

#undef MLK_API_CONCAT
#undef MLK_API_CONCAT_
#undef MLK_API_CONCAT_UNDERSCORE
#undef MLK_API_NAMESPACE
#undef MLK_API_MUST_CHECK_RETURN_VALUE
#undef MLK_API_QUALIFIER
#undef MLK_API_LEGACY_CONFIG

#endif /* MLK_CONFIG_API_NO_SUPERCOP */
#endif /* !MLK_CONFIG_API_CONSTANTS_ONLY */

/***************************** Memory Usage **********************************/

/*
 * By default mlkem-native performs all memory allocations on the stack.
 * Alternatively, mlkem-native supports custom allocation of large structures
 * through the `MLK_CONFIG_CUSTOM_ALLOC_FREE` configuration option.
 * See config.h for details.
 *
 * `MLK_TOTAL_ALLOC_{512,768,1024}_{KEYPAIR,ENCAPS,DECAPS}` indicates the
 * maximum (accumulative) allocation via MLK_ALLOC for each parameter set and
 * operation. Note that some stack allocation remains even when using custom
 * allocators, so these values are lower than total stack usage with the default
 * stack-only allocation.
 *
 * These constants may be used to implement custom allocations using a
 * fixed-sized buffer and a simple allocator (e.g., bump allocator).
 */
/* check-magic: off */
#define MLK_TOTAL_ALLOC_512_KEYPAIR_NO_PCT 5824
#define MLK_TOTAL_ALLOC_512_KEYPAIR_PCT 10048
#define MLK_TOTAL_ALLOC_512_ENCAPS 8384
#define MLK_TOTAL_ALLOC_512_DECAPS 9152
#define MLK_TOTAL_ALLOC_768_KEYPAIR_NO_PCT 10176
#define MLK_TOTAL_ALLOC_768_KEYPAIR_PCT 15552
#define MLK_TOTAL_ALLOC_768_ENCAPS 13248
#define MLK_TOTAL_ALLOC_768_DECAPS 14336
#define MLK_TOTAL_ALLOC_1024_KEYPAIR_NO_PCT 15552
#define MLK_TOTAL_ALLOC_1024_KEYPAIR_PCT 22400
#define MLK_TOTAL_ALLOC_1024_ENCAPS 19136
#define MLK_TOTAL_ALLOC_1024_DECAPS 20704
/* check-magic: on */

/*
 * MLK_TOTAL_ALLOC_*_KEYPAIR adapts based on MLK_CONFIG_KEYGEN_PCT.
 * For legacy config, we don't know which options are used, so assume
 * the worst case (PCT enabled).
 */
#if defined(MLK_API_LEGACY_CONFIG) || defined(MLK_CONFIG_KEYGEN_PCT)
#define MLK_TOTAL_ALLOC_512_KEYPAIR MLK_TOTAL_ALLOC_512_KEYPAIR_PCT
#define MLK_TOTAL_ALLOC_768_KEYPAIR MLK_TOTAL_ALLOC_768_KEYPAIR_PCT
#define MLK_TOTAL_ALLOC_1024_KEYPAIR MLK_TOTAL_ALLOC_1024_KEYPAIR_PCT
#else
#define MLK_TOTAL_ALLOC_512_KEYPAIR MLK_TOTAL_ALLOC_512_KEYPAIR_NO_PCT
#define MLK_TOTAL_ALLOC_768_KEYPAIR MLK_TOTAL_ALLOC_768_KEYPAIR_NO_PCT
#define MLK_TOTAL_ALLOC_1024_KEYPAIR MLK_TOTAL_ALLOC_1024_KEYPAIR_NO_PCT
#endif

#define MLK_MAX3_(a, b, c) \
    ((a) > (b) ? ((a) > (c) ? (a) : (c)) : ((b) > (c) ? (b) : (c)))

/*
 * `MLK_TOTAL_ALLOC_{512,768,1024}` is the maximum across all operations for
 * each parameter set.
 */
#define MLK_TOTAL_ALLOC_512                                            \
    MLK_MAX3_(MLK_TOTAL_ALLOC_512_KEYPAIR, MLK_TOTAL_ALLOC_512_ENCAPS, \
              MLK_TOTAL_ALLOC_512_DECAPS)
#define MLK_TOTAL_ALLOC_768                                            \
    MLK_MAX3_(MLK_TOTAL_ALLOC_768_KEYPAIR, MLK_TOTAL_ALLOC_768_ENCAPS, \
              MLK_TOTAL_ALLOC_768_DECAPS)
#define MLK_TOTAL_ALLOC_1024                                             \
    MLK_MAX3_(MLK_TOTAL_ALLOC_1024_KEYPAIR, MLK_TOTAL_ALLOC_1024_ENCAPS, \
              MLK_TOTAL_ALLOC_1024_DECAPS)

#endif /* !MLK_H */
