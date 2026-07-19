#ifndef MLK_TEMPO_H
#define MLK_TEMPO_H

#include "common.h"
#include "poly_k.h"

#define mlk_tempo_keygen MLK_TEMPO_NAMESPACE_K(keygen)
MLK_EXTERNAL_API
MLK_MUST_CHECK_RETURN_VALUE
int mlk_tempo_keygen(
    uint8_t *public_key,
    uint8_t *secret_key,
    uint8_t *apk,
    const uint8_t *sid,
    const uint8_t *pwd);

#define mlk_tempo_encaps MLK_TEMPO_NAMESPACE_K(encaps)
MLK_EXTERNAL_API
void mlk_tempo_encaps(
    uint8_t *public_key,
    uint8_t *ciphertext,
    uint8_t *ephemeral_key,
    const uint8_t *sid,
    const uint8_t *pwd,
    const uint8_t *apk);

#define mlk_tempo_decaps MLK_TEMPO_NAMESPACE_K(decaps)
MLK_EXTERNAL_API
void mlk_tempo_decaps(
    uint8_t *ephemeral_key,
    const uint8_t *secret_key,
    const uint8_t *ciphertext);

#define mlk_tempo_confirm MLK_TEMPO_NAMESPACE_K(confirm)
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
    const uint8_t *ephemeral_key);

#define mlk_tempo_verify MLK_TEMPO_NAMESPACE_K(verify)
MLK_EXTERNAL_API
MLK_MUST_CHECK_RETURN_VALUE
int mlk_tempo_verify(const uint8_t *tag, const uint8_t *peer_tag);

#endif
