#include "common.h"
#if !defined(MLK_CONFIG_MULTILEVEL_NO_SHARED)
#include "randombytes.h"
#ifdef MLKEM_USE_OPENSSL_RAND
#include <openssl/rand.h>
#elif defined(CONFIG_GETRANDOM)
#include <sys/random.h>
#else
#include "utils/includes.h"
#include "utils/common.h"
#endif

MLK_INTERNAL_API
int mlk_randombytes(uint8_t *out, size_t outlen)
{
#ifdef MLKEM_USE_OPENSSL_RAND
    return RAND_priv_bytes(out, (int)outlen) == 1 ? 0 : MLK_ERR_RNG_FAIL;
#elif defined(CONFIG_GETRANDOM)
    return getrandom(out, outlen, GRND_NONBLOCK) != -1 ? 0 : MLK_ERR_RNG_FAIL;
#else
    return os_get_random(out, outlen) == 0 ? 0 : MLK_ERR_RNG_FAIL;
#endif
}

#endif
