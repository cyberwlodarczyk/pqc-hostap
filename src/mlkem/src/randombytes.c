#include "common.h"
#if !defined(MLK_CONFIG_MULTILEVEL_NO_SHARED)
#include <sys/random.h>
#include "randombytes.h"

MLK_INTERNAL_API
int mlk_randombytes(uint8_t *out, size_t outlen)
{
    return getrandom(out, outlen, GRND_NONBLOCK) == -1 ? MLK_ERR_RNG_FAIL : 0;
}

#endif
