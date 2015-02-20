/* random.c - non-cryptographic fast PRNG
 *
 * (c) 2013-2015 Nicholas J. Kain <njkain at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "nk/random.h"
#include "nk/log.h"
#include "nk/io.h"

#ifdef NK_USE_GETRANDOM_SYSCALL
#include <unistd.h>
#include <sys/syscall.h>
#include <asm-generic/unistd.h>
#include <linux/random.h>
static void nk_get_urandom(char seed[static 1], size_t len)
{
    int err;
retry:
    //err = getrandom(seed, len, 0);
    err = syscall(__NR_getrandom, seed, len, 0);
    if (err < 0) {
        switch (errno) {
        case EINTR: goto retry; break;
        default: suicide("%s: getrandom() failed: %s",
                         __func__, strerror(errno));
        }
    }
}
#else
static void nk_get_rnd_clk(char seed[static 1], size_t len)
{
    struct timespec ts;
    for (size_t i = 0; i < len; ++i) {
        int r = clock_gettime(CLOCK_REALTIME, &ts);
        if (r < 0)
            suicide("%s: Could not call clock_gettime(CLOCK_REALTIME): %s",
                    __func__, strerror(errno));
        char *p = (char *)&ts.tv_sec;
        char *q = (char *)&ts.tv_nsec;
        for (size_t j = 0; j < sizeof ts.tv_sec; ++j)
            seed[i] ^= p[j];
        for (size_t j = 0; j < sizeof ts.tv_nsec; ++j)
            seed[i] ^= q[j];
        // Force some scheduler jitter.
        static const struct timespec st = { .tv_sec=0, .tv_nsec=1 };
        nanosleep(&st, NULL);
    }
}

static void nk_get_urandom(char seed[static 1], size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        int r = safe_read(fd, seed, len);
        if (r < 0) {
            log_warning("%s: Could not read /dev/urandom: %s",
                        __func__, strerror(errno));
            goto fail;
        }
    } else {
        log_warning("%s: Could not open /dev/urandom: %s", __func__,
                    strerror(errno));
        goto fail;
    }
    close(fd);
    return;
  fail:
    log_warning("%s: Seeding PRNG via system clock.  May be predictable.",
                __func__);
    nk_get_rnd_clk(seed, len);
}
#endif

// PCG XSL RR 64/32 LCG; period is 2^64
void nk_random_u32_init(struct nk_random_state_u32 s[static 1])
{
    nk_get_urandom((char *)&s->seed, sizeof s->seed);
}

uint32_t nk_random_u32(struct nk_random_state_u32 s[static 1])
{
    uint64_t os = s->seed;
    s->seed = s->seed * 6364136223846793005ULL + 1442695040888963407ULL;
    uint32_t xs = ((os ^ (os >> 18)) >> 27) & 0xffffffff;
    uint32_t r = os >> 59;
    return (xs >> r) | (xs << (32 - r));
}

void nk_random_u64_init(struct nk_random_state_u64 s[static 1])
{
    nk_get_urandom((char *)&s->seed, sizeof s->seed);
}

#ifndef NK_NO_ASM
// PCG XSL RR 128/64 LCG
// Should be more resistant to reversing the internal PRNG state to predict
// future outputs, although it should not be used where cryptographic
// security is required.
extern uint64_t nk_pcg64_roundfn(uint64_t seed[2]);
uint64_t nk_random_u64(struct nk_random_state_u64 s[static 1])
{
    return nk_pcg64_roundfn(s->seed);
}
#else
// Two independent PCG XSL RR 64/32 LCG
// Does not have the enhanced prediction resilience of the 128-bit PCG.
uint64_t nk_random_u64(struct nk_random_state_u64 s[static 1])
{
    uint64_t os0 = s->seed[0];
    s->seed[0] = s->seed[0] * 6364136223846793005ULL + 1442695040888963407ULL;
    uint64_t os1 = s->seed[1];
    s->seed[1] = s->seed[1] * 6364136223846793005ULL + 1442695040888963407ULL;

    uint32_t xs0 = ((os0 ^ (os0 >> 18)) >> 27) & 0xffffffff;
    uint32_t r0 = os0 >> 59;
    uint32_t xs1 = ((os1 ^ (os1 >> 18)) >> 27) & 0xffffffff;
    uint32_t r1 = os1 >> 59;
    uint32_t o0 = (xs0 >> r0) | (xs0 << (32 - r0));
    uint32_t o1 = (xs1 >> r1) | (xs1 << (32 - r1));
    return (uint64_t)o0 | ((uint64_t)o1 << 32);
}
#endif

