/* random.c - Tausworthe non-cryptographic fast PRNG
 *
 * (c) 2013-2014 Nicholas J. Kain <njkain at gmail dot com>
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

// This is a fast RNG that is unsuitable for cryptographic applications, but
// is at least more consistent than using rand().
//
// For more details, see
// P. L'Ecuyer, “Maximally Equidistributed Combined Tausworthe Generators”,
// Mathematics of Computation, 65, 213 (1996), 203–213.
//
// Initial seed mixing is done by using a single step of a linear
// congruential generator.  Parameters are taken from those commonly used
// in rand() implementations.

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
#include "random.h"
#include "log.h"
#include "io.h"

static uint32_t s1_32, s2_32, s3_32, s4_32;
static bool initialized_32;
static uint64_t s1_64, s2_64, s3_64, s4_64, s5_64;
static bool initialized_64;

static void nk_get_rnd_clk(char *seed, size_t len)
{
    struct timespec ts;
    for (size_t i = 0; i < len; ++i) {
        int r = clock_gettime(CLOCK_REALTIME, &ts);
        if (r < 0) {
            log_warning("%s: Could not call clock_gettime(CLOCK_REALTIME): %s",
                        __func__, strerror(errno));
            exit(EXIT_FAILURE);
        }
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

static void nk_get_urandom(char *seed, size_t len)
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

static void nk_get_urandom_u32(uint32_t *seed)
{
    nk_get_urandom((char *)seed, sizeof *seed);
}

static void nk_get_urandom_u64(uint64_t *seed)
{
    nk_get_urandom((char *)seed, sizeof *seed);
}

static void nk_random_u32_init(void)
{
    uint32_t seed;
    nk_get_urandom_u32(&seed);

    s1_32 = seed * 1664525u + (1013904223u|0x10);
    s2_32 = seed * 1103515245u + (12345u|0x1000);
    s3_32 = seed * 214013u + (2531011u|0x100000);
    s4_32 = seed * 2147483629u + (2147483587u|0x10000000);

    initialized_32 = true;
}

uint32_t nk_random_u32(void)
{
    if (!initialized_32)
        nk_random_u32_init();
    s1_32 = ((s1_32 & 0xfffffffe) << 18) ^ (((s1_32 << 6)  ^ s1_32) >> 18);
    s2_32 = ((s2_32 & 0xfffffff8) << 2)  ^ (((s2_32 << 2)  ^ s2_32) >> 27);
    s3_32 = ((s3_32 & 0xfffffff0) << 7)  ^ (((s3_32 << 13) ^ s3_32) >> 21);
    s4_32 = ((s4_32 & 0xffffff80) << 13) ^ (((s4_32 << 3)  ^ s4_32) >> 12);
    return s1_32 ^ s2_32 ^ s3_32 ^ s4_32;
}

static void nk_random_u64_init(void)
{
    uint64_t seed;
    nk_get_urandom_u64(&seed);

    s1_64 = seed * 1664525ul + (1013904223ul|0x10);
    s2_64 = seed * 1103515245ul + (12345ul|0x1000);
    s3_64 = seed * 214013ul + (2531011ul|0x100000);
    s4_64 = seed * 2147483629ul + (2147483587ul|0x10000000);
    s5_64 = seed * 6364136223846793005ul
                 + (1442695040888963407ul|0x1000000000);

    initialized_64 = true;
}

uint64_t nk_random_u64(void)
{
    if (!initialized_64)
        nk_random_u64_init();
    s1_64 = ((s1_64 & 0xfffffffffffffffe) << 10) ^ (((s1_64 << 1)  ^ s1_64) >> 53);
    s2_64 = ((s2_64 & 0xfffffffffffffe00) << 5)  ^ (((s2_64 << 24) ^ s2_64) >> 50);
    s3_64 = ((s3_64 & 0xfffffffffffff000) << 29) ^ (((s3_64 << 3)  ^ s3_64) >> 23);
    s4_64 = ((s4_64 & 0xfffffffffffe0000) << 23) ^ (((s4_64 << 5)  ^ s4_64) >> 24);
    s5_64 = ((s5_64 & 0xffffffffff800000) << 8)  ^ (((s5_64 << 3)  ^ s5_64) >> 33);
    return s1_64 ^ s2_64 ^ s3_64 ^ s4_64 ^ s5_64;
}

