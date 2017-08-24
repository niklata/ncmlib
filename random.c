/* random.c - non-cryptographic fast PRNG
 *
 * (c) 2013-2017 Nicholas J. Kain <njkain at gmail dot com>
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

#include <stdint.h>
#include "nk/hwrng.h"
#include "nk/random.h"

// Tyche PRNG: https://eden.dei.uc.pt/~sneves/pubs/2011-snfa2.pdf

void nk_random_init(struct nk_random_state *s)
{
    nk_get_hwrng(s->seed, sizeof(uint32_t) * 2);
    s->seed[2] = 2654435769;
    s->seed[3] = 1367130551;
    for (unsigned i = 0; i < 20; ++i) (void)nk_random_u32(s);
}

static inline uint32_t rotl32(const uint32_t x, int k) {
    return (x << k) | (x >> (32 - k));
}

uint32_t nk_random_u32(struct nk_random_state *s)
{
    s->seed[0] += s->seed[1]; s->seed[3] = rotl32(s->seed[3] ^ s->seed[0], 16);
    s->seed[2] += s->seed[3]; s->seed[1] = rotl32(s->seed[1] ^ s->seed[2], 12);
    s->seed[0] += s->seed[1]; s->seed[3] = rotl32(s->seed[3] ^ s->seed[0], 8);
    s->seed[2] += s->seed[3]; s->seed[1] = rotl32(s->seed[1] ^ s->seed[2], 7);
    return s->seed[1];
}

