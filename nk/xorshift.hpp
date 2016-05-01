#ifndef NKLIB_RNG_XORSHIFT_HPP_
#define NKLIB_RNG_XORSHIFT_HPP_

#include <cstring>
#include <cstdint>
#include <algorithm>
extern "C" {
#include <nk/hwrng.h>
}

// A family of fast, high-quality RNG for non-cryptographic applications that
// requires very little RAM for state.  These algorithms perform quite
// competitively with the well-known Mersenne Twister, but are faster with a
// much smaller RAM footprint.
//
// The smallest state generator that is sufficient for the task should be
// preferred; it will be more resistant to biases introduced by initial seeds
// that do not have a relatively even distribution of one and zero bits
// ('zeroland') when compared to generators with a larger state space.
//
// This bias hardly exists in the initial samples from the xorshift64* variant,
// but may take dozens or hundreds of samples to resolve with the xorshift1024*
// or xorshift4096* variants.
//
// In general the xorshift* generators have better properties, but the
// xorshift128+ generator is particularly fast and has good behavior aside from
// being slower to escape from 'zeroland' when compared to the xorshift64*
// generator.
//
// xorshift* generators are described in
// S. Vigna, "An experimental exploration of Marsaglia's xorshift generators,
//            scrambled".
//
// xorshift+ generators are described in
// S. Vigna, "Further scramblings of Marsaglia's xorshift generators".
//
// xoroshiro+ generators are described at
// http://xoroshiro.di.unimi.it/

namespace nk {
namespace rng {

// This is a fixed-increment version of Java 8's SplittableRandom generator
// It is fast and passes BigCrush, but is only used for expanding 64-bit seeds.
namespace detail {
    inline uint64_t splitmix64(uint64_t &x) {
        uint64_t z = (x += 0x9e3779b97f4a7c15ull);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
        return z ^ (z >> 31);
    }
    static inline uint64_t rotl(const uint64_t x, int k) {
        return (x << k) | (x >> (64 - k));
    }
}

// Should be preferred for most applications.
class xoroshiro128p
{
public:
    typedef std::uint64_t result_type;
    xoroshiro128p() { nk_get_hwrng((char *)s_, sizeof s_); }
    xoroshiro128p(uint64_t s) { seed(s); }
    xoroshiro128p(uint64_t a, uint64_t b) { seed(a, b); }
    void seed(uint64_t s) { s_[0] = s; s_[1] = detail::splitmix64(s); }
    void seed(uint64_t a, uint64_t b) { s_[0] = a; s_[1] = b; }
    void seed(const void *s, size_t slen) { memcpy(s_, s, std::min(slen, sizeof s_)); }
    uint64_t operator()()
    {
        const auto s0 = s_[0];
        auto s1 = s_[1];
        const auto result = s0 + s1;

        s1 ^= s0;
        s_[0] = detail::rotl(s0, 55) ^ s1 ^ (s1 << 14);
        s_[1] = detail::rotl(s1, 36);

        return result;
    }
    void jump()
    {
        static const uint64_t JUMP[] = { 0xbeac0467eba5facb, 0xd86b048b86aa9922 };
        uint64_t s0{0}, s1{0};
        for (unsigned i = 0; i < sizeof JUMP / sizeof *JUMP; ++i) {
            for (unsigned b = 0; b < 64; ++b) {
                if (JUMP[i] & 1ull << b) {
                    s0 ^= s_[0];
                    s1 ^= s_[1];
                }
                operator()();
            }
        }
        s_[0] = s0;
        s_[1] = s1;
    }
    void discard(unsigned long long z)
    {
        while (z-- > 0)
            (void)(*this)();
    }
    static constexpr uint64_t min() { return 0ull; }
    static constexpr uint64_t max() { return ~0ull; }
    static constexpr size_t state_size = 2 * sizeof(uint64_t);
    friend bool operator==(const xoroshiro128p &a, const xoroshiro128p &b);
    friend bool operator!=(const xoroshiro128p &a, const xoroshiro128p &b);
private:
    uint64_t s_[2];
};

inline bool operator==(const xoroshiro128p &a, const xoroshiro128p &b)
{
    return a.s_[0] == b.s_[0] && a.s_[1] == b.s_[1];
}
inline bool operator!=(const xoroshiro128p &a, const xoroshiro128p &b)
{
    return a.s_[0] != b.s_[0] || a.s_[1] != b.s_[1];
}

}
}

#endif

