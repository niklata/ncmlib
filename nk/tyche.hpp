#ifndef NCMLIB_RNG_TYCHE_HPP_
#define NCMLIB_RNG_TYCHE_HPP_

#include <cstring>
#include <cstdint>
#include <algorithm>
#include <tuple>
extern "C" {
#include <nk/hwrng.h>
}

namespace nk::rng {

// Non-cryptographic PRNG that uses the ChaCha quarter-round function.
// Passes BigCrush, designed to be easy to split via the index parameter.
// https://eden.dei.uc.pt/~sneves/pubs/2011-snfa2.pdf
// Roughly comparable in speed to PCG64, xorshift1024m, or speckrng-10.

namespace detail {
    static inline uint64_t rotl(const uint64_t x, int k) {
        return (x << k) | (x >> (64 - k));
    }
    template <typename T>
    static inline T nk_get_hwrng_v() {
        T r;
        nk_get_hwrng((char *)&r, sizeof r);
        return r;
    }
}

struct tyche final
{
    typedef std::uint32_t result_type;
    tyche(uint64_t s, uint32_t idx) noexcept
        : s_{ static_cast<uint32_t>(s >> 32), static_cast<uint32_t>(s), 2654435769, 1367130551 ^ idx } { discard(20); }
    tyche(uint32_t idx = 0) : tyche(detail::nk_get_hwrng_v<uint64_t>(), idx) {}
    tyche(uint32_t a, uint32_t b, uint32_t c, uint32_t d) noexcept : s_{ a, b, c, d } {}

    std::tuple<uint32_t, uint32_t, uint32_t, uint32_t> seed() const { return std::make_tuple(s_[0], s_[1], s_[2], s_[3]); }
    void seed(uint32_t a, uint32_t b, uint32_t c, uint32_t d) noexcept { s_[0] = a; s_[1] = b; s_[2] = c; s_[3] = d; }

    inline uint32_t operator()() noexcept
    {
        s_[0] += s_[1]; s_[3] = detail::rotl(s_[3] ^ s_[0], 16);
        s_[2] += s_[3]; s_[1] = detail::rotl(s_[1] ^ s_[2], 12);
        s_[0] += s_[1]; s_[3] = detail::rotl(s_[3] ^ s_[0], 8);
        s_[2] += s_[3]; s_[1] = detail::rotl(s_[1] ^ s_[2], 7);
        return s_[1];
    }
    void discard(size_t z) noexcept { while (z-- > 0) operator()(); }
    static constexpr uint32_t min() noexcept { return 0u; }
    static constexpr uint32_t max() noexcept { return ~0u; }
    static constexpr size_t state_size = sizeof(uint64_t);
    friend constexpr bool operator==(const tyche &a, const tyche &b) noexcept;
    friend constexpr bool operator!=(const tyche &a, const tyche &b) noexcept;
private:
    uint32_t s_[4];
};
inline constexpr bool operator==(const tyche &a, const tyche &b) noexcept {
    return a.s_[0] == b.s_[0] && a.s_[1] == b.s_[1] && a.s_[2] == b.s_[2] && a.s_[3] == b.s_[3];
}
inline constexpr bool operator!=(const tyche &a, const tyche &b) noexcept { return !operator==(a, b); }

}

#endif

