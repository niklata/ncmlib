#ifndef NKLIB_RNG_XORSHIFT_HPP_
#define NKLIB_RNG_XORSHIFT_HPP_

#include <random>
#include <cstdint>

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

#if defined(_MSC_VER) && _MSC_VER < 1900
#define constexpr const
#endif

namespace nk {
namespace rng {

class xorshift64m
{
public:
    typedef std::uint64_t result_type;
    xorshift64m(uint64_t s) : s_(s) {}
    template <class Sseq> explicit xorshift64m(Sseq &seq) { seed(seq); }
    void seed(uint64_t s) { s_ = s; }
    template <class Sseq> void seed(Sseq &seq)
    {
        std::array<std::uint32_t, 2> s;
        seq.generate(s.begin(), s.end());
        s_ = static_cast<std::uint64_t>(s[0]) << 32
            | static_cast<std::uint64_t>(s[1]);
    }
    uint64_t operator()()
    {
        s_ ^= s_ >> 12;
        s_ ^= s_ << 25;
        s_ ^= s_ >> 27;
        return s_ * 2685821657736338717ull;
    }
    void discard(unsigned long long z)
    {
        while (z-- > 0)
            (void)(*this)();
    }
    static constexpr uint64_t min() { return 0ull; }
    static constexpr uint64_t max() { return ~0ull; }
    static constexpr size_t state_size = 2;
    friend bool operator==(const xorshift64m &a, const xorshift64m &b);
    friend bool operator!=(const xorshift64m &a, const xorshift64m &b);
private:
    uint64_t s_;
};

inline bool operator==(const xorshift64m &a, const xorshift64m &b)
{
    return a.s_ == b.s_;
}
inline bool operator!=(const xorshift64m &a, const xorshift64m &b)
{
    return a.s_ != b.s_;
}

class xorshift1024m
{
public:
    typedef std::uint64_t result_type;
    xorshift1024m(uint64_t s) { seed(s); }
    template <class Sseq> explicit xorshift1024m(Sseq &seq)
    {
        seed(seq);
    }
    void seed(uint64_t s)
    {
        std::seed_seq ss{ s & 0xffffffff, s >> 32 };
        seed(ss);
    }
    template <class Sseq> void seed(Sseq &seq)
    {
        std::array<std::uint32_t, 32> s;
        seq.generate(s.begin(), s.end());
        for (size_t i = 0; i < 16; ++i)
            s_[i] = static_cast<std::uint64_t>(s[2 * i]) << 32
            | static_cast<std::uint64_t>(s[2 * i + 1]);
        idx_ = 0;
    }
    uint64_t operator()()
    {
        auto s0 = s_[idx_];
        auto s1 = s_[idx_ = (idx_ + 1) & 15];
        s1 ^= s1 << 31;
        s1 ^= s1 >> 11;
        s0 ^= s0 >> 30;
        return (s_[idx_] = s0 ^ s1) * 1181783497276652981ull;
    }
    void discard(unsigned long long z)
    {
        while (z-- > 0)
            (void)(*this)();
    }
    static constexpr uint64_t min() { return 0ull; }
    static constexpr uint64_t max() { return ~0ull; }
    static constexpr size_t state_size = 32;
    friend bool operator==(const xorshift1024m &a, const xorshift1024m &b);
    friend bool operator!=(const xorshift1024m &a, const xorshift1024m &b);
private:
    uint64_t s_[16];
    int idx_;
};

inline bool operator==(const xorshift1024m &a, const xorshift1024m &b)
{
    return !memcmp(a.s_, b.s_, sizeof a.s_);
}
inline bool operator!=(const xorshift1024m &a, const xorshift1024m &b)
{
    return !!memcmp(a.s_, b.s_, sizeof a.s_);
}

class xorshift4096m
{
public:
    typedef std::uint64_t result_type;
    xorshift4096m(uint64_t s) { seed(s); }
    template <class Sseq> explicit xorshift4096m(Sseq &seq)
    {
        seed(seq);
    }
    void seed(uint64_t s)
    {
        std::seed_seq ss{ s & 0xffffffff, s >> 32 };
        seed(ss);
    }
    template <class Sseq> void seed(Sseq &seq)
    {
        std::array<std::uint32_t, 128> s;
        seq.generate(s.begin(), s.end());
        for (size_t i = 0; i < 64; ++i)
            s_[i] = static_cast<std::uint64_t>(s[2 * i]) << 32
            | static_cast<std::uint64_t>(s[2 * i + 1]);
        idx_ = 0;
    }
    uint64_t operator()()
    {
        auto s0 = s_[idx_];
        auto s1 = s_[idx_ = (idx_ + 1) & 63];
        s1 ^= s1 << 25;
        s1 ^= s1 >> 3;
        s0 ^= s0 >> 49;
        return (s_[idx_] = s0 ^ s1) * 8372773778140471301ull;
    }
    void discard(unsigned long long z)
    {
        while (z-- > 0)
            (void)(*this)();
    }
    static constexpr uint64_t min() { return 0ull; }
    static constexpr uint64_t max() { return ~0ull; }
    static constexpr size_t state_size = 128;
    friend bool operator==(const xorshift4096m &a, const xorshift4096m &b);
    friend bool operator!=(const xorshift4096m &a, const xorshift4096m &b);
private:
    uint64_t s_[64];
    int idx_;
};

inline bool operator==(const xorshift4096m &a, const xorshift4096m &b)
{
    return !memcmp(a.s_, b.s_, sizeof a.s_);
}
inline bool operator!=(const xorshift4096m &a, const xorshift4096m &b)
{
    return !!memcmp(a.s_, b.s_, sizeof a.s_);
}

class xorshift128p
{
public:
    typedef std::uint64_t result_type;
    xorshift128p(uint64_t s) { seed(s); }
    template <class Sseq> explicit xorshift128p(Sseq &seq)
    {
        seed(seq);
    }
    void seed(uint64_t s)
    {
        std::seed_seq ss{ s & 0xffffffff, s >> 32 };
        seed(ss);
    }
    template <class Sseq> void seed(Sseq &seq)
    {
        std::array<std::uint32_t, 4> s;
        seq.generate(s.begin(), s.end());
        for (size_t i = 0; i < 2; ++i)
            s_[i] = static_cast<std::uint64_t>(s[2 * i]) << 32
            | static_cast<std::uint64_t>(s[2 * i + 1]);
    }
    uint64_t operator()()
    {
        auto s1 = s_[0];
        const auto s0 = s_[1];
        s_[0] = s0;
        s1 ^= s1 << 23;
        return (s_[1] = (s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26))) + s0;
    }
    void discard(unsigned long long z)
    {
        while (z-- > 0)
            (void)(*this)();
    }
    static constexpr uint64_t min() { return 0ull; }
    static constexpr uint64_t max() { return ~0ull; }
    static constexpr size_t state_size = 4;
    friend bool operator==(const xorshift128p &a, const xorshift128p &b);
    friend bool operator!=(const xorshift128p &a, const xorshift128p &b);
private:
    uint64_t s_[2];
};

inline bool operator==(const xorshift128p &a, const xorshift128p &b)
{
    return a.s_[0] == b.s_[0] && a.s_[1] == b.s_[1];
}
inline bool operator!=(const xorshift128p &a, const xorshift128p &b)
{
    return a.s_[0] != b.s_[0] || a.s_[1] != b.s_[1];
}

}
}

#endif

