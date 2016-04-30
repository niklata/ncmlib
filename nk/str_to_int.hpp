#ifndef NKLIB_STR_TO_INT_HPP_
#define NKLIB_STR_TO_INT_HPP_

#include <cstdint>
#include <limits>
#include <type_traits>
#include <stdexcept>
#include <string>

namespace nk {
    namespace detail {
        template <typename T>
        T str_to_signed_integer(const char *s)
        {
            using ut = typename std::make_unsigned<T>::type;
            constexpr auto maxut = static_cast<typename std::make_unsigned<T>::type>(std::numeric_limits<T>::max());
            ut ret(0), digit;
            bool neg = (*s == '-');
            if (neg) ++s;
            do {
                if (*s < '0' || *s > '9') goto fail;
                if (ret > maxut / 10) goto fail;
                digit = *s - '0';
                ret = ret * 10u + digit;
            } while (*++s);
            if (ret > maxut + neg) goto fail;
            return neg ? -static_cast<T>(ret) : ret;
        fail:
            throw std::runtime_error("conversion failed\n");
        }
        template <typename T>
        T str_to_signed_integer(const char *s, size_t c)
        {
            using ut = typename std::make_unsigned<T>::type;
            constexpr auto maxut = std::make_unsigned<T>::type>(std::numeric_limits<T>::max());
            ut ret(0), digit;
            bool neg;
            if (c == 0) goto fail;
            neg = (*s == '-');
            if (neg) ++s, c--;
            if (c == 0) goto fail;
            do {
                if (*s < '0' || *s > '9') goto fail;
                if (ret > maxut / 10) goto fail;
                digit = *s - '0';
                ret = ret * 10u + digit;
            } while (--c);
            if (ret > maxut + neg) goto fail;
            return neg ? -static_cast<T>(ret) : ret;
        fail:
            throw std::runtime_error("conversion failed\n");
        }
        template <typename T>
        T str_to_unsigned_integer(const char *s)
        {
            T ret(0), digit;
            bool neg = (*s == '-');
            if (neg) goto fail;
            do {
                if (*s < '0' || *s > '9') goto fail;
                if (ret > std::numeric_limits<T>::max() / 10) goto fail;
                digit = *s - '0';
                ret = ret * 10u + digit;
            } while (*++s);
            return ret;
        fail:
            throw std::runtime_error("conversion failed\n");
        }
        template <typename T>
        T str_to_unsigned_integer(const char *s, size_t c)
        {
            T ret(0), digit;
            bool neg;
            if (c == 0) goto fail;
            neg = (*s == '-');
            if (neg) goto fail;
            do {
                if (*s < '0' || *s > '9') goto fail;
                if (ret > std::numeric_limits<T>::max() / 10) goto fail;
                digit = *s - '0';
                ret = ret * 10u + digit;
            } while (--c);
            return ret;
        fail:
            throw std::runtime_error("conversion failed\n");
        }
    }

    static inline auto str_to_s64(const char *s)
    {
        return detail::str_to_signed_integer<int64_t>(s);
    }
    static inline auto str_to_s32(const char *s)
    {
        return detail::str_to_signed_integer<int32_t>(s);
    }
    static inline auto str_to_s16(const char *s)
    {
        return detail::str_to_signed_integer<int16_t>(s);
    }
    static inline auto str_to_s8(const char *s)
    {
        return detail::str_to_signed_integer<int8_t>(s);
    }
    static inline auto str_to_u64(const char *s)
    {
        return detail::str_to_unsigned_integer<uint64_t>(s);
    }
    static inline auto str_to_u32(const char *s)
    {
        return detail::str_to_unsigned_integer<uint32_t>(s);
    }
    static inline auto str_to_u16(const char *s)
    {
        return detail::str_to_unsigned_integer<uint16_t>(s);
    }
    static inline auto str_to_u8(const char *s)
    {
        return detail::str_to_unsigned_integer<uint8_t>(s);
    }

    static inline auto str_to_s64(const std::string &s)
    {
        return detail::str_to_signed_integer<int64_t>(s.c_str());
    }
    static inline auto str_to_s32(const std::string &s)
    {
        return detail::str_to_signed_integer<int32_t>(s.c_str());
    }
    static inline auto str_to_s16(const std::string &s)
    {
        return detail::str_to_signed_integer<int16_t>(s.c_str());
    }
    static inline auto str_to_s8(const std::string &s)
    {
        return detail::str_to_signed_integer<int8_t>(s.c_str());
    }
    static inline auto str_to_u64(const std::string &s)
    {
        return detail::str_to_unsigned_integer<uint64_t>(s.c_str());
    }
    static inline auto str_to_u32(const std::string &s)
    {
        return detail::str_to_unsigned_integer<uint32_t>(s.c_str());
    }
    static inline auto str_to_u16(const std::string &s)
    {
        return detail::str_to_unsigned_integer<uint16_t>(s.c_str());
    }
    static inline auto str_to_u8(const std::string &s)
    {
        return detail::str_to_unsigned_integer<uint8_t>(s.c_str());
    }
}
#endif
