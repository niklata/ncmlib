#ifndef NKLIB_FROM_STRING_HPP_
#define NKLIB_FROM_STRING_HPP_

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
                if (*s < '0' || *s > '9') goto fail_inv;
                if (ret > maxut / 10) goto fail_oor;
                digit = *s - '0';
                ret = ret * 10u + digit;
            } while (*++s);
            if (ret > maxut + neg) goto fail_oor;
            return neg ? -static_cast<T>(ret) : ret;
        fail_oor:
            throw std::out_of_range("would overflow or underflow");
        fail_inv:
            throw std::invalid_argument("conversion impossible");
        }
        template <typename T>
        T str_to_signed_integer(const char *s, size_t c)
        {
            using ut = typename std::make_unsigned<T>::type;
            constexpr auto maxut = static_cast<typename std::make_unsigned<T>::type>(std::numeric_limits<T>::max());
            ut ret(0), digit;
            bool neg;
            if (c == 0) goto fail_inv;
            neg = (*s == '-');
            if (neg) ++s, c--;
            if (c == 0) goto fail_inv;
            do {
                if (*s < '0' || *s > '9') goto fail_inv;
                if (ret > maxut / 10) goto fail_oor;
                digit = *s - '0';
                ret = ret * 10u + digit;
            } while (++s, --c);
            if (ret > maxut + neg) goto fail_oor;
            return neg ? -static_cast<T>(ret) : ret;
        fail_oor:
            throw std::out_of_range("would overflow or underflow");
        fail_inv:
            throw std::invalid_argument("conversion impossible");
        }
        template <typename T>
        T str_to_unsigned_integer(const char *s)
        {
            T ret(0), digit;
            bool neg = (*s == '-');
            if (neg) goto fail_oor;
            do {
                if (*s < '0' || *s > '9') goto fail_inv;
                if (ret > std::numeric_limits<T>::max() / 10) goto fail_oor;
                digit = *s - '0';
                ret = ret * 10u + digit;
            } while (*++s);
            return ret;
        fail_oor:
            throw std::out_of_range("would overflow or underflow");
        fail_inv:
            throw std::invalid_argument("conversion impossible");
        }
        template <typename T>
        T str_to_unsigned_integer(const char *s, size_t c)
        {
            T ret(0), digit;
            bool neg;
            if (c == 0) goto fail_inv;
            neg = (*s == '-');
            if (neg) goto fail_oor;
            do {
                if (*s < '0' || *s > '9') goto fail_inv;
                if (ret > std::numeric_limits<T>::max() / 10) goto fail_oor;
                digit = *s - '0';
                ret = ret * 10u + digit;
            } while (++s, --c);
            return ret;
        fail_oor:
            throw std::out_of_range("would overflow or underflow");
        fail_inv:
            throw std::invalid_argument("conversion impossible");
        }

        template <typename T,
                  typename std::enable_if<std::is_integral<T>::value, T>::type = 0,
                  typename std::enable_if<std::is_unsigned<T>::value, T>::type = 0
                  >
        T do_from_string(const char *s) {
            return detail::str_to_unsigned_integer<T>(s);
        }
        template <typename T,
                  typename std::enable_if<std::is_integral<T>::value, T>::type = 0,
                  typename std::enable_if<std::is_signed<T>::value, T>::type = 0
                  >
        T do_from_string(const char *s) {
            return detail::str_to_signed_integer<T>(s);
        }
        template <typename T,
                  typename std::enable_if<std::is_integral<T>::value, T>::type = 0,
                  typename std::enable_if<std::is_unsigned<T>::value, T>::type = 0
                  >
        T do_from_string(const char *s, size_t c) {
            return detail::str_to_unsigned_integer<T>(s, c);
        }
        template <typename T,
                  typename std::enable_if<std::is_integral<T>::value, T>::type = 0,
                  typename std::enable_if<std::is_signed<T>::value, T>::type = 0
                  >
        T do_from_string(const char *s, size_t c) {
            return detail::str_to_signed_integer<T>(s, c);
        }
    }

    template <typename Target>
    Target from_string(const char *s)
    {
        return detail::do_from_string<Target>(s);
    }
    template <typename Target>
    Target from_string(const char *s, size_t c)
    {
        return detail::do_from_string<Target>(s, c);
    }
    template <typename Target>
    Target from_string(const std::string &s)
    {
        return detail::do_from_string<Target>(s.c_str(), s.size());
    }
}
#endif

