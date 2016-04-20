#ifndef NK_STR_TO_INT_HPP_
#define NK_STR_TO_INT_HPP_
namespace nk {

static inline int64_t str_to_s64(const char *s)
{
    size_t ret(0);
    bool neg = (*s == '-');
    if (neg) ++s;
    do {
        if (*s < '0' || *s > '9') goto fail;
        if (ret > INT64_MAX / 10) goto fail;
        unsigned digit = *s - '0';
        ret = ret * 10u + digit;
    } while (*++s);
    if (ret > (uint64_t)INT64_MAX + neg) goto fail;
    return neg ? -ret : ret;
fail:
    throw std::runtime_error("conversion failed\n");
}

static inline uint64_t str_to_u64(const char *s)
{
    size_t ret(0);
    bool neg = (*s == '-');
    if (neg) goto fail;
    do {
        if (*s < '0' || *s > '9') goto fail;
        if (ret > UINT64_MAX / 10) goto fail;
        unsigned digit = *s - '0';
        ret = ret * 10u + digit;
    } while (*++s);
    return ret;
fail:
    throw std::runtime_error("conversion failed\n");
}

}
#endif

