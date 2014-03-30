#ifndef NCMLIB_XSTRDUP_H_
#define NCMLIB_XSTRDUP_H_

#include <string.h>
#include "nk/log.h"

#define xstrdup(a) xstrdup_z_(a,__func__)
static inline char *xstrdup_z_(const char *s, const char *fn)
{
    char *r = strdup(s);
    if (!r)
        suicide("%s: strdup failed", fn);
    return r;
}

#endif /* NCMLIB_XSTRDUP_H_ */
