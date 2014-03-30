#ifndef NCMLIB_COPY_CMDARG_H_
#define NCMLIB_COPY_CMDARG_H_

#include <stdio.h>
#include <stdlib.h>
#include "nk/log.h"

static void copy_cmdarg(char *dest, char *src, size_t destlen, char *argname)
{
    ssize_t olen = snprintf(dest, destlen, "%s", src);
    if (olen < 0)
        suicide("snprintf failed on %s; your system is broken?", argname);
    if ((size_t)olen >= destlen)
        suicide("snprintf would truncate %s arg; it's too long", argname);
}

#endif /* NCMLIB_COPY_CMDARG_H_ */
