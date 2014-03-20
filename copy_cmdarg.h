#ifndef NCMLIB_COPY_CMDARG_H_
#define NCMLIB_COPY_CMDARG_H_

#include <stdio.h>
#include <stdlib.h>
#include "log.h"

static void copy_cmdarg(char *dest, char *src, size_t destlen, char *argname)
{
    ssize_t olen = snprintf(dest, destlen, "%s", src);
    if (olen < 0) {
        log_error("snprintf failed on %s; your system is broken?", argname);
        exit(EXIT_FAILURE);
    }
    if ((size_t)olen >= destlen) {
        log_error("snprintf would truncate %s arg; it's too long", argname);
        exit(EXIT_FAILURE);
    }
}

#endif /* NCMLIB_COPY_CMDARG_H_ */
