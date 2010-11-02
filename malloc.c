#include <stdlib.h>
#include "log.h"

void *xmalloc(size_t size) {
        void *ret;

        ret = malloc(size);
        if (ret == NULL)
                suicide("FATAL - malloc() failed\n");
        return ret;
}
