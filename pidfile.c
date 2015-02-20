/* pidfile.c - process id file functions
 *
 * (c) 2003-2015 Nicholas J. Kain <njkain at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include "nk/pidfile.h"
#include "nk/log.h"

void write_pid(const char file[static 1]) {
    FILE *f = fopen(file, "w");
    if (!f)
        suicide("%s: fopen(%s) failed: %s", __func__, file, strerror(errno));
    pid_t pid = getpid();
    int r = fprintf(f, "%u", pid);
    if (r < 0)
        suicide("%s: fprintf(%s, %u) failed: %s", __func__, file, pid,
                strerror(errno));
    if (fclose(f))
        suicide("%s: fclose(%s) failed: %s", __func__, file, strerror(errno));
}

/* Return 0 on success, -1 on failure. */
int file_exists(const char file[static 1], const char mode[static 1])
{
    FILE *f = fopen(file, mode);
    if (!f) {
        log_line("%s: fopen(%s, %o) failed: %s", __func__, file, mode,
                 strerror(errno));
        return -1;
    }
    if (fclose(f))
        log_line("%s: fclose(%s) failed: %s", __func__, file, strerror(errno));
    return 0;
}
