/* exec.c - functions to exec a job
 *
 * (c) 2003-2014 Nicholas J. Kain <njkain at gmail dot com>
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

#include <sys/types.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>

#include "defines.h"
#include "exec.h"
#include "malloc.h"
#include "xstrdup.h"
#include "log.h"

void nk_fix_env(uid_t uid, bool chdir_home)
{
    if (clearenv())
        suicide("%s: clearenv failed: %s", __func__, strerror(errno));

    struct passwd *pw = getpwuid(uid);
    if (!pw)
        suicide("%s: user uid %u does not exist.  Not execing.",
                __func__, uid);

    char uids[20];
    ssize_t snlen = snprintf(uids, sizeof uids, "%i", uid);
    if (snlen < 0 || (size_t)snlen <= sizeof uids)
        suicide("%s: UID was truncated (%d).  Not execing.", __func__, snlen);
    if (setenv("UID", uids, 1))
        goto fail_fix_env;

    if (setenv("USER", pw->pw_name, 1))
        goto fail_fix_env;
    if (setenv("USERNAME", pw->pw_name, 1))
        goto fail_fix_env;
    if (setenv("LOGNAME", pw->pw_name, 1))
        goto fail_fix_env;

    if (setenv("HOME", pw->pw_dir, 1))
        goto fail_fix_env;
    if (setenv("PWD", pw->pw_dir, 1))
        goto fail_fix_env;

    if (chdir_home) {
        if (chdir(pw->pw_dir))
            suicide("%s: failed to chdir to uid %u's homedir.  Not execing.",
                    __func__, uid);
    } else {
        if (chdir("/"))
            suicide("%s: failed to chdir to root directory.  Not execing.",
                    __func__);
    }

    if (setenv("SHELL", pw->pw_shell, 1))
        goto fail_fix_env;
    if (setenv("PATH", DEFAULT_PATH, 1))
        goto fail_fix_env;
    return;
fail_fix_env:
    suicide("%s: failed to sanitize environment.  Not execing.", __func__);
}

// Not re-entrant or thread-safe.
void nk_execute(const char *command, const char *args)
{
    static char *argv[MAX_ARGS];
    static size_t n;

    /* free memory used on previous execution */
    for (size_t m = 0; m < n; m++)
        free(argv[m]);
    n = 0;

    if (!command)
        return;

    /* strip the path from the command name and store in cmdname */
    const char *p = strrchr(command, '/');
    argv[0] = xstrdup(p ? p + 1 : command);

    /* decompose args into argv */
    p = args;
    for (n = 1;; p = strchr(p, ' '), n++) {
        if (!p || n > (MAX_ARGS - 2)) {
            argv[n] = NULL;
            break;
        }
        if (n != 1)
            p++; /* skip the space */
        char *q = strchr(p, ' ');
        if (!q)
            q = strchr(p, '\0');
        size_t len = q - p + 1;
        if (len > INT_MAX) {
            log_error("%s argument n=%zu length is too long", __func__, n);
            return;
        }
        argv[n] = xmalloc(len);
        ssize_t snlen = snprintf(argv[n], len, "%.*s", (int)(len - 1), p);
        if (snlen < 0 || (size_t)snlen >= len) {
            log_error("%s: argument n=%zu would truncate.  Not execing.",
                      __func__, n);
            return;
        }
    }

    execv(command, argv);
}
