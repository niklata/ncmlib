/* chroot.c - chroots jobs and drops privs
 *
 * (c) 2005-2014 Nicholas J. Kain <njkain at gmail dot com>
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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#include "chroot.h"
#include "defines.h"
#include "log.h"

void imprison(const char *chroot_dir)
{
    if (chroot(chroot_dir)) {
        log_error("%s: chroot('%s') failed: %s", __func__, chroot_dir,
                  strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (chdir("/")) {
        log_error("%s: chdir('/') failed: %s", __func__, strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void drop_root(uid_t uid, gid_t gid)
{
    if (uid == 0 || gid == 0) {
        log_error("%s: attempt to drop root to root", __func__);
        exit(EXIT_FAILURE);
    }

    if (getgid() != gid) {
        if (setgid(gid)) {
            log_error("%s: setgid failed: %s", __func__, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    if (getuid() != uid) {
        if (setuid(uid)) {
            log_error("%s: setuid failed: %s", __func__, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
}

