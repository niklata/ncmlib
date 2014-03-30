/* privilege.c - uid/gid, chroot, and capability handling
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

#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#ifdef NCM_USE_CAPABILITY
#include <sys/capability.h>
#include <sys/prctl.h>
#endif

#include "privilege.h"
#include "defines.h"
#include "log.h"

void nk_set_chroot(const char *chroot_dir)
{
    if (chroot(chroot_dir))
        suicide("%s: chroot('%s') failed: %s", __func__, chroot_dir,
                strerror(errno));
    if (chdir("/"))
        suicide("%s: chdir('/') failed: %s", __func__, strerror(errno));
}

void nk_set_uidgid(uid_t uid, gid_t gid)
{
    if (setgroups(1, &gid))
        suicide("%s: setgroups failed: %s", __func__, strerror(errno));
    if (setresgid(gid, gid, gid))
        suicide("%s: setresgid failed: %s", __func__, strerror(errno));
    if (setresuid(uid, uid, uid))
        suicide("%s: setresuid failed: %s", __func__, strerror(errno));
    if (getgid() != gid || getuid() != uid)
        suicide("%s: failed because the OS or libc is broken", __func__);
}

#ifdef NCM_USE_CAPABILITY
void nk_set_capability(const char *captxt)
{
    if (!captxt)
        return;
    if (prctl(PR_SET_KEEPCAPS, 1))
        suicide("%s: prctl failed: %s", __func__, strerror(errno));
    cap_t caps = cap_from_text(captxt);
    if (!caps)
        suicide("%s: cap_from_text failed: %s", __func__, strerror(errno));
    if (cap_set_proc(caps))
        suicide("%s: cap_set_proc failed: %s", __func__, strerror(errno));
    if (cap_free(caps))
        suicide("%s: cap_free failed: %s", __func__, strerror(errno));
}
#endif
