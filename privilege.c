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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#ifdef __linux__
#include <sys/capability.h>
#include <sys/prctl.h>
#endif
#include "nk/privilege.h"
#include "nk/log.h"

void nk_set_chroot(const char *chroot_dir)
{
    if (chroot(chroot_dir))
        suicide("%s: chroot('%s') failed: %s", __func__, chroot_dir,
                strerror(errno));
    if (chdir("/"))
        suicide("%s: chdir('/') failed: %s", __func__, strerror(errno));
}

#ifdef NK_USE_CAPABILITY
static void nk_set_capability_prologue(const char *captxt)
{
    if (!captxt)
        return;
    if (prctl(PR_SET_KEEPCAPS, 1))
        suicide("%s: prctl failed: %s", __func__, strerror(errno));
}
static void nk_set_capability_epilogue(const char *captxt)
{
    if (!captxt)
        return;
    cap_t caps = cap_from_text(captxt);
    if (!caps)
        suicide("%s: cap_from_text failed: %s", __func__, strerror(errno));
    if (cap_set_proc(caps))
        suicide("%s: cap_set_proc failed: %s", __func__, strerror(errno));
    if (cap_free(caps))
        suicide("%s: cap_free failed: %s", __func__, strerror(errno));
}
#else
static void nk_set_capability_prologue(const char *captxt) { (void)captxt; }
static void nk_set_capability_epilogue(const char *captxt) { (void)captxt; }
#endif

#ifdef NK_USE_NO_NEW_PRIVS
static void nk_set_no_new_privs(void)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        suicide("%s: prctl failed: %s", __func__, strerror(errno));
}
#else
static void nk_set_no_new_privs(void) {}
#endif

void nk_set_uidgid(uid_t uid, gid_t gid, const char *captxt)
{
    nk_set_capability_prologue(captxt);
    if (setgroups(1, &gid))
        suicide("%s: setgroups failed: %s", __func__, strerror(errno));
    if (setresgid(gid, gid, gid))
        suicide("%s: setresgid failed: %s", __func__, strerror(errno));
    if (setresuid(uid, uid, uid))
        suicide("%s: setresuid failed: %s", __func__, strerror(errno));
    uid_t ruid, euid, suid;
    if (getresuid(&ruid, &euid, &suid))
        suicide("%s: getresuid failed: %s", __func__, strerror(errno));
    if (ruid != uid || euid != uid || suid != uid)
        suicide("%s: getresuid failed; the OS or libc is broken", __func__);
    gid_t rgid, egid, sgid;
    if (getresgid(&rgid, &egid, &sgid))
        suicide("%s: getresgid failed: %s", __func__, strerror(errno));
    if (rgid != gid || egid != gid || sgid != gid)
        suicide("%s: getresgid failed; the OS or libc is broken", __func__);
    if (setreuid(-1, 0) == 0)
        suicide("%s: OS or libc broken; able to restore privilege after drop",
                __func__);
    nk_set_capability_epilogue(captxt);
    nk_set_no_new_privs();
}

int nk_uidgidbyname(const char *username, uid_t *uid, gid_t *gid)
{
    if (!username)
        return -1;
    struct passwd *pws = getpwnam(username);
    if (!pws) {
        for (size_t i = 0; username[i]; ++i) {
            if (!isdigit(username[i]))
                return -1;
        }
        char *p;
        long lt = strtol(username, &p, 10);
        if (errno == ERANGE && (lt == LONG_MIN || lt == LONG_MAX))
            return -1;
        if (lt < 0 || lt > (long)UINT_MAX)
            return -1;
        if (p == username)
            return -1;
        pws = getpwuid((uid_t)lt);
        if (!pws)
            return -1;
    }
    if (gid)
        *gid = pws->pw_gid;
    if (uid)
        *uid = pws->pw_uid;
    return 0;
}

int nk_gidbyname(const char *groupname, gid_t *gid)
{
    if (!groupname)
        return -1;
    struct group *grp = getgrnam(groupname);
    if (!grp) {
        for (size_t i = 0; groupname[i]; ++i) {
            if (!isdigit(groupname[i]))
                return -1;
        }
        char *p;
        long lt = strtol(groupname, &p, 10);
        if (errno == ERANGE && (lt == LONG_MIN || lt == LONG_MAX))
            return -1;
        if (lt < 0 || lt > (long)UINT_MAX)
            return -1;
        if (p == groupname)
            return -1;
        grp = getgrgid((gid_t)lt);
        if (!grp)
            return -1;
    }
    if (gid)
        return grp->gr_gid;
    return 0;
}

