/* exec.c - functions to exec a job
 *
 * (c) 2003-2016 Nicholas J. Kain <njkain at gmail dot com>
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
#include "nk/exec.h"

#define DEFAULT_PATH "/bin:/usr/bin:/usr/local/bin"
#define MAX_ARGS 256
#define MAX_ARGBUF 4096

#define NK_GEN_ENV(GEN_STR, ...) do { \
        if (env_offset >= envlen) return -3; \
        ssize_t snlen = snprintf(envbuf, envbuflen, GEN_STR "0", __VA_ARGS__); \
        if (snlen < 0 || (size_t)snlen >= envbuflen) return -2; \
        if (snlen > 0) envbuf[snlen-1] = 0; \
        env[env_offset++] = envbuf; envbuf += snlen; envbuflen -= snlen; \
    } while (0)

/*
 * uid: userid of the user account that the environment will constructed for
 * chroot_path: path where the environment will be chrooted or NULL if no chroot
 * env: array of character pointers that will be filled in with the new environment
 * envlen: number of character pointers available in env; a terminal '0' ptr must be available
 * envbuf: character buffer that will be used for storing state associated with env
 * envbuflen: number of available characters in envbuf for use
 *
 * returns:
 * 0 on success
 * -1 if an account for uid does not exist
 * -2 if there is not enough space in envbuf for the generated environment
 * -3 if there is not enough space in env for the generated environment
 * -4 if chdir to homedir or rootdir failed
 */
int nk_generate_env(uid_t uid, const char *chroot_path, char *env[], size_t envlen,
                    char *envbuf, size_t envbuflen)
{
    char pw_strs[1024];
    struct passwd pw_s;
    struct passwd *pw;
    int pwr = getpwuid_r(uid, &pw_s, pw_strs, sizeof pw_strs, &pw);
    if (pwr || !pw) return -1;

    size_t env_offset = 0;
    if (envlen-- < 1)// So we don't have to account for the terminal NULL
        return -3;

    NK_GEN_ENV("UID=%i", uid);
    NK_GEN_ENV("USER=%s", pw->pw_name);
    NK_GEN_ENV("USERNAME=%s", pw->pw_name);
    NK_GEN_ENV("LOGNAME=%s", pw->pw_name);
    NK_GEN_ENV("HOME=%s", pw->pw_dir);
    NK_GEN_ENV("SHELL=%s", pw->pw_shell);
    NK_GEN_ENV("PATH=%s", DEFAULT_PATH);
    NK_GEN_ENV("PWD=%s", !chroot_path ? pw->pw_dir : "/");
    if (chroot_path && chroot(chroot_path)) return -4;
    if (chdir(chroot_path ? chroot_path : "/")) return -4;

    env[env_offset] = 0;
    return 0;
}

#define NK_GEN_ARG(GEN_STR, ...) do { \
        ssize_t snlen = snprintf(argbuf, argbuflen, GEN_STR "0", __VA_ARGS__); \
        if (snlen < 0 || (size_t)snlen >= argbuflen) { \
            const char errstr[] = "nk_execute: constructing argument list failed\n"; \
            write(STDERR_FILENO, errstr, sizeof errstr); \
            _Exit(EXIT_FAILURE); \
        } \
        if (snlen > 0) argbuf[snlen-1] = 0; \
        argv[curv] = argbuf; argv[++curv] = NULL; \
        argbuf += snlen; argbuflen -= snlen; \
    } while (0)

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
#endif
void __attribute__((noreturn))
nk_execute(const char *command, const char *args, char * const envp[])
{
    char *argv[MAX_ARGS];
    char argbuf_s[MAX_ARGBUF];
    char *argbuf = argbuf_s;
    size_t curv = 0;
    size_t argbuflen = sizeof argbuf_s;

    if (!command)
        _Exit(EXIT_SUCCESS);

    // strip the path from the command name and set argv[0]
    const char *p = strrchr(command, '/');
    NK_GEN_ARG("%s", p ? p + 1 : command);

    if (args) {
        p = args;
        const char *q = args;
        bool squote = false, dquote = false, atend = false;
        for (;; ++p) {
            switch (*p) {
            default: continue;
            case '\0':
                 atend = true;
                 goto endarg;
            case ' ':
                if (!squote && !dquote)
                    goto endarg;
                continue;
            case '\'':
                if (!dquote)
                    squote = !squote;
                continue;
            case '"':
                if (!squote)
                    dquote = !dquote;
                continue;
            }
endarg:
            {
                if (p == q) break;
                // Push an argument.
                if (q > p) {
                    const char errstr[] = "nk_execute: argument length too long\n";
                    write(STDERR_FILENO, errstr, sizeof errstr);
                    _Exit(EXIT_FAILURE);
                }
                const size_t len = p - q;
                NK_GEN_ARG("%.*s", (int)len, q);
                q = p + 1;
                if (atend || curv >= (MAX_ARGS - 1))
                    break;
            }
        }
    }
    execve(command, argv, envp);
    {
        const char errstr[] = "nk_execute: execve failed\n";
        write(STDERR_FILENO, errstr, sizeof errstr);
        _Exit(EXIT_FAILURE);
    }
}
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

