/*
 * network.c - abstracted task-oriented network functions
 *
 * (c) 2008-2014 Nicholas J. Kain <njkain at gmail dot com>
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
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <netdb.h>

#include "network.h"
#include "malloc.h"

/**
 * Given a TCP socket, set that socket to non-blocking mode.
 * @param fd socket that will be set to non-blocking mode
 * @return 0 on success, -1 on failure
 */
int tcp_set_sock_nonblock(int fd)
{
    int ret = 0, flags;

    flags = fcntl(fd, F_GETFL);
    ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (ret == -1)
        return -1;
    return 0;
}

/**
 * Sets up listening sockets associated with a single address and port.
 *
 * @param node string describing host or address to which we will bind;
 *             NULL means to bind to all available addresses
 * @param port Port on which we will listen.
 * @param backlog Number of connections allowed on incoming queue.
 * @return NULL if no listening fds are created; otherwise, an array of
 *         integers.  The first integer in the array will be the total
 *         number of elements in the array.  Each subsequent integer
 *         will be the value of a fd listening on the specified node.
 *         This array should be freed with free().
 */
int *tcp_server_socket(const char *node, unsigned int port, int backlog)
{
    int ret, opt = 1, *fdarray;
    size_t sret;
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE /* address suitable for bind */
    }, *result = NULL;
    char buf[32];

    sret = snprintf(buf, sizeof buf, "%u", port);
    if (sret > sizeof buf) {
        fprintf(stderr, "server_socket: overly long port name %zd > %zd",
				sret, sizeof buf);
		return NULL;
    }
    ret = getaddrinfo(node, buf, &hints, &result);
    if (ret) {
        fprintf(stderr, "server_socket - getaddrinfo(): %s", strerror(errno));
        freeaddrinfo(result);
        return NULL;
    }

    int numfds = 0, fditer = 0;
    for (struct addrinfo *iter = result; iter; iter = iter->ai_next)
        ++numfds;
    if (numfds > 0) {
        fdarray = xmalloc((numfds + 1) * sizeof (int));
        fdarray[fditer++] = numfds + 1;
    } else {
        fprintf(stderr, "server_socket - no addresses to bind");
        return NULL;
    }

    for (struct addrinfo *iter = result; iter; iter = iter->ai_next) {
        int fd = socket(iter->ai_family, iter->ai_socktype, 0);
        if (fd < 0) {
            fprintf(stderr, "server_socket - socket(): %s", strerror(errno));
            continue;
        }

        ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
        if (ret) {
            fprintf(stderr, "server_socket - setsockopt(): %s", strerror(errno));
            close(fd);
            continue;
        }
        ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof opt);
        if (ret) {
            fprintf(stderr, "server_socket - setsockopt(): %s", strerror(errno));
            close(fd);
            continue;
        }
        ret = tcp_set_sock_nonblock(fd);
        if (ret) {
            fprintf(stderr, "server_socket - fcntl(O_NONBLOCK): %s",
                    strerror(errno));
            close(fd);
            continue;
        }

        ret = bind(fd, iter->ai_addr, iter->ai_addrlen);
        if (ret) {
            fprintf(stderr, "server_socket - bind(): %s", strerror(errno));
            close(fd);
            continue;
        }

        ret = listen(fd, backlog);
        if (ret) {
            fprintf(stderr, "server_socket - listen(): %s", strerror(errno));
            close(fd);
            continue;
        }
        fdarray[fditer++] = fd;
    }

    if (fditer < numfds + 1) {
        fdarray[0] = fditer;
        fdarray = xrealloc(fdarray, fditer);
    }

    freeaddrinfo(result);
    return fdarray;
}
