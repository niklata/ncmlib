/*
 * network.c - abstracted task-oriented network functions
 * Time-stamp: <2010-11-01 20:05:35 nk>
 *
 * (c) 2008-2010 Nicholas J. Kain <njkain at gmail dot com>
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

#include <stdlib.h>
#include <assert.h>

/**
 * Given a TCP socket, set that socket to non-blocking mode.
 * @param fd socket that will be set to non-blocking mode
 */
void tcp_set_sock_nonblock(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/**
 * Attempts to connect via tcp to a host.  WARNING: addrs will be freed by
 * this function.
 *
 * @param name Pretty-printable name of the server to which we will connect.
 * @param addrs GSList* of dns_lookup_result_t* of addresses which belong to
 *         the hostname.  This argument should be readily available to
 *         any function that is a callback from dns_lookup().  NOTE: This
 *         pointer will be freed by this function.
 * @param port Port to which we will connect.
 * @return the file descriptor of the new socket, or -1 on failure
 */
int tcp_client_socket(char *name, GSList *addrs, unsigned int port)
{
    GSList *p;
    dns_lookup_result_t *addr;
    int fd = -1, ret, opt = 1;
    int family = AF_INET + AF_INET6; /* theoretical portability hack */

    if (!addrs || !name)
        goto fail;

    for (p = addrs; p != NULL; p = p->next) {
        addr = p->data;
        if (family != addr->family) {
            if (fd >= 0)
                close(fd);
            fd = socket(addr->family, SOCK_STREAM, 0);
            if (fd < 0) {
                fprintf(stderr, "%s - socket(): %s", name, strerror(errno));
                continue;
            }
            ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
            if (ret)
                fprintf(stderr, "%s - setsockopt(): %s", name, strerror(errno));
            ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof opt);
            if (ret)
                fprintf(stderr, "%s - setsockopt(): %s", name, strerror(errno));
            family = addr->family;
        }

        if (family == AF_INET) {
            struct sockaddr_in sa = {
                .sin_family = family,
                .sin_port = htons(port)
            };
            memcpy(&sa.sin_addr.s_addr, addr->addr, addr->len);

            ret = connect(fd, (struct sockaddr *)&sa, sizeof sa);
        } else if (family == AF_INET6) {
            struct sockaddr_in6 sa = {
                .sin6_family = family,
                .sin6_port = htons(port)
            };
            memcpy(&sa.sin6_addr.s6_addr, addr->addr, addr->len);

            ret = connect(fd, (struct sockaddr *)&sa, sizeof sa);
        } else {
            fprintf(stderr, "%s - unknown address family %d", name, family);
            continue;
        }

        if (!ret)
            goto success;

        fprintf(stderr, "%s - connect(): %s", name, strerror(errno));
    }

    fprintf(stderr, "%s - unable to connect", name);
    if (fd >= 0)
        close(fd);
  fail:
    dns_free_lookup_result(addrs);
    return -1;

  success:
    tcp_set_sock_nonblock(fd);
    dns_free_lookup_result(addrs);

    return fd;
}

/**
 * Sets up a listening socket.
 *
 * @param domain PF_INET or PF_INET6
 * @param port Port on which we will listen.
 * @param backlog Number of connections allowed on incoming queue.
 * @return file descriptor of the new listening socket or -1 on failure
 */
int tcp_server_socket(int domain, unsigned int port, int backlog)
{
    int fd = -1, ret, opt = 1;
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE
    }, *res = NULL;
    char buf[32];

    fd = socket(domain, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "server_socket - socket(): %s", strerror(errno));
		return -1;
    }

    ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
    if (ret) {
        fprintf(stderr, "server_socket - setsockopt(): %s", strerror(errno));
		return -1;
	}

	ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof opt);
    if (ret) {
        fprintf(stderr, "server_socket - setsockopt(): %s", strerror(errno));
		return -1;
	}
    tcp_set_sock_nonblock(fd);

    ret = snprintf(buf, sizeof buf, "%u", port);
    if (ret > sizeof buf) {
        fprintf(stderr, "server_socket: overly long port name %d > %lu",
				ret, sizeof buf);
        close(fd);
		return -1;
    }
    ret = getaddrinfo(NULL, buf, &hints, &res);
    if (ret) {
        fprintf(stderr, "server_socket - getaddrinfo(): %s", strerror(errno));
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    ret = bind(fd, res->ai_addr, res->ai_addrlen);
    if (ret) {
        fprintf(stderr, "server_socket - bind(): %s", strerror(errno));
        close(fd);
        freeaddrinfo(res);
        return -1;
    }

    ret = listen(fd, backlog);
    if (ret) {
        fprintf(stderr, "server_socket - listen(): %s", strerror(errno));
        close(fd);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    return fd;
}

/**
 * Creates a new TCP client connection.
 * @param name Pretty-printable name of the server to which we will connect.
 * @param addrs GSList* of dns_lookup_result_t* of addresses which belong to
 *         the hostname.  This argument should be readily available to
 *         any function that is a callback from dns_lookup().  NOTE: This
 *         pointer will be freed by this function.
 * @param port Port to which we will connect.
 * @return NULL on failure or a pointer to the newly allocated connection
 */
net_tcp_t *net_tcp_client_new(char *name, GSList *addrs, unsigned int port)
{
    net_tcp_t *tcp;
    int fd;

    if (!name || !addrs)
        return NULL;

    fd = tcp_client_socket(name, addrs, port);
    if (fd == -1)
        return NULL;

    tcp = xmalloc(sizeof net_tcp_t);
    tcp->fd = fd;
    tcp->ref = 1;
    tcp->ssl = NULL;

    return tcp;
}

/**
 * Creates a new TCP server listener.
 * @param domain domain (PF_INET or PF_INET6) for the listening socket
 * @param port port on which the socket will listen for connections
 * @param backlog number of pending connections that may be queued
 * @return NULL on failure or a pointer to the newly allocated listener
 */
net_tcp_t *net_tcp_server_new(int domain, unsigned int port, int backlog)
{
    net_tcp_t *tcp;
    int fd;

    if (domain != PF_INET && domain != PF_INET6) {
        fprintf(stderr, "%s: unknown domain", __func__);
        return NULL;
    }

    fd = tcp_server_socket(domain, port, backlog);
    if (fd == -1)
        return NULL;

    tcp = xmalloc(sizeof net_tcp_t);
    tcp->fd = fd;
    tcp->ref = 1;
    tcp->ssl = NULL;

    return tcp;
}

/**
 * Accepts a connection that has been received by a TCP listener.
 * @param listentcp TCP connection associated with the listener socket
 *                  on which the connection attempt was received
 * @param addr pointer to a buffer where the IP address of the peer will
 *             be stored
 * @param addrlen length of the address buffer in bytes
 * @return NULL on failure or a pointer to the newly allocated connection
 */
net_tcp_t *net_tcp_accept_new(net_tcp_t *listentcp, struct sockaddr *addr,
                              socklen_t *addrlen)
{
    net_tcp_t *tcp;
    int fd;

    if (!listentcp)
        return NULL;

    fd = accept(listentcp->fd, addr, addrlen);
    if (fd == -1) {
        fprintf(stderr, "%s: accept() returned %s", __func__, strerror(errno));
        return NULL;
    }

    tcp_set_sock_nonblock(fd);

    tcp = xmalloc(sizeof net_tcp_t);
    tcp->fd = fd;
    tcp->ref = 1;
    tcp->ssl = NULL;

    return tcp;
}

/**
 * Increases the reference count on a TCP connection.
 * @param tcp TCP connection that will have its reference count incremented
 * @return the new reference count value for the TCP connection
 */
int net_tcp_ref(net_tcp_t *tcp)
{
    if (!tcp)
        return 0;
    return ++tcp->ref;
}

/**
 * Decreases the reference count on a TCP connection.  If the reference
 * count reaches zero, then the connection will be closed and its associated
 * structure will be freed.
 * @param tcp TCP connection that will have its reference count decreased
 * @return the new reference count value for the TCP connection
 */
int net_tcp_del(net_tcp_t *tcp)
{
    int rc = 0;

    if (!tcp)
        return rc;

    rc = --tcp->ref;

    assert(rc >= 0);

    if (rc == 0) {
        if (tcp->ssl) {
            /* if ssl_close fails, we close the socket anyway */
            net_tcp_ssl_close(tcp);
            net_ssl_del(tcp->ssl);
        }
      close_again:
        if ((close(tcp->fd)) == -1) {
            if (errno == EINTR)
                goto close_again;
            else
                fprintf(stderr, "%s: close returned %s",
                        __func__, strerror(errno));
        }
        free(tcp);
    }
    return rc;
}

/**
 * Writes the contents of a byte buffer to a TCP connection.
 * @param tcp TCP connection structure to which data will be written
 * @param buf points to the data that will be written
 * @param len length of the data that will be written in bytes
 * @param written NULL or a pointer to a size_t that will contain the number of
 *                bytes actually written to the connection after net_tcp_write()
 *                returns
 * @note a separate written parameter exists because it is possible that
 *       multiple write operations may be performed and some number of them
 *       succeed at writing characters before a failure is encountered
 * @return 0 on success, -1 on failure, -2 if operation would block (SSL only)
 */
int net_tcp_write(net_tcp_t *tcp, const void *buf, size_t len, size_t *written)
{
    const char *bufr = buf;
    int ret = 0;
    ssize_t t;
    size_t off = 0;

    if (!tcp || !bufr)
        goto out;

    if (tcp->ssl) {
        int r = net_tcp_ssl_write(tcp, bufr, len);
        if (written) {
            if (r > 0)
                *written = r;
            else
                *written = 0;
        }
        if (r > 0)
            return 0;
        return r;
    }

    while (len > 0) {
        t = write(tcp->fd, bufr + off, len);
        if (t == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;
            fprintf(stderr, "%s: write returned %s", __func__, strerror(errno));
            ret = -1;
            goto out;
        }
        off += t;
        len -= t;
    }

  out:
    if (written)
        *written = off;
    return ret;
}

/**
 * Reads data from a TCP connection.
 * @param tcp TCP connection structure from which data will be read
 * @param buf buffer to which the read data will be stored
 * @param len length of the buffer in bytes
 * @return number of characters read on success,
 *         0 if remote server has disconnected, -1 on failure,
 *         -2 if operation would block (SSL only)
 */
int net_tcp_read(net_tcp_t *tcp, void *buf, size_t len)
{
    char *bufr = buf;
    ssize_t t;
    int off = 0;

    if (!tcp || !bufr)
        return 0;

    if (tcp->ssl)
        return net_tcp_ssl_read(tcp, bufr, len);

    while (len > 0) {
        t = read(tcp->fd, bufr + off, len);
        if (t == 0)
            return 0;
        else if (t == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return off;
            if (errno == EINTR)
                continue;
            fprintf(stderr, "%s: read returned %s", __func__, strerror(errno));
            return -1;
        }
        off += t;
        len -= t;
    }
    return off;
}
