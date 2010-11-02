/*
 * network.h - abstracted task-oriented network functions
 * Time-stamp: <2010-11-01 20:05:42 nk>
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

#ifndef NCM_NETWORK_H_
#define NCM_NETWORK_H_

#include <sys/socket.h>

typedef enum {
    NET_SSL_TYPENULL = 0,
    NET_SSL_CLIENT,
    NET_SSL_SERVER
} net_ssl_type_t;

typedef enum {
    NET_SSL_NULL = 0, /* structure initialized but nothing else */
    NET_SSL_CONNECTING = 1, /* ssl connection not yet established */
    NET_SSL_CONNECTED = 2, /* ssl connection established */
    NET_SSL_OK, /* ssl connection needs no pending ssl work */
    NET_SSL_CLOSING, /* ssl connection in the process of shutdown/close */
    NET_SSL_CLOSED, /* ssl connection cleanly shut down */
    NET_SSL_FAILED /* ssl connection had a fatal error */
} net_ssl_state_t;

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

typedef void (*net_ssl_cb_fn_t)(void *tcp, void *userdata);

typedef struct {
    SSL *ssl;
    void *cb_data;
    net_ssl_state_t state;
    net_ssl_type_t type;
    net_ssl_cb_fn_t cb;
    unsigned int verify:1;
} net_ssl_t;

/**
 * Opaque structure for a TCP connection.
 */
typedef struct {
    net_ssl_t *ssl;
    int fd;
    int ref;
} net_tcp_t;

void tcp_set_sock_nonblock(int fd);
int tcp_client_socket(char *name, GSList *addrs, unsigned int port);
int tcp_server_socket(int domain, unsigned int port, int backlog);

net_tcp_t *net_tcp_client_new(char *name, GSList *addrs, unsigned int port);
net_tcp_t *net_tcp_server_new(int domain, unsigned int port, int backlog);
net_tcp_t *net_tcp_accept_new(net_tcp_t *listentcp, struct sockaddr *addr,
                              socklen_t *addrlen);

int net_tcp_ref(net_tcp_t *tcp);
int net_tcp_del(net_tcp_t *tcp);
int net_tcp_write(net_tcp_t *tcp, const void *buf, size_t len, size_t *written);
int net_tcp_read(net_tcp_t *tcp, void *buf, size_t len);

#endif /* NCM_NETWORK_H_ */
