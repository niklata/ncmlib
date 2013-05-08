/*
 * ssl.c - abstracted task-oriented network SSL functions
 * Time-stamp: <2010-11-01 19:45:29 nk>
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

#ifndef NCM_SSL_H_
#define NCM_SSL_H_

#include "network.h"

void ssl_init(void);
void net_ssl_del(net_ssl_t *ssl);
int net_tcp_ssl_close(net_tcp_t *tcp);
int net_tcp_enable_ssl_client(net_tcp_t *tcp, const char *certpath);
int net_tcp_enable_ssl_server(net_tcp_t *tcp, const char *certpath,
                              net_ssl_cb_fn_t cb, void *cb_data, int verify);
int net_tcp_ssl_read(net_tcp_t *tcp, void *buf, size_t len);
int net_tcp_ssl_write(net_tcp_t *tcp, const void *buf, size_t len);

#endif /* NCM_SSL_H_ */
