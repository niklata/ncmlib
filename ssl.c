/*
 * ssl.c - abstracted task-oriented network SSL functions
 * Time-stamp: <2010-11-01 19:58:11 nk>
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
#include "network.h"

/**
 * @todo Global ctx may not be appropriate -- it depends on how the
 * authentication and certificate associations are handled in OpenSSL.
 */
static SSL_CTX *ctx;
static SSL_CTX *svr_ctx;

/**
 * Prints messages from the OpenSSL error stack.
 * @param caller name of the calling function; typically __func__
 * @param func name of the OpenSSL function most recently called
 */
static void _ssl_print_errorstack(const char *caller, const char *func)
{
    char buf[128];

    assert(func);
    ERR_error_string_n(ERR_get_error(), buf, sizeof buf);
    fprintf(stderr, "%s: %s() error - %s", caller, func, buf);
}
#define ssl_print_errorstack(a) _ssl_print_errorstack(__func__, (a))

/**
 * Initializes required state for SSL connections.
 */
void ssl_init(void)
{
    SSL_load_error_strings();
    SSL_library_init();

    ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) {
        ssl_print_errorstack("SSL_CTX_new");
        return;
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

    svr_ctx = SSL_CTX_new(SSLv23_server_method());
    if (!svr_ctx) {
        ssl_print_errorstack("SSL_CTX_new");
        return;
    }
    SSL_CTX_set_options(svr_ctx, SSL_OP_NO_SSLv2);
}

/**
 * Creates a new SSL connection structure.
 * @param ssl OpenSSL connection structure that will be associated
 * @return newly allocated SSL connection structure
 */
static net_ssl_t *net_ssl_new(SSL *ssl)
{
    net_ssl_t *nssl;

    assert(ctx);
    assert(ssl);

    nssl = calloc(1, sizeof net_ssl_t);
    nssl->ssl = ssl;
    nssl->state = NET_SSL_NULL;
    return nssl;
}

/**
 * Frees a SSL connection structure.
 * @param ssl SSL connection structure that will be freed
 */
void net_ssl_del(net_ssl_t *ssl)
{
    if (!ssl)
        return;
    if (ssl->ssl)
        SSL_free(ssl->ssl);
    free(ssl);
}

/**
 * Closes an established SSL connection.
 * @param tcp TCP connection structure that contains that SSL connection
 *            that will be closed
 * @return 0 on success, 1 if call would block (repeat later), -1 on failure
 *         if return is 1, then ssl->state is set to NET_SSL_CLOSING and
 *         must be completed by trying to read or write to the tcp stream
 *         once again
 */
int net_tcp_ssl_close(net_tcp_t *tcp)
{
    int r;

    assert(tcp);
    assert(tcp->ssl);

    if (tcp->ssl->state < NET_SSL_CONNECTED) {
        net_ssl_del(tcp->ssl);
        tcp->ssl = NULL;
        return 0;
    }
    if (tcp->ssl->state > NET_SSL_CLOSING)
        return 0;
    tcp->ssl->state = NET_SSL_CLOSING;
    r = SSL_shutdown(tcp->ssl->ssl);
    if (r == 0) {
        /* Sent "close notify" alert; must repeat to fully shutdown. */
        return 1;
    } else if (r == 1) {
        /* Received "close notify" alert; shutdown complete. */
        tcp->ssl->state = NET_SSL_CLOSED;
        return 0;
    } else {
        int err = SSL_get_error(tcp->ssl->ssl, r);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            /* operation would block -- complete via callback */
            return 1;
        } else {
            char buf[128];

            ERR_error_string_n(ERR_get_error(), buf, sizeof buf);
            fprintf(stderr, "%s: SSL_shutdown() error - %s", __func__, buf);
        }
    }
    return -1;
}

/**
 *
 * @return 0 on success, -1 on failure
 */
static int ssl_verify_cert(net_tcp_t *tcp)
{
    X509 *cert;
    char subject[256];
    char issuer[256];

    assert(tcp);
    assert(tcp->ssl);

    cert = SSL_get_peer_certificate(tcp->ssl->ssl);
    if (!cert) {
        fprintf(stderr, "%s: peer sent no certificate", __func__);
        return -1;
    }
    X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof subject);
    X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof issuer);
    fprintf(stdout, "%s: subject = '%s'", __func__, subject);
    fprintf(stdout, "%s: issuer = '%s'", __func__, issuer);
    X509_free(cert);
    return 0;
}

/**
 * Low level function that negotiates a SSL connection on an established TCP
 * connection.
 * @param tcp TCP connection structure on which the SSL connection will
 *            be made
 * @return 0 on success, 1 if call would block (repeat later), -1 on failure
 *         if return is 1, then ssl->state is set to NET_SSL_CONNECTING and
 *         must be completed by trying to read or write to the tcp stream
 *         once again
 */
static int net_tcp_ssl_connect(net_tcp_t *tcp)
{
    int r;

    assert(tcp);
    assert(tcp->ssl);

    if (tcp->ssl->state < NET_SSL_CONNECTING)
        tcp->ssl->state = NET_SSL_CONNECTING;
    else if (tcp->ssl->state > NET_SSL_CONNECTING)
        return 0;

    r = SSL_connect(tcp->ssl->ssl);
    if (r == 0) {
        tcp->ssl->state = NET_SSL_CLOSED;
        ssl_print_errorstack("SSL_connect");
        return -1;
    } else if (r < 0) {
        int err = SSL_get_error(tcp->ssl->ssl, r);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            /* operation would block -- complete via callback */
            return 1;
        }
        else {
            char buf[128];

            ERR_error_string_n(ERR_get_error(), buf, sizeof buf);
            fprintf(stderr, "%s: SSL_connect() error - %s", __func__, buf);
        }
        tcp->ssl->state = NET_SSL_FAILED;
        return -1;
    }
    ssl_verify_cert(tcp);
    tcp->ssl->state = NET_SSL_CONNECTED;
    return 0;
}

/**
 * Enables SSL on an established TCP client connection.
 * @param tcp TCP connection structure on which SSL will be enabled
 * @param certpath NULL or filesystem path to the SSL certificate and public
 *                 key (in pem format) that will be provided to the SSL peer
 * @return 0 on success, -1 on failure
 */
int net_tcp_enable_ssl_client(net_tcp_t *tcp, const char *certpath)
{
    SSL *ssl;
    int r;

    if (!tcp)
        return -1;
    if (tcp->ssl) {
        fprintf(stderr,
                "%s: tcp structure already has an associated SSL session",
                __func__);
        return -1;
    }

    ssl = SSL_new(ctx);
    if (!ssl) {
        ssl_print_errorstack("SSL_new");
        return -1;
    }

    r = SSL_set_fd(ssl, tcp->fd);
    if (!r) {
        ssl_print_errorstack("SSL_set_fd");
        SSL_free(ssl);
        return -1;
    }

    if (certpath) {
        r = SSL_use_certificate_file(ssl, certpath, SSL_FILETYPE_PEM);
        if (!r) {
            ssl_print_errorstack("SSL_use_certificate_chain_file");
            SSL_free(ssl);
            return -1;
        }
        r = SSL_use_PrivateKey_file(ssl, certpath, SSL_FILETYPE_PEM);
        if (!r) {
            ssl_print_errorstack("SSL_use_PrivateKey_file");
            SSL_free(ssl);
            return -1;
        }
    }

    tcp->ssl = net_ssl_new(ssl);
    tcp->ssl->type = NET_SSL_CLIENT;
    r = net_tcp_ssl_connect(tcp);
    if (r == -1) {
        net_ssl_del(tcp->ssl);
        tcp->ssl = NULL;
        return -1;
    } else if (r == 1) {
        /* connect would block -- next r/w event will complete the connect */
        return 0;
    }

    return 0;
}

/**
 * Low level function that accepts a SSL connection on an established TCP
 * connection.
 * @param tcp TCP connection structure on which the SSL connection will
 *            be accepted
 * @return 0 on success, 1 if call would block (repeat later), -1 on failure
 *         if return is 1, then ssl->state is set to NET_SSL_CONNECTING and
 *         must be completed by trying to read or write to the tcp stream
 *         once again
 */
static int net_tcp_ssl_accept(net_tcp_t *tcp)
{
    int r;

    assert(tcp);
    assert(tcp->ssl);

    if (tcp->ssl->state < NET_SSL_CONNECTING)
        tcp->ssl->state = NET_SSL_CONNECTING;
    else if (tcp->ssl->state > NET_SSL_CONNECTING)
        return 0;

    r = SSL_accept(tcp->ssl->ssl);
    if (r == 0) {
        tcp->ssl->state = NET_SSL_CLOSED;
        ssl_print_errorstack("SSL_accept");
        return -1;
    } else if (r < 0) {
        int err = SSL_get_error(tcp->ssl->ssl, r);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            /* operation would block -- complete via callback */
            return 1;
        }
        else {
            char buf[128];

            ERR_error_string_n(ERR_get_error(), buf, sizeof buf);
            fprintf(stderr, "%s: SSL_accept() error - %s", __func__, buf);
        }
        tcp->ssl->state = NET_SSL_FAILED;
        return -1;
    }
    ssl_verify_cert(tcp);
    tcp->ssl->state = NET_SSL_CONNECTED;
    if (tcp->ssl->cb)
        tcp->ssl->cb(tcp, tcp->ssl->cb_data);
    return 0;
}

static int ssl_verify_server_fn(int preverify_ok, X509_STORE_CTX *ctx)
{
    /* XXX: perform actual verification of the client's certificate */
    return 1;
}

/**
 * Enables SSL on an established TCP server connection (using _accept()).
 * @param tcp TCP connection structure on which SSL will be enabled
 * @param certpath filesystem path to the certificate file and private key
 *                 that will be used for the connection
 * @param cb NULL or pointer to a function of type net_ssl_cb_fn_t that will be
 *           called once the SSL connection has been negotiated and accepted
 * @param cb_data user-provided pointer that will be passed to cb
 * @param verify if 0 then do not verify the peer, otherwise authenticate
 *               the peer using its certificate
 * @return 0 on success, -1 on failure
 */
int net_tcp_enable_ssl_server(net_tcp_t *tcp, const char *certpath,
                              net_ssl_cb_fn_t cb, void *cb_data, int verify)
{
    SSL *ssl;
    int r;

    if (!tcp)
        return -1;
    if (!certpath) {
        fprintf(stderr, "%s: certpath cannot be NULL for server SSL sessions",
                  __func__);
        return -1;
    }
    if (tcp->ssl) {
        fprintf(stderr,
                "%s: tcp structure already has an associated SSL session",
                __func__);
        return -1;
    }

    ssl = SSL_new(svr_ctx);
    if (!ssl) {
        ssl_print_errorstack("SSL_new");
        return -1;
    }

    r = SSL_set_fd(ssl, tcp->fd);
    if (!r) {
        ssl_print_errorstack("SSL_set_fd");
        SSL_free(ssl);
        return -1;
    }

    r = SSL_use_certificate_file(ssl, certpath, SSL_FILETYPE_PEM);
    if (!r) {
        ssl_print_errorstack("SSL_use_certificate_chain_file");
        SSL_free(ssl);
        return -1;
    }
    r = SSL_use_PrivateKey_file(ssl, certpath, SSL_FILETYPE_PEM);
    if (!r) {
        ssl_print_errorstack("SSL_use_PrivateKey_file");
        SSL_free(ssl);
        return -1;
    }
    if (!SSL_check_private_key(ssl)) {
        fprintf(stderr, "SSL_check_private_key: private key is bad");
        SSL_free(ssl);
        return -1;
    }

    tcp->ssl = net_ssl_new(ssl);
    tcp->ssl->type = NET_SSL_SERVER;
    if (cb) {
        tcp->ssl->cb = cb;
        tcp->ssl->cb_data = cb_data;
    }
    if (verify) {
        SSL_set_verify(ssl, SSL_VERIFY_PEER, ssl_verify_server_fn);
        SSL_set_verify_depth(ssl, 0);
        tcp->ssl->verify = 1;
    }

    r = net_tcp_ssl_accept(tcp);
    if (r == -1) {
        net_ssl_del(tcp->ssl);
        tcp->ssl = NULL;
        return -1;
    } else if (r == 1) {
        /* connect would block -- next r/w event will complete the connect */
        return 0;
    }

    return 0;
}

/**
 * Checks the internal state of a SSL connection to see if it's possible
 * to read or write on the connection.
 * @param tcp TCP connection structure where SSL state will be checked
 * @return 0 indicates ok to proceed, -1 indicates fatal error, -2 indicates
 *         transient error
 */
static inline int ssl_state_allow_rw(net_tcp_t *tcp)
{
    int r;

    switch (tcp->ssl->state) {
        case NET_SSL_NULL:
        case NET_SSL_CONNECTING:
            switch (tcp->ssl->type) {
                case NET_SSL_CLIENT:
                    r = net_tcp_ssl_connect(tcp);
                    break;
                case NET_SSL_SERVER:
                    r = net_tcp_ssl_accept(tcp);
                    break;
                default:
                    r = -1;
                    break;
            }
            if (r == -1) {
                net_ssl_del(tcp->ssl);
                tcp->ssl = NULL;
                return -1;
            } else if (r == 1) {
                /* connect would block -- next r/w event will complete it*/
                return -2;
            }
            break;
        case NET_SSL_CONNECTED:
        case NET_SSL_OK:
            break;
        case NET_SSL_CLOSING:
        case NET_SSL_CLOSED:
        case NET_SSL_FAILED:
            return -1;
    }
    return 0;
}

/**
 * Reads data from a SSL-protected connection.
 * @param tcp SSL-protected TCP connection structure from which data will
 *            be read
 * @param buf buffer to which the read data will be stored
 * @param len length of the buffer in bytes
 * @return a value > 0 indicates the number of bytes read into the buffer;
 *         0 indicates the remote peer shut down the SSL link;
 *         -1 on fatal error, -2 on transient error (call should be retried)
 */
int net_tcp_ssl_read(net_tcp_t *tcp, void *buf, size_t len)
{
    char *bufr = buf;
    int r, rbytes = 0;

    if (!tcp || !tcp->ssl)
        return -1;

    r = ssl_state_allow_rw(tcp);
    if (r < 0)
        return r;

  again:
    r = SSL_read(tcp->ssl->ssl, bufr, len);
    if (r == 0) {
        r = net_tcp_ssl_close(tcp);
        if (r == 1)
            return -2;
        else
            return -1;
    } else if (r < 0) {
        r = SSL_get_error(tcp->ssl->ssl, r);
        if (r == SSL_ERROR_WANT_READ || r == SSL_ERROR_WANT_WRITE) {
            /* if READ, handshake is in progress during a read, and SSL_pending
             * doesn't work during handshakes, so we directly bail out
             * to avoid a busy loop */
            return -2;
        } else if (r == SSL_ERROR_ZERO_RETURN) {
            /* remote end unexpectedly dropped connection */
            r = net_tcp_ssl_close(tcp);
            if (r == 1)
                return -2;
            else
                return -1;
        } else {
            char bt[128];

            ERR_error_string_n(ERR_get_error(), bt, sizeof bt);
            fprintf(stderr, "%s: SSL_read() error - %s", __func__, bt);
            return -1;
        }
    }
    rbytes += r;

    r = SSL_pending(tcp->ssl->ssl);
    if (r > 0) {
        bufr += rbytes;
        len -= rbytes;
        if (len < r)
            return rbytes;
        else
            goto again;
    }
    return rbytes;
}

/**
 * Writes data on a SSL-protected connection.
 * @param tcp SSL-protected TCP connection structure to which data will be
 *            written
 * @param buf points to the data that will be written
 * @param len length of the data that will be written in bytes
 * @return a value > 0 indicates the number of bytes written from the buffer;
 *         0 indicates the remote peer shut down the SSL link;
 *         -1 on fatal error, -2 on transient error (call should be retried)
 */
int net_tcp_ssl_write(net_tcp_t *tcp, const void *buf, size_t len)
{
    const char *bufr = buf;
    int r;

    if (!tcp || !tcp->ssl)
        return -1;

    r = ssl_state_allow_rw(tcp);
    if (r < 0)
        return r;

    r = SSL_write(tcp->ssl->ssl, bufr, len);
    if (r == 0) {
        r = net_tcp_ssl_close(tcp);
        if (r == 1)
            return -2;
        else
            return -1;
    } else if (r < 0) {
        r = SSL_get_error(tcp->ssl->ssl, r);
        if (r == SSL_ERROR_WANT_READ || r == SSL_ERROR_WANT_WRITE) {
            return -2;
        } else if (r == SSL_ERROR_ZERO_RETURN) {
            /* remote end unexpectedly dropped connection */
            r = net_tcp_ssl_close(tcp);
            if (r == 1)
                return -2;
            else
                return -1;
        } else {
            char bt[128];

            ERR_error_string_n(ERR_get_error(), bt, sizeof bt);
            fprintf(stderr, "%s: SSL_write() error - %s", __func__, bt);
            return -1;
        }
    }

    return r;
}
