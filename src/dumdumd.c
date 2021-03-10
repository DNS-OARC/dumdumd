/*
 * dumdumd - packets sent lightning fast to dev null
 * Copyright (c) 2017, OARC, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdbool.h>

#undef ANYBACKEND

#if defined(HAVE_LIBEV) && defined(HAVE_EV_H)
#undef ANYBACKEND
#define ANYBACKEND 1
#include <ev.h>
#else
#undef HAVE_LIBEV
#endif

#if defined(HAVE_LIBUV) && defined(HAVE_UV_H)
#undef ANYBACKEND
#define ANYBACKEND 1
#include <uv.h>
#else
#undef HAVE_LIBUV
#endif

#ifndef ANYBACKEND
#error "No event library backend found, need at least libev or libuv"
#endif

char* program_name = 0;
#define STATS_INIT { 0, 0, 0, 0, 0 }
struct stats {
    size_t accept;
    size_t accdrop;
    size_t conns;
    size_t bytes;
    size_t pkts;
};
struct stats _stats0 = STATS_INIT;
struct stats _stats = STATS_INIT;

SSL_CTX* ssl_ctx = 0;

struct tls_ctx {
    SSL* ssl;
    BIO* rbio, *wbio;
    bool accepted, close;
};

bool close_conn_after_first = false;

static void usage(void) {
    printf(
        "usage: %s [options] [ip] <port>\n"
        /* -o            description                                                 .*/
        "  -B ackend     Select backend: ev, uv (default)\n"
        "  -u            Use UDP\n"
        "  -t            Use TCP\n"
        "                Using both UDP and TCP if none of the above options are used\n"
        "  -T            Use TLS for TCP, implies TCP (Only in uv)\n"
        "                key.pem cert.pem expected in $PWD\n"
        "  -C            Close connection after first reflect, only applied for\n"
        "                TCP/TLS and if -r is used\n"
        "  -A            Use SO_REUSEADDR on sockets\n"
        "  -R            Use SO_REUSEPORT on sockets\n"
        "  -L <sec>      Use SO_LINGER with the given seconds\n"
        "  -r            Reflect data back to sender (Only in uv)\n"
        "  -h            Print this help and exit\n"
        "  -V            Print version and exit\n",
        program_name
    );
}

static void version(void) {
    printf("%s version " PACKAGE_VERSION "\n", program_name);
}

static inline void stats_cb(void) {
    printf("accept(drop): %lu ( %lu ) conns: %lu pkts: %lu bytes %lu\n",
        _stats.accept,
        _stats.accdrop,
        _stats.conns,
        _stats.pkts,
        _stats.bytes
    );
    _stats = _stats0;
}

static char recvbuf[4*1024*1024];

#ifdef HAVE_LIBEV
static void _ev_stats_cb(struct ev_loop *loop, ev_timer *w, int revents) {
    stats_cb();
}

static void _ev_shutdown_cb(struct ev_loop *loop, ev_io *w, int revents) {
    int fd = w->data - (void*)0;

    if (recv(fd, recvbuf, sizeof(recvbuf), 0) > 0)
        return;

    ev_io_stop(loop, w);
    close(fd);
    free(w); /* TODO: Delayed free maybe? */
}

static void _ev_recv_cb(struct ev_loop *loop, ev_io *w, int revents) {
    int fd = w->data - (void*)0;
    ssize_t bytes;

    for (;;) {
        bytes = recv(fd, recvbuf, sizeof(recvbuf), 0);
        if (bytes < 1)
            break;
        _stats.pkts++;
        _stats.bytes += bytes;
        if (bytes < sizeof(recvbuf)) {
            return;
        }
    }

    ev_io_stop(loop, w);
    shutdown(fd, SHUT_RDWR);
    ev_io_init(w, _ev_shutdown_cb, fd, EV_READ);
    ev_io_start(loop, w);
}

static void _ev_accept_cb(struct ev_loop *loop, ev_io *w, int revents) {
    int fd = w->data - (void*)0, newfd, flags;
    struct sockaddr addr;
    socklen_t len;

    for (;;) {
        memset(&addr, 0, sizeof(struct sockaddr));
        len = sizeof(struct sockaddr);
        newfd = accept(fd, &addr, &len);
        _stats.accept++;
        if (newfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;
            fprintf(stderr, "accept(%d) ", fd);
            perror("");
            ev_io_stop(loop, w);
            shutdown(fd, SHUT_RDWR);
            close(fd);
            free(w); /* TODO: Delayed free maybe? */
            _stats.accdrop++;
            return;
        }

        if ((flags = fcntl(newfd, F_GETFL)) == -1
            || fcntl(newfd, F_SETFL, flags | O_NONBLOCK))
        {
            perror("fcntl()");
            shutdown(newfd, SHUT_RDWR);
            close(newfd);
            _stats.accdrop++;
            return;
        }

        {
            ev_io* io = calloc(1, sizeof(ev_io));
            if (!io) {
                perror("calloc()");
                shutdown(newfd, SHUT_RDWR);
                close(newfd);
                _stats.accdrop++;
                return;
            }
            io->data += newfd;
            ev_io_init(io, _ev_recv_cb, newfd, EV_READ);
            ev_io_start(loop, io);
            _stats.conns++;
        }
    }
}
#endif

#ifdef HAVE_LIBUV
static void _uv_stats_cb(uv_timer_t* w) {
    stats_cb();
}

void* _req_list = 0;

inline void _req_add(void* vp) {
    *(void**)vp = _req_list;
    _req_list = vp;
}

void* _buf_list = 0;

inline void _buf_add(void* vp) {
    *(void**)vp = _buf_list;
    _buf_list = vp;
}

static void _uv_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = recvbuf;
    buf->len = sizeof(recvbuf);
}

static void _uv_alloc_reflect_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    if (_buf_list) {
        buf->base = _buf_list;
        _buf_list = *(void**)_buf_list;
    } else {
        buf->base = malloc(4096);
    }
    buf->len = 4096;
}

static void _uv_close_cb(uv_handle_t* handle) {
    if (handle->data) {
        struct tls_ctx* tls = (struct tls_ctx*)handle->data;
        SSL_free(tls->ssl);
        free(tls);
    }
    free(handle);
}

static void _uv_udp_recv_reflect_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags);

static void _uv_udp_send_cb(uv_udp_send_t* req, int status) {
    if (uv_udp_recv_start(req->handle, _uv_alloc_reflect_cb, _uv_udp_recv_reflect_cb)) {
        uv_close((uv_handle_t*)req->handle, _uv_close_cb);
    }
    _buf_add(req->data);
    _req_add(req);
}

static void _uv_udp_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags) {
    if (nread < 0) {
        uv_udp_recv_stop(handle);
        uv_close((uv_handle_t*)handle, _uv_close_cb);
        return;
    }

    _stats.pkts++;
    _stats.bytes += nread;
}

static void _uv_udp_recv_reflect_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags) {
    if (nread < 0) {
        uv_udp_recv_stop(handle);
        uv_close((uv_handle_t*)handle, _uv_close_cb);
        _buf_add(buf->base);
        return;
    }

    _stats.pkts++;
    _stats.bytes += nread;

    uv_udp_recv_stop(handle);

    uv_udp_send_t* req;
    if (_req_list) {
        req = _req_list;
        _req_list = *(void**)_req_list;
    } else {
        req = malloc(sizeof(*req));
    }
    if (!req) {
        uv_close((uv_handle_t*)handle, _uv_close_cb);
        _buf_add(buf->base);
        return;
    }
    req->data = buf->base;
    uv_buf_t sndbuf;
    sndbuf = uv_buf_init(buf->base, nread);
    if (uv_udp_send(req, handle, &sndbuf, 1, addr, _uv_udp_send_cb)) {
        uv_close((uv_handle_t*)handle, _uv_close_cb);
        _req_add(req);
        _buf_add(buf->base);
        return;
    }
}

static void _uv_tcp_recv_cb(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf) {
    if (nread < 0) {
        uv_read_stop(handle);
        uv_close((uv_handle_t*)handle, _uv_close_cb);
        return;
    }

    _stats.pkts++;
    _stats.bytes += nread;
}

static void _uv_on_connect_cb(uv_stream_t* server, int status) {
    uv_tcp_t* tcp;
    int err;

    if (status) {
        _stats.accdrop++;
        return;
    }

    tcp = calloc(1, sizeof(uv_tcp_t));
    if ((err = uv_tcp_init(uv_default_loop(), tcp))) {
        fprintf(stderr, "uv_tcp_init() %s\n", uv_strerror(err));
        free(tcp);
        _stats.accdrop++;
        return;
    }
    if ((err = uv_accept(server, (uv_stream_t*)tcp))) {
        fprintf(stderr, "uv_accept() %s\n", uv_strerror(err));
        uv_close((uv_handle_t*)tcp, _uv_close_cb);
        _stats.accdrop++;
        return;
    }
    _stats.accept++;
    if ((err = uv_read_start((uv_stream_t*)tcp, _uv_alloc_cb, _uv_tcp_recv_cb))) {
        fprintf(stderr, "uv_read_start() %s\n", uv_strerror(err));
        uv_close((uv_handle_t*)tcp, _uv_close_cb);
        return;
    }
    _stats.conns++;
}

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;

static void _uv_tcp_recv_reflect_cb(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf);

static void _uv_tcp_send_cb(uv_write_t* req, int status) {
    if (req->handle->data) {
        struct tls_ctx* tls = (struct tls_ctx*)req->handle->data;
        write_req_t* wr = (write_req_t*)req;

        if (close_conn_after_first && tls->close) {
            uv_tcp_close_reset((uv_tcp_t*)req->handle, _uv_close_cb);
            _buf_add(((write_req_t*)req)->buf.base);
            _req_add(req);
            return;
        }

        ssize_t nread = BIO_read(tls->wbio, wr->buf.base, wr->buf.len);
        if (nread > 0) {
            wr->buf = uv_buf_init(wr->buf.base, nread);
            uv_write(req, req->handle, &wr->buf, 1, _uv_tcp_send_cb);
            return;
        }
    } else if (close_conn_after_first) {
        uv_tcp_close_reset((uv_tcp_t*)req->handle, _uv_close_cb);
        _buf_add(((write_req_t*)req)->buf.base);
        _req_add(req);
        return;
    }

    if (uv_read_start((uv_stream_t*)req->handle, _uv_alloc_reflect_cb, _uv_tcp_recv_reflect_cb)) {
        uv_close((uv_handle_t*)req->handle, _uv_close_cb);
    }
    _buf_add(((write_req_t*)req)->buf.base);
    _req_add(req);
}

static void _uv_tcp_recv_reflect_cb(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf) {
    if (nread < 0) {
        uv_read_stop(handle);
        uv_close((uv_handle_t*)handle, _uv_close_cb);
        return;
    }

    _stats.pkts++;

    if (handle->data) {
        struct tls_ctx* tls = (struct tls_ctx*)handle->data;

        if (BIO_write(tls->rbio, buf->base, nread) != nread) {
            fprintf(stderr, "BIO_write(): unable to write all %zu bytes\n", nread);
            uv_read_stop(handle);
            uv_close((uv_handle_t*)handle, _uv_close_cb);
            _buf_add(buf->base);
            return;
        }

        bool want_write = false;
        if (!tls->accepted) {
            int err = SSL_accept(tls->ssl);
            if (!err) {
                fprintf(stderr, "SSL_accept(): handshake was not successful or shut down\n");
                uv_read_stop(handle);
                uv_close((uv_handle_t*)handle, _uv_close_cb);
                _buf_add(buf->base);
                return;
            } else if (err < 1) {
                switch(SSL_get_error(tls->ssl, err)) {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                    want_write = true;
                    break;
                default:
                    fprintf(stderr, "SSL_accept(): %s\n", ERR_error_string(SSL_get_error(tls->ssl, err), 0));
                    uv_read_stop(handle);
                    uv_close((uv_handle_t*)handle, _uv_close_cb);
                    _buf_add(buf->base);
                    return;
                }
            } else {
                tls->accepted = true;
            }
        }
        for (; !want_write;) {
            nread = SSL_read(tls->ssl, buf->base, buf->len);
            if (nread < 1) {
                switch(SSL_get_error(tls->ssl, nread)) {
                case SSL_ERROR_WANT_READ:
                    break;
                case SSL_ERROR_WANT_WRITE:
                    want_write = true;
                    break;
                default:
                    fprintf(stderr, "SSL_read(): %s\n", ERR_error_string(SSL_get_error(tls->ssl, nread), 0));
                    uv_read_stop(handle);
                    uv_close((uv_handle_t*)handle, _uv_close_cb);
                    _buf_add(buf->base);
                    return;
                }
                break;
            }
            _stats.bytes += nread;
            nread = SSL_write(tls->ssl, buf->base, nread);
            // we expect everything to be written since partial write is not enabled
            if (nread < 1) {
                switch(SSL_get_error(tls->ssl, nread)) {
                case SSL_ERROR_WANT_READ:
                    break;
                case SSL_ERROR_WANT_WRITE:
                    want_write = true;
                    break;
                default:
                    fprintf(stderr, "SSL_write(): %s\n", ERR_error_string(SSL_get_error(tls->ssl, nread), 0));
                    uv_read_stop(handle);
                    uv_close((uv_handle_t*)handle, _uv_close_cb);
                    _buf_add(buf->base);
                    return;
                }
                break;
            }
            tls->close = true;
        }

        nread = BIO_read(tls->wbio, buf->base, buf->len);
        if (nread < 1) {
            if (want_write && tls->accepted) {
                fprintf(stderr, "want write but nothing in wbio?\n");
                uv_read_stop(handle);
                uv_close((uv_handle_t*)handle, _uv_close_cb);
            }
            _buf_add(buf->base);
            return;
        }
    } else {
        _stats.bytes += nread;
    }

    uv_read_stop(handle);

    write_req_t* req;
    if (_req_list) {
        req = _req_list;
        _req_list = *(void**)_req_list;
    } else {
        req = malloc(sizeof(*req));
    }
    if (!req) {
        uv_close((uv_handle_t*)handle, _uv_close_cb);
        _buf_add(buf->base);
        return;
    }
    req->buf = uv_buf_init(buf->base, nread);
    uv_write((uv_write_t*)req, handle, &req->buf, 1, _uv_tcp_send_cb);
}

static void _uv_on_connect_reflect_cb(uv_stream_t* server, int status) {
    uv_tcp_t* tcp;
    int err;

    if (status) {
        _stats.accdrop++;
        return;
    }

    tcp = calloc(1, sizeof(uv_tcp_t));
    if ((err = uv_tcp_init(uv_default_loop(), tcp))) {
        fprintf(stderr, "uv_tcp_init() %s\n", uv_strerror(err));
        free(tcp);
        _stats.accdrop++;
        return;
    }
    if ((err = uv_accept(server, (uv_stream_t*)tcp))) {
        fprintf(stderr, "uv_accept() %s\n", uv_strerror(err));
        uv_close((uv_handle_t*)tcp, _uv_close_cb);
        _stats.accdrop++;
        return;
    }
    if (ssl_ctx) {
        struct tls_ctx* tls = calloc(1, sizeof(struct tls_ctx));
        if (!tls) {
            uv_close((uv_handle_t*)tcp, _uv_close_cb);
            _stats.accdrop++;
            return;
        }
        if (!(tls->rbio = BIO_new(BIO_s_mem()))) {
            free(tls);
            uv_close((uv_handle_t*)tcp, _uv_close_cb);
            _stats.accdrop++;
            return;
        }
        if (!(tls->wbio = BIO_new(BIO_s_mem()))) {
            BIO_free(tls->rbio);
            free(tls);
            uv_close((uv_handle_t*)tcp, _uv_close_cb);
            _stats.accdrop++;
            return;
        }
        if (!(tls->ssl = SSL_new(ssl_ctx))) {
            fprintf(stderr, "SSL_new(): %s\n", ERR_error_string(ERR_get_error(), 0));
            BIO_free(tls->wbio);
            BIO_free(tls->rbio);
            free(tls);
            uv_close((uv_handle_t*)tcp, _uv_close_cb);
            _stats.accdrop++;
            return;
        }
        SSL_set_bio(tls->ssl, tls->rbio, tls->wbio);

        tcp->data = tls;

        err = SSL_accept(tls->ssl);
        if (!err) {
            fprintf(stderr, "SSL_accept(): handshake was not successful or shut down\n");
            uv_close((uv_handle_t*)tcp, _uv_close_cb);
            _stats.accdrop++;
            return;
        } else if (err < 1) {
            bool want_write = false;

            switch(SSL_get_error(tls->ssl, err)) {
            case SSL_ERROR_WANT_READ:
                break;
            case SSL_ERROR_WANT_WRITE:
                want_write = true;
                break;
            default:
                fprintf(stderr, "SSL_accept(): %d %s\n", err, ERR_error_string(SSL_get_error(tls->ssl, err), 0));
                uv_close((uv_handle_t*)tcp, _uv_close_cb);
                _stats.accdrop++;
                return;
            }

            uv_buf_t buf;
            _uv_alloc_reflect_cb(0, 0, &buf);

            int nread = BIO_read(tls->wbio, buf.base, buf.len);
            if (nread < 1) {
                if (want_write) {
                    fprintf(stderr, "SSL_accept(): want write but nothing in wbio?\n");
                    uv_close((uv_handle_t*)tcp, _uv_close_cb);
                    _stats.accdrop++;
                }
                _buf_add(buf.base);
            } else {
                write_req_t* req;
                if (_req_list) {
                    req = _req_list;
                    _req_list = *(void**)_req_list;
                } else {
                    req = malloc(sizeof(*req));
                }
                if (!req) {
                    uv_close((uv_handle_t*)tcp, _uv_close_cb);
                    return;
                }

                req->buf = uv_buf_init(buf.base, nread);
                uv_write((uv_write_t*)req, (uv_stream_t*)tcp, &req->buf, 1, _uv_tcp_send_cb);
                _stats.accept++;
                _stats.conns++;
                return;
            }
        } else {
            tls->accepted = true;
        }
    }
    _stats.accept++;
    if ((err = uv_read_start((uv_stream_t*)tcp, _uv_alloc_reflect_cb, _uv_tcp_recv_reflect_cb))) {
        fprintf(stderr, "uv_read_start() %s\n", uv_strerror(err));
        uv_close((uv_handle_t*)tcp, _uv_close_cb);
        return;
    }
    _stats.conns++;
}
#endif

int main(int argc, char* argv[]) {
    int opt, use_udp = 0, use_tcp = 0, use_tls = 0, reuse_addr = 0, reuse_port = 0, linger = 0, reflect = 0;
    struct addrinfo* addrinfo = 0;
    struct addrinfo hints;
    const char* node = 0;
    const char* service = 0;
    int use_ev = 0, use_uv = 0;

#if defined(HAVE_LIBUV)
    use_uv = 1;
#elif defined(HAVE_LIBEV)
    use_ev = 1;
#endif

    if ((program_name = strrchr(argv[0], '/'))) {
        program_name++;
    }
    else {
        program_name = argv[0];
    }

    while ((opt = getopt(argc, argv, "B:utTCARL:rhV")) != -1) {
        switch (opt) {
            case 'B':
                if (!strcmp(optarg, "ev")) {
#ifdef HAVE_LIBEV
                    use_uv = 0;
                    use_ev = 1;
#else
                    fprintf(stderr, "No libev support compiled in\n");
                    return 2;
#endif
                }
                else if(!strcmp(optarg, "uv")) {
#ifdef HAVE_LIBUV
                    use_ev = 0;
                    use_uv = 1;
#else
                    fprintf(stderr, "No libuv support compiled in\n");
                    return 2;
#endif
                }
                break;

            case 'u':
                use_udp = 1;
                break;

            case 't':
                use_tcp = 1;
                break;

            case 'T':
                use_tcp = 1;
                use_tls = 1;
                break;

            case 'C':
                close_conn_after_first = true;
                break;

            case 'A':
                reuse_addr = 1;
                break;

            case 'R':
                reuse_port = 1;
                break;

            case 'L':
                linger = atoi(optarg);
                if (linger < 1) {
                    usage();
                    return 2;
                }
                break;

            case 'r':
                reflect = 1;
                break;

            case 'h':
                usage();
                return 0;

            case 'V':
                version();
                return 0;

            default:
                usage();
                return 2;
        }
    }

    if (!use_udp && !use_tcp) {
        use_udp = 1;
        use_tcp = 1;
    }

    if (optind < argc) {
        service = argv[optind++];
    }
    else {
        usage();
        return 2;
    }
    if (optind < argc) {
        node = service;
        service = argv[optind++];
    }
    if (optind < argc) {
        usage();
        return 2;
    }

    if (use_tls) {
#ifdef HAVE_TLS_METHOD
        if (!(ssl_ctx = SSL_CTX_new(TLS_method()))) {
            fprintf(stderr, "SSL_CTX_new(): %s", ERR_error_string(ERR_get_error(), 0));
            return 1;
        }
        if (!SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION)) {
            fprintf(stderr, "SSL_CTX_set_min_proto_version(TLS1_2_VERSION): %s", ERR_error_string(ERR_get_error(), 0));
            return 1;
        }
#else
        if (!(ssl_ctx = SSL_CTX_new(SSLv23_server_method()))) {
            fprintf(stderr, "SSL_CTX_new(): %s", ERR_error_string(ERR_get_error(), 0));
            return 1;
        }
#endif
        if (SSL_CTX_use_certificate_file(ssl_ctx, "cert.pem", SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, "SSL_CTX_use_certificate_file(): %s", ERR_error_string(ERR_get_error(), 0));
            return 1;
        }
        if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "key.pem", SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, "SSL_CTX_use_PrivateKey_file(): %s", ERR_error_string(ERR_get_error(), 0));
            return 1;
        }
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(node, service, &hints, &addrinfo)) {
        perror("getaddrinfo()");
        return 1;
    }
    if (!addrinfo) {
        return 1;
    }

    {
        struct addrinfo* ai = addrinfo;
        int fd, optval, flags;

        for (; ai; ai = ai->ai_next) {
            switch (ai->ai_socktype) {
                case SOCK_DGRAM:
                case SOCK_STREAM:
                    break;
                default:
                    continue;
            }

            switch (ai->ai_protocol) {
                case IPPROTO_UDP:
                    if (!use_udp)
                        continue;
                    break;
                case IPPROTO_TCP:
                    if (!use_tcp)
                        continue;
                    break;
                default:
                    continue;
            }

            fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (fd < 0) {
                perror("socket()");
                return 1;
            }

#ifdef SO_REUSEADDR
            if (reuse_addr) {
                optval = 1;
                if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))) {
                    perror("setsockopt(SO_REUSEADDR)");
                    return 1;
                }
            }
#endif
#ifdef SO_REUSEPORT
            if (reuse_port) {
                optval = 1;
                if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval))) {
                    perror("setsockopt(SO_REUSEPORT)");
                    return 1;
                }
            }
#endif
            {
                struct linger l = { 0, 0 };
                if (linger > 0) {
                    l.l_onoff = 1;
                    l.l_linger = linger;
                }
                if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l))) {
                    perror("setsockopt(SO_LINGER)");
                    return 1;
                }
            }

            if ((flags = fcntl(fd, F_GETFL)) == -1) {
                perror("fcntl(F_GETFL)");
                return 1;
            }
            if (fcntl(fd, F_SETFL, flags | O_NONBLOCK)) {
                perror("fcntl(F_SETFL)");
                return 1;
            }

#ifdef HAVE_LIBEV
            if (use_ev) {
                if (bind(fd, ai->ai_addr, ai->ai_addrlen) < 0) {
                    perror("bind()");
                    return 1;
                }
                if (ai->ai_socktype == SOCK_STREAM && listen(fd, 10)) {
                    perror("listen()");
                    return 1;
                }

                {
                    ev_io* io = calloc(1, sizeof(ev_io));
                    if (!io) {
                        perror("calloc()");
                        return 1;
                    }
                    io->data += fd;
                    ev_io_init(io, ai->ai_socktype == SOCK_STREAM ? _ev_accept_cb : _ev_recv_cb, fd, EV_READ);
                    ev_io_start(EV_DEFAULT, io);
                }
            }
            else
#endif
#ifdef HAVE_LIBUV
            if (use_uv) {
                int err;
                if (ai->ai_socktype == SOCK_DGRAM) {
                    uv_udp_t* udp = calloc(1, sizeof(uv_udp_t));

                    if ((err = uv_udp_init(uv_default_loop(), udp))) {
                        fprintf(stderr, "uv_udp_init() %s\n", uv_strerror(err));
                        return 1;
                    }
                    if ((err = uv_udp_open(udp, fd))) {
                        fprintf(stderr, "uv_udp_open() %s\n", uv_strerror(err));
                        return 1;
                    }
                    if ((err = uv_udp_bind(udp, ai->ai_addr, UV_UDP_REUSEADDR))) {
                        fprintf(stderr, "uv_udp_bind() %s\n", uv_strerror(err));
                        return 1;
                    }
                    if (reflect) {
                        printf("reflecting UDP packets\n");
                        if ((err = uv_udp_recv_start(udp, _uv_alloc_reflect_cb, _uv_udp_recv_reflect_cb))) {
                            fprintf(stderr, "uv_udp_recv_start() %s\n", uv_strerror(err));
                            return 1;
                        }
                    } else {
                        if ((err = uv_udp_recv_start(udp, _uv_alloc_cb, _uv_udp_recv_cb))) {
                            fprintf(stderr, "uv_udp_recv_start() %s\n", uv_strerror(err));
                            return 1;
                        }
                    }
                }
                else if(ai->ai_socktype == SOCK_STREAM) {
                    uv_tcp_t* tcp = calloc(1, sizeof(uv_tcp_t));

                    if ((err = uv_tcp_init(uv_default_loop(), tcp))) {
                        fprintf(stderr, "uv_tcp_init() %s\n", uv_strerror(err));
                        return 1;
                    }
                    if ((err = uv_tcp_open(tcp, fd))) {
                        fprintf(stderr, "uv_tcp_open() %s\n", uv_strerror(err));
                        return 1;
                    }
                    if ((err = uv_tcp_bind(tcp, ai->ai_addr, UV_UDP_REUSEADDR))) {
                        fprintf(stderr, "uv_tcp_bind() %s\n", uv_strerror(err));
                        return 1;
                    }
                    if (reflect) {
                        printf("reflecting %s packets\n", use_tls ? "TLS" : "TCP");
                        if ((err = uv_listen((uv_stream_t*)tcp, 10, _uv_on_connect_reflect_cb))) {
                            fprintf(stderr, "uv_listen() %s\n", uv_strerror(err));
                            return 1;
                        }
                    } else {
                        if ((err = uv_listen((uv_stream_t*)tcp, 10, _uv_on_connect_cb))) {
                            fprintf(stderr, "uv_listen() %s\n", uv_strerror(err));
                            return 1;
                        }
                    }
                }
                else {
                    continue;
                }
            }
            else
#endif
            {
                return 3;
            }

            {
                char h[NI_MAXHOST], s[NI_MAXSERV];
                if (getnameinfo(ai->ai_addr, ai->ai_addrlen, h, NI_MAXHOST, s, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV)) {
                    perror("getnameinfo()");
                    h[0] = 0;
                    s[0] = 0;
                }

                printf("listen: %d fam: %d type: %d proto: %d host: %s service: %s\n", fd, ai->ai_family, ai->ai_socktype, ai->ai_protocol, h, s);
            }
        }
    }

    freeaddrinfo(addrinfo);

#ifdef HAVE_LIBEV
    if (use_ev) {
        ev_timer stats;

        printf("backend: libev\n");
        ev_timer_init(&stats, _ev_stats_cb, 1.0, 1.0);
        ev_timer_start(EV_DEFAULT, &stats);

        ev_run(EV_DEFAULT, 0);
    }
    else
#endif
#ifdef HAVE_LIBUV
    if (use_uv) {
        uv_timer_t stats;

        printf("backend: libuv\n");
        uv_timer_init(uv_default_loop(), &stats);
        uv_timer_start(&stats, _uv_stats_cb, 1000, 1000);

        uv_run(uv_default_loop(), 0);
    }
    else
#endif
    {
        printf("backend: none\n");
    }

    return 0;
}
