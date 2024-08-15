/*
 * dumdohd - reflect DNS-over-HTTPS requests, based on (for now):
 *  https://raw.githubusercontent.com/nghttp2/nghttp2/master/examples/libevent-server.c
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <err.h>
#include <string.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include <event.h>
#include <event2/event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>

#include <nghttp2/nghttp2.h>

int                random_disconnect   = 0;
int                listen_backlog      = 10;
int                conn_flags          = 0;
int                flip_qr_bit         = 0;
unsigned long long random_disconnected = 0, random_disconnect_checks = 0;

#define OUTPUT_WOULDBLOCK_THRESHOLD (1 << 16)

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#define MAKE_NV(NAME, VALUE)                                                  \
    {                                                                         \
        (uint8_t*)NAME, (uint8_t*)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1, \
            NGHTTP2_NV_FLAG_NONE                                              \
    }

struct app_context;
typedef struct app_context app_context;

typedef struct http2_stream_data {
    struct http2_stream_data *prev, *next;
    char*                     request_path;
    int32_t                   stream_id;
    int                       fd;
    uint8_t                   data[64 * 1024];
    size_t                    datalen, dataread;
} http2_stream_data;

typedef struct http2_session_data {
    struct http2_stream_data root;
    struct bufferevent*      bev;
    app_context*             app_ctx;
    nghttp2_session*         session;
    char*                    client_addr;
} http2_session_data;

struct app_context {
    SSL_CTX*           ssl_ctx;
    struct event_base* evbase;
};

static unsigned char next_proto_list[256];
static size_t        next_proto_list_len;

#ifndef OPENSSL_NO_NEXTPROTONEG
static int next_proto_cb(SSL* ssl, const unsigned char** data,
    unsigned int* len, void* arg)
{
    (void)ssl;
    (void)arg;

    *data = next_proto_list;
    *len  = (unsigned int)next_proto_list_len;
    return SSL_TLSEXT_ERR_OK;
}
#endif /* !OPENSSL_NO_NEXTPROTONEG */

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
static int alpn_select_proto_cb(SSL* ssl, const unsigned char** out,
    unsigned char* outlen, const unsigned char* in,
    unsigned int inlen, void* arg)
{
    int rv;
    (void)ssl;
    (void)arg;

    rv = nghttp2_select_next_protocol((unsigned char**)out, outlen, in, inlen);

    if (rv != 1) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    return SSL_TLSEXT_ERR_OK;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */

/* Create SSL_CTX. */
static SSL_CTX* create_ssl_ctx(const char* key_file, const char* cert_file)
{
    SSL_CTX* ssl_ctx;

    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ssl_ctx) {
        errx(1, "Could not create SSL/TLS context: %s",
            ERR_error_string(ERR_get_error(), NULL));
    }
    SSL_CTX_set_options(ssl_ctx,
        SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        errx(1, "Could not read private key file %s", key_file);
    }
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1) {
        errx(1, "Could not read certificate file %s", cert_file);
    }

    next_proto_list[0] = NGHTTP2_PROTO_VERSION_ID_LEN;
    memcpy(&next_proto_list[1], NGHTTP2_PROTO_VERSION_ID,
        NGHTTP2_PROTO_VERSION_ID_LEN);
    next_proto_list_len = 1 + NGHTTP2_PROTO_VERSION_ID_LEN;

#ifndef OPENSSL_NO_NEXTPROTONEG
    SSL_CTX_set_next_protos_advertised_cb(ssl_ctx, next_proto_cb, NULL);
#endif /* !OPENSSL_NO_NEXTPROTONEG */

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_proto_cb, NULL);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */

    return ssl_ctx;
}

/* Create SSL object */
static SSL* create_ssl(SSL_CTX* ssl_ctx)
{
    SSL* ssl;
    ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        errx(1, "Could not create SSL/TLS session object: %s",
            ERR_error_string(ERR_get_error(), NULL));
    }
    return ssl;
}

static void add_stream(http2_session_data* session_data,
    http2_stream_data*                     stream_data)
{
    stream_data->next       = session_data->root.next;
    session_data->root.next = stream_data;
    stream_data->prev       = &session_data->root;
    if (stream_data->next) {
        stream_data->next->prev = stream_data;
    }
}

static void remove_stream(http2_session_data* session_data,
    http2_stream_data*                        stream_data)
{
    (void)session_data;

    stream_data->prev->next = stream_data->next;
    if (stream_data->next) {
        stream_data->next->prev = stream_data->prev;
    }
}

static http2_stream_data*
create_http2_stream_data(http2_session_data* session_data, int32_t stream_id)
{
    http2_stream_data* stream_data;
    stream_data = malloc(sizeof(http2_stream_data));
    memset(stream_data, 0, sizeof(http2_stream_data));
    stream_data->stream_id = stream_id;
    stream_data->fd        = -1;

    add_stream(session_data, stream_data);
    return stream_data;
}

static void delete_http2_stream_data(http2_stream_data* stream_data)
{
    if (stream_data->fd != -1) {
        close(stream_data->fd);
    }
    free(stream_data->request_path);
    free(stream_data);
}

static http2_session_data* create_http2_session_data(app_context* app_ctx,
    int                                                           fd,
    struct sockaddr*                                              addr,
    int                                                           addrlen)
{
    int                 rv;
    http2_session_data* session_data;
    SSL*                ssl;
    char                host[NI_MAXHOST];
    int                 val = 1;

    ssl          = create_ssl(app_ctx->ssl_ctx);
    session_data = malloc(sizeof(http2_session_data));
    memset(session_data, 0, sizeof(http2_session_data));
    session_data->app_ctx = app_ctx;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char*)&val, sizeof(val));
    session_data->bev = bufferevent_openssl_socket_new(
        app_ctx->evbase, fd, ssl, BUFFEREVENT_SSL_ACCEPTING,
        BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    bufferevent_enable(session_data->bev, EV_READ | EV_WRITE);
    rv = getnameinfo(addr, (socklen_t)addrlen, host, sizeof(host), NULL, 0,
        NI_NUMERICHOST);
    if (rv != 0) {
        session_data->client_addr = strdup("(unknown)");
    } else {
        session_data->client_addr = strdup(host);
    }

    return session_data;
}

static void delete_http2_session_data(http2_session_data* session_data)
{
    http2_stream_data* stream_data;
    SSL*               ssl = bufferevent_openssl_get_ssl(session_data->bev);
    fprintf(stderr, "%s disconnected\n", session_data->client_addr);
    if (ssl) {
        SSL_shutdown(ssl);
    }
    bufferevent_free(session_data->bev);
    nghttp2_session_del(session_data->session);
    for (stream_data = session_data->root.next; stream_data;) {
        http2_stream_data* next = stream_data->next;
        delete_http2_stream_data(stream_data);
        stream_data = next;
    }
    free(session_data->client_addr);
    free(session_data);
}

/* Serialize the frame and send (or buffer) the data to
   bufferevent. */
static int session_send(http2_session_data* session_data)
{
    int rv;
    rv = nghttp2_session_send(session_data->session);
    if (rv != 0) {
        warnx("Fatal error: %s", nghttp2_strerror(rv));
        return -1;
    }
    return 0;
}

/* Read the data in the bufferevent and feed them into nghttp2 library
   function. Invocation of nghttp2_session_mem_recv() may make
   additional pending frames, so call session_send() at the end of the
   function. */
static int session_recv(http2_session_data* session_data)
{
    ssize_t          readlen;
    struct evbuffer* input   = bufferevent_get_input(session_data->bev);
    size_t           datalen = evbuffer_get_length(input);
    unsigned char*   data    = evbuffer_pullup(input, -1);

    readlen = nghttp2_session_mem_recv(session_data->session, data, datalen);
    if (readlen < 0) {
        warnx("Fatal error: %s", nghttp2_strerror((int)readlen));
        return -1;
    }
    if (evbuffer_drain(input, (size_t)readlen) != 0) {
        warnx("Fatal error: evbuffer_drain failed");
        return -1;
    }
    if (session_send(session_data) != 0) {
        return -1;
    }
    return 0;
}

static ssize_t send_callback(nghttp2_session* session, const uint8_t* data,
    size_t length, int flags, void* user_data)
{
    http2_session_data* session_data = (http2_session_data*)user_data;
    struct bufferevent* bev          = session_data->bev;
    (void)session;
    (void)flags;

    /* Avoid excessive buffering in server side. */
    if (evbuffer_get_length(bufferevent_get_output(session_data->bev)) >= OUTPUT_WOULDBLOCK_THRESHOLD) {
        return NGHTTP2_ERR_WOULDBLOCK;
    }
    bufferevent_write(bev, data, length);
    return (ssize_t)length;
}

/* Returns nonzero if the string |s| ends with the substring |sub| */
static int ends_with(const char* s, const char* sub)
{
    size_t slen   = strlen(s);
    size_t sublen = strlen(sub);
    if (slen < sublen) {
        return 0;
    }
    return memcmp(s + slen - sublen, sub, sublen) == 0;
}

/* Returns int value of hex string character |c| */
static uint8_t hex_to_uint(uint8_t c)
{
    if ('0' <= c && c <= '9') {
        return (uint8_t)(c - '0');
    }
    if ('A' <= c && c <= 'F') {
        return (uint8_t)(c - 'A' + 10);
    }
    if ('a' <= c && c <= 'f') {
        return (uint8_t)(c - 'a' + 10);
    }
    return 0;
}

/* Decodes percent-encoded byte string |value| with length |valuelen|
   and returns the decoded byte string in allocated buffer. The return
   value is NULL terminated. The caller must free the returned
   string. */
static char* percent_decode(const uint8_t* value, size_t valuelen)
{
    char* res;

    res = malloc(valuelen + 1);
    if (valuelen > 3) {
        size_t i, j;
        for (i = 0, j = 0; i < valuelen - 2;) {
            if (value[i] != '%' || !isxdigit(value[i + 1]) || !isxdigit(value[i + 2])) {
                res[j++] = (char)value[i++];
                continue;
            }
            res[j++] = (char)((hex_to_uint(value[i + 1]) << 4) + hex_to_uint(value[i + 2]));
            i += 3;
        }
        memcpy(&res[j], &value[i], 2);
        res[j + 2] = '\0';
    } else {
        memcpy(res, value, valuelen);
        res[valuelen] = '\0';
    }
    return res;
}

static ssize_t file_read_callback(nghttp2_session* session, int32_t stream_id,
    uint8_t* buf, size_t length,
    uint32_t*            data_flags,
    nghttp2_data_source* source,
    void*                user_data)
{
    int     fd = source->fd;
    ssize_t r;
    (void)session;
    (void)stream_id;
    (void)user_data;

    while ((r = read(fd, buf, length)) == -1 && errno == EINTR)
        ;
    if (r == -1) {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    if (r == 0) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    return r;
}

static ssize_t data_read_callback(nghttp2_session* session, int32_t stream_id,
    uint8_t* buf, size_t length,
    uint32_t*            data_flags,
    nghttp2_data_source* source,
    void*                user_data)
{
    http2_stream_data* stream_data;
    stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
    if (!stream_data) {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    length = length > stream_data->datalen - stream_data->dataread ? stream_data->datalen - stream_data->dataread : length;
    memcpy(buf, stream_data->data, length);
    stream_data->dataread += length;
    if (stream_data->dataread >= stream_data->datalen) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    return length;
}

static int send_response(nghttp2_session* session, int32_t stream_id,
    nghttp2_nv* nva, size_t nvlen)
{
    int                   rv;
    nghttp2_data_provider data_prd;
    // data_prd.source.fd = fd;
    // data_prd.read_callback = file_read_callback;
    data_prd.read_callback = data_read_callback;

    rv = nghttp2_submit_response(session, stream_id, nva, nvlen, &data_prd);
    if (rv != 0) {
        warnx("Fatal error: %s", nghttp2_strerror(rv));
        return -1;
    }
    return 0;
}

static const char ERROR_HTML[] = "<html><head><title>404</title></head>"
                                 "<body><h1>404 Not Found</h1></body></html>";

static int error_reply(nghttp2_session* session,
    http2_stream_data*                  stream_data)
{
    // int rv;
    // ssize_t writelen;
    // int pipefd[2];
    nghttp2_nv hdrs[] = { MAKE_NV(":status", "404") };

    // rv = pipe(pipefd);
    // if (rv != 0) {
    //   warn("Could not create pipe");
    //   rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
    //                                  stream_data->stream_id,
    //                                  NGHTTP2_INTERNAL_ERROR);
    //   if (rv != 0) {
    //     warnx("Fatal error: %s", nghttp2_strerror(rv));
    //     return -1;
    //   }
    //   return 0;
    // }
    //
    // writelen = write(pipefd[1], ERROR_HTML, sizeof(ERROR_HTML) - 1);
    // close(pipefd[1]);
    //
    // if (writelen != sizeof(ERROR_HTML) - 1) {
    //   close(pipefd[0]);
    //   return -1;
    // }
    //
    // stream_data->fd = pipefd[0];

    if (send_response(session, stream_data->stream_id, hdrs, ARRLEN(hdrs)) != 0) {
        // close(pipefd[0]);
        return -1;
    }
    return 0;
}

/* nghttp2_on_header_callback: Called when nghttp2 library emits
   single header name/value pair. */
static int on_header_callback(nghttp2_session* session,
    const nghttp2_frame* frame, const uint8_t* name,
    size_t namelen, const uint8_t* value,
    size_t valuelen, uint8_t flags, void* user_data)
{
    http2_stream_data* stream_data;
    const char         PATH[] = ":path";
    (void)flags;
    (void)user_data;

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
        if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
            break;
        }
        stream_data = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
        if (!stream_data || stream_data->request_path) {
            break;
        }
        if (namelen == sizeof(PATH) - 1 && memcmp(PATH, name, namelen) == 0) {
            size_t j;
            for (j = 0; j < valuelen && value[j] != '?'; ++j)
                ;
            stream_data->request_path = percent_decode(value, j);
            if (j < valuelen && !strncmp("?dns=", value + j, 5) && j + 5 < valuelen && valuelen - j - 5 < (4 * (sizeof(stream_data->data) / 3))) {
                size_t      len  = valuelen - j - 5;
                const void* data = value + j + 5;
                //  printf("%zu %zu\n", len, len%4);
                //  if (len % 4) {
                //      uint8_t tmpdata[len + len%4];
                //      memcpy(tmpdata, data, len);
                //      for(size_t pad = len % 4; pad; pad--) {
                //          tmpdata[len + pad - 1] = '=';
                //      }
                //      data = tmpdata;
                //      len += len % 4;
                //  }
                // printf("%zu %.*s\n", len, (int)len, (char*)data);
                // const unsigned char* data2 = "AAEBAAABAAAAAAAABmdvb2dsZQNjb20AABwAAQ==";
                // printf("%zu %s\n", strlen(data2), data2);
                // printf("%d\n", strncmp(data2, data, len));
                // int dlen = EVP_DecodeBlock(stream_data->data, data2, strlen(data2));
                // printf("%d %zu\n", dlen, strlen(data2));
                // printf("%p %p\n", stream_data->data, data);
                // dlen = EVP_DecodeBlock(stream_data->data, data, len);
                // printf("%d\n", dlen);

                uint8_t tmpdata[len + len % 4 + 1];
                memcpy(tmpdata, data, len);
                for (size_t pad = len % 4; pad; pad--) {
                    tmpdata[len + pad - 1] = '=';
                }
                len += len % 4;
                tmpdata[len] = 0;
                uint8_t* p   = tmpdata;
                while (*p) {
                    switch (*p) {
                    case '-':
                        *p++ = '+';
                        break;
                    case '_':
                        *p++ = '/';
                        break;
                    default:
                        p++;
                    }
                }
                int dlen = EVP_DecodeBlock(stream_data->data, tmpdata, len);
                if (dlen > 0) {
                    stream_data->datalen = dlen;
                }
            }
        }
        break;
    }
    return 0;
}

static int on_begin_headers_callback(nghttp2_session* session,
    const nghttp2_frame*                              frame,
    void*                                             user_data)
{
    http2_session_data* session_data = (http2_session_data*)user_data;
    http2_stream_data*  stream_data;

    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }
    stream_data = create_http2_stream_data(session_data, frame->hd.stream_id);
    nghttp2_session_set_stream_user_data(session, frame->hd.stream_id,
        stream_data);
    return 0;
}

/* Minimum check for directory traversal. Returns nonzero if it is
   safe. */
static int check_path(const char* path)
{
    /* We don't like '\' in url. */
    return path[0] && path[0] == '/' && strchr(path, '\\') == NULL && strstr(path, "/../") == NULL && strstr(path, "/./") == NULL && !ends_with(path, "/..") && !ends_with(path, "/.");
}

static int on_request_recv(nghttp2_session* session,
    http2_session_data*                     session_data,
    http2_stream_data*                      stream_data)
{
    // int fd;
    nghttp2_nv hdrs[] = {
        MAKE_NV(":status", "200"),
        MAKE_NV("content-type", "application/dns")
    };
    // char *rel_path;

    if (!stream_data->request_path || !stream_data->datalen) {
        if (error_reply(session, stream_data) != 0) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }
    // fprintf(stderr, "%s GET %s\n", session_data->client_addr,
    //         stream_data->request_path);
    // if (!check_path(stream_data->request_path)) {
    //   if (error_reply(session, stream_data) != 0) {
    //     return NGHTTP2_ERR_CALLBACK_FAILURE;
    //   }
    //   return 0;
    // }
    // for (rel_path = stream_data->request_path; *rel_path == '/'; ++rel_path)
    //   ;
    // fd = open(rel_path, O_RDONLY);
    // if (fd == -1) {
    //   if (error_reply(session, stream_data) != 0) {
    //     return NGHTTP2_ERR_CALLBACK_FAILURE;
    //   }
    //   return 0;
    // }
    // stream_data->fd = fd;

    if (random_disconnect) {
        random_disconnect_checks++;
        if (random_disconnect_checks < random_disconnected) {
            // unsigned looped
            random_disconnected      = 0;
            random_disconnect_checks = 0;
        }
        int r;
        if ((r = rand() % 100) < random_disconnect && (random_disconnected * 100) / random_disconnect_checks < random_disconnect) {
            random_disconnected++;
            // nghttp2_session_terminate_session(session, NGHTTP2_CANCEL);
            nghttp2_submit_goaway(session, NGHTTP2_FLAG_NONE, stream_data->stream_id, NGHTTP2_CANCEL, 0, 0);
            return 0;
        }
    }

    if (flip_qr_bit) {
        // flip QR bit
        if (stream_data->datalen > 2) {
            if ((stream_data->data[2] & 0x80)) {
                stream_data->data[2] &= 0x7f;
            } else {
                stream_data->data[2] |= 0x80;
            }
        }
    }

    if (send_response(session, stream_data->stream_id, hdrs, ARRLEN(hdrs)) != 0) {
        // close(fd);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

static int on_frame_recv_callback(nghttp2_session* session,
    const nghttp2_frame* frame, void* user_data)
{
    http2_session_data* session_data = (http2_session_data*)user_data;
    http2_stream_data*  stream_data;
    switch (frame->hd.type) {
    case NGHTTP2_DATA:
    case NGHTTP2_HEADERS:
        /* Check that the client request has finished */
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
            stream_data = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
            /* For DATA and HEADERS frame, this callback may be called after
         on_stream_close_callback. Check that stream still alive. */
            if (!stream_data) {
                return 0;
            }
            return on_request_recv(session, session_data, stream_data);
        }
        break;
    default:
        break;
    }
    return 0;
}

static int on_stream_close_callback(nghttp2_session* session, int32_t stream_id,
    uint32_t error_code, void* user_data)
{
    http2_session_data* session_data = (http2_session_data*)user_data;
    http2_stream_data*  stream_data;
    (void)error_code;

    stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
    if (!stream_data) {
        return 0;
    }
    remove_stream(session_data, stream_data);
    delete_http2_stream_data(stream_data);
    return 0;
}

static int on_data_chunk_recv_callback(nghttp2_session* session,
    uint8_t                                             flags,
    int32_t                                             stream_id,
    const uint8_t*                                      data,
    size_t len, void* user_data)
{
    http2_session_data* session_data = (http2_session_data*)user_data;
    http2_stream_data*  stream_data;
    stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
    if (!stream_data) {
        return 0;
    }
    len = len > sizeof(stream_data->data) - stream_data->datalen ? sizeof(stream_data->data) - stream_data->datalen : len;
    memcpy(stream_data->data + stream_data->datalen, data, len);
    stream_data->datalen += len;
    return 0;
}

static void initialize_nghttp2_session(http2_session_data* session_data)
{
    nghttp2_session_callbacks* callbacks;

    nghttp2_session_callbacks_new(&callbacks);

    nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);

    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
        on_frame_recv_callback);

    nghttp2_session_callbacks_set_on_stream_close_callback(
        callbacks, on_stream_close_callback);

    nghttp2_session_callbacks_set_on_header_callback(callbacks,
        on_header_callback);

    nghttp2_session_callbacks_set_on_begin_headers_callback(
        callbacks, on_begin_headers_callback);

    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);

    nghttp2_session_server_new(&session_data->session, callbacks, session_data);

    nghttp2_session_callbacks_del(callbacks);
}

/* Send HTTP/2 client connection header, which includes 24 bytes
   magic octets and SETTINGS frame */
static int send_server_connection_header(http2_session_data* session_data)
{
    nghttp2_settings_entry iv[1] = {
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 }
    };
    int rv;

    rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv,
        ARRLEN(iv));
    if (rv != 0) {
        warnx("Fatal error: %s", nghttp2_strerror(rv));
        return -1;
    }
    return 0;
}

/* readcb for bufferevent after client connection header was
   checked. */
static void readcb(struct bufferevent* bev, void* ptr)
{
    http2_session_data* session_data = (http2_session_data*)ptr;
    (void)bev;

    if (session_recv(session_data) != 0) {
        delete_http2_session_data(session_data);
        return;
    }
}

/* writecb for bufferevent. To greaceful shutdown after sending or
   receiving GOAWAY, we check the some conditions on the nghttp2
   library and output buffer of bufferevent. If it indicates we have
   no business to this session, tear down the connection. If the
   connection is not going to shutdown, we call session_send() to
   process pending data in the output buffer. This is necessary
   because we have a threshold on the buffer size to avoid too much
   buffering. See send_callback(). */
static void writecb(struct bufferevent* bev, void* ptr)
{
    http2_session_data* session_data = (http2_session_data*)ptr;
    if (evbuffer_get_length(bufferevent_get_output(bev)) > 0) {
        return;
    }
    if (nghttp2_session_want_read(session_data->session) == 0 && nghttp2_session_want_write(session_data->session) == 0) {
        delete_http2_session_data(session_data);
        return;
    }
    if (session_send(session_data) != 0) {
        delete_http2_session_data(session_data);
        return;
    }
}

/* eventcb for bufferevent */
static void eventcb(struct bufferevent* bev, short events, void* ptr)
{
    http2_session_data* session_data = (http2_session_data*)ptr;
    if (events & BEV_EVENT_CONNECTED) {
        const unsigned char* alpn    = NULL;
        unsigned int         alpnlen = 0;
        SSL*                 ssl;
        (void)bev;

        fprintf(stderr, "%s connected\n", session_data->client_addr);

        ssl = bufferevent_openssl_get_ssl(session_data->bev);

#ifndef OPENSSL_NO_NEXTPROTONEG
        SSL_get0_next_proto_negotiated(ssl, &alpn, &alpnlen);
#endif /* !OPENSSL_NO_NEXTPROTONEG */
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
        if (alpn == NULL) {
            SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
        }
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */

        if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
            fprintf(stderr, "%s h2 is not negotiated\n", session_data->client_addr);
            delete_http2_session_data(session_data);
            return;
        }

        initialize_nghttp2_session(session_data);

        if (send_server_connection_header(session_data) != 0 || session_send(session_data) != 0) {
            delete_http2_session_data(session_data);
            return;
        }

        return;
    }
    // if (events & BEV_EVENT_EOF) {
    //   fprintf(stderr, "%s EOF\n", session_data->client_addr);
    // } else if (events & BEV_EVENT_ERROR) {
    //   fprintf(stderr, "%s network error\n", session_data->client_addr);
    // } else if (events & BEV_EVENT_TIMEOUT) {
    //   fprintf(stderr, "%s timeout\n", session_data->client_addr);
    // }
    delete_http2_session_data(session_data);
}

/* callback for evconnlistener */
static void acceptcb(struct evconnlistener* listener, int fd,
    struct sockaddr* addr, int addrlen, void* arg)
{
    app_context*        app_ctx = (app_context*)arg;
    http2_session_data* session_data;
    (void)listener;

    session_data = create_http2_session_data(app_ctx, fd, addr, addrlen);

    bufferevent_setcb(session_data->bev, readcb, writecb, eventcb, session_data);
}

static void start_listen(struct event_base* evbase, const char* service,
    app_context* app_ctx)
{
    int              rv;
    struct addrinfo  hints;
    struct addrinfo *res, *rp;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
    hints.ai_flags |= AI_ADDRCONFIG;
#endif /* AI_ADDRCONFIG */

    rv = getaddrinfo(NULL, service, &hints, &res);
    if (rv != 0) {
        errx(1, "Could not resolve server address");
    }
    for (rp = res; rp; rp = rp->ai_next) {
        struct evconnlistener* listener;
        listener = evconnlistener_new_bind(
            evbase, acceptcb, app_ctx, LEV_OPT_CLOSE_ON_FREE | conn_flags,
            listen_backlog, rp->ai_addr, (int)rp->ai_addrlen);
        if (listener) {
            freeaddrinfo(res);

            return;
        }
    }
    errx(1, "Could not start listener");
}

static void initialize_app_context(app_context* app_ctx, SSL_CTX* ssl_ctx,
    struct event_base* evbase)
{
    memset(app_ctx, 0, sizeof(app_context));
    app_ctx->ssl_ctx = ssl_ctx;
    app_ctx->evbase  = evbase;
}

static void run(const char* service, const char* key_file,
    const char* cert_file)
{
    SSL_CTX*           ssl_ctx;
    app_context        app_ctx;
    struct event_base* evbase;

    ssl_ctx = create_ssl_ctx(key_file, cert_file);
    evbase  = event_base_new();
    initialize_app_context(&app_ctx, ssl_ctx, evbase);
    start_listen(evbase, service, &app_ctx);

    event_base_loop(evbase, 0);

    event_base_free(evbase);
    SSL_CTX_free(ssl_ctx);
}

static void usage(void)
{
    printf(
        "usage: dumdohd [options] <port> <key.pem> <cert.pem>\n"
        /* -o            description                                                 .*/
        "  -D <num>      Do random disconnect on receive, 0-100 (percent)\n"
        "  -A            Use LEV_OPT_REUSEABLE on sockets\n"
        "  -R            Use LEV_OPT_REUSEABLE_PORT on sockets\n"
        "  -Q <num>      Use specified listen() queue size\n"
        "  -o <opt>      Enable special options/features, see -H\n"
        "  -h            Print this help and exit\n"
        "  -H            Print help about special options/features and exit\n"
        "  -V            Print version and exit\n");
}

static void usage2(void)
{
    printf(
        "usage: dumdohd .. -o <opt> ..\n"
        "  flip-qr-bit: Track DNS messages and flip the QR bit\n");
}

static void version(void)
{
    printf("dumdohd version " PACKAGE_VERSION "\n");
}

int main(int argc, char** argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "D:ARo:hHVQ:")) != -1) {
        switch (opt) {
        case 'D':
            random_disconnect = atoi(optarg);
            if (random_disconnect < 1 || random_disconnect > 100) {
                usage();
                return 2;
            }
            break;

        case 'A':
            conn_flags |= LEV_OPT_REUSEABLE;
            break;

        case 'R':
            conn_flags |= LEV_OPT_REUSEABLE_PORT;
            break;

        case 'h':
            usage();
            return 0;

        case 'H':
            usage2();
            return 0;

        case 'V':
            version();
            return 0;

        case 'Q':
            listen_backlog = atoi(optarg);
            if (listen_backlog < 1) {
                usage();
                return 2;
            }
            break;

        case 'o':
            if (!strcmp(optarg, "flip-qr-bit")) {
                flip_qr_bit = 1;
                printf("flipping QR bit\n");
                break;
            }
            fprintf(stderr, "unknown option: %s\n", optarg);
            // fallthrough

        default:
            usage();
            return 2;
        }
    }

    if (argc < optind + 3) {
        usage();
        exit(EXIT_FAILURE);
    }

    struct sigaction act;
    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &act, NULL);

    SSL_load_error_strings();
    SSL_library_init();
    srand(time(0));

    run(argv[optind], argv[optind + 1], argv[optind + 2]);
    return 0;
}
