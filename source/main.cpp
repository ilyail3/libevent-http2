/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifdef __sgi
#define errx(exitcode, format, args...)                                        \
  {                                                                            \
    warnx(format, ##args);                                                     \
    exit(exitcode);                                                            \
  }
#define warn(format, args...) warnx(format ": %s", ##args, strerror(errno))
#define warnx(format, args...) fprintf(stderr, format "\n", ##args)
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif /* HAVE_NETDB_H */

#include <signal.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif /* HAVE_FCNTL_H */

#include <ctype.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */

#include <netinet/tcp.h>

#ifndef __sgi

#include <err.h>
#include "http2_server.h"
#include "unused.h"
#include "ssl_config.h"
#include "http2_session_data.h"
#include "http2_streams.h"
#include "http2_sessions.h"

#endif

#include <string.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/conf.h>

#include <event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>

#include <nghttp2/nghttp2.h>
#include <zconf.h>
#include <fcntl.h>

#define OUTPUT_WOULDBLOCK_THRESHOLD (1 << 16)
#define HTTP2_MAX_POST_DATA_SIZE 1 << 24

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *) NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,   \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }





/* Serialize the frame and send (or buffer) the data to
   bufferevent. */
static int session_send(http2_session_data *session_data) {
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
static int session_recv(http2_session_data *session_data) {
    ssize_t readlen;
    struct evbuffer *input = bufferevent_get_input(session_data->bev);
    size_t datalen = evbuffer_get_length(input);
    unsigned char *data = evbuffer_pullup(input, -1);

    readlen = nghttp2_session_mem_recv(session_data->session, data, datalen);
    if (readlen < 0) {
        warnx("Fatal error: %s", nghttp2_strerror((int) readlen));
        return -1;
    }
    if (evbuffer_drain(input, (size_t) readlen) != 0) {
        warnx("Fatal error: evbuffer_drain failed");
        return -1;
    }
    if (session_send(session_data) != 0) {
        return -1;
    }
    return 0;
}

static ssize_t send_callback(nghttp2_session *session _U_, const uint8_t *data,
                             size_t length, int flags _U_, void *user_data) {
    http2_session_data *session_data = (http2_session_data *) user_data;
    struct bufferevent *bev = session_data->bev;
    /* Avoid excessive buffering in server side. */
    if (evbuffer_get_length(bufferevent_get_output(session_data->bev)) >=
        OUTPUT_WOULDBLOCK_THRESHOLD) {
        return NGHTTP2_ERR_WOULDBLOCK;
    }
    bufferevent_write(bev, data, length);
    return (ssize_t) length;
}

/* Returns nonzero if the string |s| ends with the substring |sub| */
static int ends_with(const char *s, const char *sub) {
    size_t slen = strlen(s);
    size_t sublen = strlen(sub);
    if (slen < sublen) {
        return 0;
    }
    return memcmp(s + slen - sublen, sub, sublen) == 0;
}





static ssize_t file_read_callback(nghttp2_session *session _U_,
                                  int32_t stream_id _U_, uint8_t *buf,
                                  size_t length, uint32_t *data_flags,
                                  nghttp2_data_source *source,
                                  void *user_data _U_) {
    int fd = source->fd;
    ssize_t r;
    while ((r = read(fd, buf, length)) == -1 && errno == EINTR);
    if (r == -1) {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    if (r == 0) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    return r;
}

static int send_response(nghttp2_session *session, int32_t stream_id,
                         nghttp2_nv *nva, size_t nvlen, int fd) {
    int rv;
    nghttp2_data_provider data_prd;
    data_prd.source.fd = fd;
    data_prd.read_callback = file_read_callback;

    rv = nghttp2_submit_response(session, stream_id, nva, nvlen, &data_prd);
    if (rv != 0) {
        warnx("Fatal error: %s", nghttp2_strerror(rv));
        return -1;
    }
    return 0;
}

static const char ERROR_HTML[] = "<html><head><title>404</title></head>"
        "<body><h1>404 Not Found</h1></body></html>";

static int error_reply(nghttp2_session *session,
                       http2_stream_data *stream_data) {
    int rv;
    ssize_t writelen;
    int pipefd[2];
    nghttp2_nv hdrs[] = {MAKE_NV(":status", "404")};

    rv = pipe(pipefd);
    if (rv != 0) {
        warn("Could not create pipe");
        rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                       stream_data->stream_id,
                                       NGHTTP2_INTERNAL_ERROR);
        if (rv != 0) {
            warnx("Fatal error: %s", nghttp2_strerror(rv));
            return -1;
        }
        return 0;
    }

    writelen = write(pipefd[1], ERROR_HTML, sizeof(ERROR_HTML) - 1);
    close(pipefd[1]);

    if (writelen != sizeof(ERROR_HTML) - 1) {
        close(pipefd[0]);
        return -1;
    }

    stream_data->fd = pipefd[0];

    if (send_response(session, stream_data->stream_id, hdrs, ARRLEN(hdrs),
                      pipefd[0]) != 0) {
        close(pipefd[0]);
        return -1;
    }
    return 0;
}

static int time_reply(nghttp2_session *session,
                      http2_stream_data *stream_data){
    int rv;
    ssize_t writelen;
    int pipefd[2];
    nghttp2_nv hdrs[] = {MAKE_NV(":status", "200"), MAKE_NV("content-type", "text/plain")};

    rv = pipe(pipefd);
    if (rv != 0) {
        warn("Could not create pipe");
        rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                       stream_data->stream_id,
                                       NGHTTP2_INTERNAL_ERROR);
        if (rv != 0) {
            warnx("Fatal error: %s", nghttp2_strerror(rv));
            return -1;
        }
        return 0;
    }


    char buffer[50];

    time_t now;
    time(&now);
    size_t time_length = strftime(buffer, sizeof buffer, "%FT%TZ", gmtime(&now));

    writelen = write(pipefd[1], buffer, time_length - 1);
    close(pipefd[1]);

    if (writelen != time_length - 1) {
        close(pipefd[0]);
        return -1;
    }

    stream_data->fd = pipefd[0];

    if (send_response(session, stream_data->stream_id, hdrs, ARRLEN(hdrs),
                      pipefd[0]) != 0) {
        close(pipefd[0]);
        return -1;
    }
    return 0;
}

/* nghttp2_on_header_callback: Called when nghttp2 library emits
   single header name/value pair. */
static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, const uint8_t *name,
                              size_t namelen, const uint8_t *value,
                              size_t valuelen, uint8_t flags _U_,
                              void *user_data _U_) {
    http2_stream_data *stream_data;

    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
                break;
            }

            stream_data =
                    (http2_stream_data *)nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

            if (!stream_data) {
                break;
            }

            handle_header(stream_data, name, namelen, value, valuelen);

            break;
    }
    return 0;
}

static int on_begin_headers_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
    http2_session_data *session_data = (http2_session_data *) user_data;
    http2_stream_data *stream_data;

    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }
    stream_data = create_http2_stream_data(session_data, frame->hd.stream_id);
    nghttp2_session_set_stream_user_data(session, frame->hd.stream_id,
                                         stream_data);
    return 0;
}

/* Minimum check for directory traversal. Returns nonzero if it is
   safe. */
static int check_path(const char *path) {
    /* We don't like '\' in url. */
    return path[0] && path[0] == '/' && strchr(path, '\\') == NULL &&
           strstr(path, "/../") == NULL && strstr(path, "/./") == NULL &&
           !ends_with(path, "/..") && !ends_with(path, "/.");
}

static int on_request_recv(nghttp2_session *session,
                           http2_session_data *session_data,
                           http2_stream_data *stream_data) {
    int fd;
    nghttp2_nv hdrs[] = {
            MAKE_NV(":status", "200")
    };

    char *rel_path;

    if (!stream_data->request_path) {
        if (error_reply(session, stream_data) != 0) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    fprintf(stderr, "%s %s %s\n",
            session_data->client_addr,
            stream_data->method,
            stream_data->request_path
    );

    if (!check_path(stream_data->request_path)) {
        if (error_reply(session, stream_data) != 0) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }
    for (rel_path = stream_data->request_path; *rel_path == '/'; ++rel_path);
    if(strcmp(rel_path,"time") == 0){
        if(time_reply(session, stream_data) != 0){
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    } else {
        fd = open(rel_path, O_RDONLY);
        if (fd == -1) {
            if (error_reply(session, stream_data) != 0) {
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            return 0;
        }
        stream_data->fd = fd;

        if (send_response(session, stream_data->stream_id, hdrs, ARRLEN(hdrs), fd) !=
            0) {
            close(fd);
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }
}

static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
    http2_session_data *session_data = (http2_session_data *) user_data;
    http2_stream_data *stream_data;
    switch (frame->hd.type) {
        case NGHTTP2_DATA:
        case NGHTTP2_HEADERS:
            /* Check that the client request has finished */
            if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                stream_data =
                        (http2_stream_data *) nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
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

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code _U_, void *user_data) {
    http2_session_data *session_data = (http2_session_data *) user_data;
    http2_stream_data *stream_data;

    stream_data = (http2_stream_data *) nghttp2_session_get_stream_user_data(session, stream_id);
    if (!stream_data) {
        return 0;
    }
    remove_stream(session_data, stream_data);
    delete_http2_stream_data(stream_data);
    return 0;
}

static int server_on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id,
                                              const uint8_t *data, size_t len, void *user_data)
{
    http2_session_data *session_data = (http2_session_data *)user_data;
    http2_stream_data* stream_data = (http2_stream_data*)nghttp2_session_get_stream_user_data(session, stream_id);
    int rv;


    // TODO: buffering and stored file or memory, currently store len byte
    // when callback only once
    if (stream_data->request_body == nullptr) {
        stream_data->request_body = (http2_request_body*)malloc(sizeof(http2_request_body));
        memset(stream_data->request_body, 0, sizeof(http2_request_body));
    }

    if (stream_data->request_body->last) {
        fprintf(stderr, "request_body length reached MRB_HTTP2_MAX_POST_DATA_SIZE");
        rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, stream_data->stream_id, NGHTTP2_INTERNAL_ERROR);
        if (rv != 0) {
            fprintf(stderr, "Fatal error: %s", nghttp2_strerror(rv));
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    } else {
        char *pos;
        stream_data->request_body->len += len;
        if (stream_data->request_body->len >= HTTP2_MAX_POST_DATA_SIZE) {
            fprintf(stderr, "post data length(%ld) exceed "
                            "MRB_HTTP2_MAX_POST_DATA_SIZE(%d)\n",
                    (long)stream_data->request_body->len, HTTP2_MAX_POST_DATA_SIZE);
            stream_data->request_body->len = HTTP2_MAX_POST_DATA_SIZE;
            stream_data->request_body->last = 1;
            rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, stream_data->stream_id, NGHTTP2_INTERNAL_ERROR);
            if (rv != 0) {
                fprintf(stderr, "Fatal error: %s", nghttp2_strerror(rv));
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
            return 0;
        }

        stream_data->request_body->data =
                (char *)realloc(stream_data->request_body->data, stream_data->request_body->len + 1);
        pos = stream_data->request_body->data;
        pos += stream_data->request_body->pos;
        memcpy(pos, data, stream_data->request_body->len - stream_data->request_body->pos);
        stream_data->request_body->pos += len;
        stream_data->request_body->data[stream_data->request_body->len] = '\0';
    }

    return 0;
}

static void initialize_nghttp2_session(http2_session_data *session_data) {
    nghttp2_session_callbacks *callbacks;

    nghttp2_session_callbacks_new(&callbacks);

    nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);

    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                         on_frame_recv_callback);

    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, server_on_data_chunk_recv_callback);

    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);

    nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                     on_header_callback);

    nghttp2_session_callbacks_set_on_begin_headers_callback(
            callbacks, on_begin_headers_callback);

    nghttp2_session_server_new(&session_data->session, callbacks, session_data);

    nghttp2_session_callbacks_del(callbacks);
}

/* Send HTTP/2 client connection header, which includes 24 bytes
   magic octets and SETTINGS frame */
static int send_server_connection_header(http2_session_data *session_data) {
    nghttp2_settings_entry iv[1] = {
            {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
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
static void readcb(struct bufferevent *bev _U_, void *ptr) {
    http2_session_data *session_data = (http2_session_data *) ptr;
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
static void writecb(struct bufferevent *bev, void *ptr) {
    http2_session_data *session_data = (http2_session_data *) ptr;
    if (evbuffer_get_length(bufferevent_get_output(bev)) > 0) {
        return;
    }
    if (nghttp2_session_want_read(session_data->session) == 0 &&
        nghttp2_session_want_write(session_data->session) == 0) {
        delete_http2_session_data(session_data);
        return;
    }
    if (session_send(session_data) != 0) {
        delete_http2_session_data(session_data);
        return;
    }
}

/* eventcb for bufferevent */
static void eventcb(struct bufferevent *bev _U_, short events, void *ptr) {
    http2_session_data *session_data = (http2_session_data *) ptr;
    if (events & BEV_EVENT_CONNECTED) {
        fprintf(stderr, "%s connected\n", session_data->client_addr);

        initialize_nghttp2_session(session_data);

        if (send_server_connection_header(session_data) != 0) {
            delete_http2_session_data(session_data);
            return;
        }

        return;
    }
    if (events & BEV_EVENT_EOF) {
        fprintf(stderr, "%s EOF\n", session_data->client_addr);
    } else if (events & BEV_EVENT_ERROR) {
        fprintf(stderr, "%s network error\n", session_data->client_addr);
    } else if (events & BEV_EVENT_TIMEOUT) {
        fprintf(stderr, "%s timeout\n", session_data->client_addr);
    }
    delete_http2_session_data(session_data);
}

/* callback for evconnlistener */
static void acceptcb(struct evconnlistener *listener _U_, int fd,
                     struct sockaddr *addr, int addrlen, void *arg) {
    app_context *app_ctx = (app_context *) arg;
    http2_session_data *session_data;

    session_data = create_http2_session_data(app_ctx, fd, addr, addrlen);

    bufferevent_setcb(session_data->bev, readcb, writecb, eventcb, session_data);
}

static void start_listen(struct event_base *evbase, const char *service,
                         app_context *app_ctx) {
    int rv;
    struct addrinfo hints;
    struct addrinfo *res, *rp;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
    hints.ai_flags |= AI_ADDRCONFIG;
#endif /* AI_ADDRCONFIG */

    rv = getaddrinfo(NULL, service, &hints, &res);
    if (rv != 0) {
        errx(1, "Could not resolve server address");
    }
    for (rp = res; rp; rp = rp->ai_next) {
        struct evconnlistener *listener;
        listener = evconnlistener_new_bind(
                evbase, acceptcb, app_ctx, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
                16, rp->ai_addr, (int) rp->ai_addrlen);
        if (listener) {
            freeaddrinfo(res);

            return;
        }
    }
    errx(1, "Could not start listener");
}

static void initialize_app_context(app_context *app_ctx, SSL_CTX *ssl_ctx,
                                   struct event_base *evbase) {
    memset(app_ctx, 0, sizeof(app_context));
    app_ctx->ssl_ctx = ssl_ctx;
    app_ctx->evbase = evbase;
}

static void run(const char *service, const char *key_file,
                const char *cert_file) {
    SSL_CTX *ssl_ctx;
    app_context app_ctx;
    struct event_base *evbase;

    ssl_ctx = create_ssl_ctx(key_file, cert_file);
    evbase = event_base_new();
    initialize_app_context(&app_ctx, ssl_ctx, evbase);
    start_listen(evbase, service, &app_ctx);

    event_base_loop(evbase, 0);

    event_base_free(evbase);
    SSL_CTX_free(ssl_ctx);
}

int main(int argc, char **argv) {
    struct sigaction act;

    if (argc < 4) {
        fprintf(stderr, "Usage: libevent-server PORT KEY_FILE CERT_FILE\n");
        exit(EXIT_FAILURE);
    }

    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &act, NULL);

#ifndef OPENSSL_IS_BORINGSSL
    OPENSSL_config(NULL);
#endif /* OPENSSL_IS_BORINGSSL */
    SSL_load_error_strings();
    SSL_library_init();

    run(argv[1], argv[2], argv[3]);
    return 0;
}