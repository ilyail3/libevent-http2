#pragma once

#include <nghttp2/nghttp2.h>
#include <openssl/ossl_typ.h>
#include "http_stream_data.h"

struct app_context;
typedef struct app_context app_context;

typedef struct http2_config {
    const char* dh_params_file;
} http2_config;

typedef struct http2_server {
    http2_config *config;
} http2_server;

typedef struct {
    SSL_CTX *ssl_ctx;
    struct event_base *evbase;
    struct http2_server* server;
} app_context;

typedef struct http2_session_data {
    struct http2_stream_data root;
    struct bufferevent *bev;
    app_context *app_ctx;
    nghttp2_session *session;
    char *client_addr;
} http2_session_data;

static void add_stream(http2_session_data *session_data, http2_stream_data *stream_data);

static void remove_stream(http2_session_data *session_data, http2_stream_data *stream_data);



static http2_session_data *create_http2_session_data(app_context *app_ctx, int fd,
                                                     struct sockaddr *addr, int addrlen);