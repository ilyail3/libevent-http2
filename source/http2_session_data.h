#pragma once

#include <nghttp2/nghttp2.h>
#include "http2_server.h"
#include "http2_stream.h"

typedef struct http2_session_data {
    struct http2_stream_data root;
    struct bufferevent *bev;
    app_context *app_ctx;
    nghttp2_session *session;
    char *client_addr;
} http2_session_data;