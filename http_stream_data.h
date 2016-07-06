#pragma once

#include <cstdint>
#include <cstdio>
#include <nghttp2/nghttp2.h>

#define HTTP2_HEADER_MAX_LENGTH 256

typedef struct http2_request_body {
    char *data;
    int64_t len;
    size_t pos;
    unsigned int last : 1;
} http2_request_body;

typedef struct http2_stream_data {
    struct http2_stream_data *prev, *next;
    char *request_path;
    char *request_args;
    http2_request_body *request_body;
    char *unparsed_uri;
    char *percent_encode_uri;
    char method[16];
    char scheme[8];
    char authority[1024];
    int32_t stream_id;
    int fd;
    int64_t readleft;
    nghttp2_nv nva[HTTP2_HEADER_MAX_LENGTH];
    size_t nvlen;
    struct evhttp_request *upstream_req;
} http2_stream_data;