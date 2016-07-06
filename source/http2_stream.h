#pragma once

#include <cstdint>
#include <cstdio>
#include "http2_server.h"

typedef struct http2_request_body {
    char *data;
    int64_t len;
    size_t pos;
    unsigned int last : 1;
} http2_request_body;


typedef struct http2_stream_data {
    struct http2_stream_data *prev, *next;

    char *request_path;
    char *method;

    http2_request_body *request_body;

    int32_t stream_id;
    int fd;
} http2_stream_data;