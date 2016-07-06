#pragma once

#include "http2_session_data.h"
#include "unused.h"

void add_stream(
        http2_session_data *session_data,
        http2_stream_data *stream_data
);

void remove_stream(
        http2_session_data *session_data _U_,
        http2_stream_data *stream_data
);

http2_stream_data *create_http2_stream_data(
        http2_session_data *session_data,
        int32_t stream_id
);

void delete_http2_stream_data(http2_stream_data *stream_data);

void handle_header(
        http2_stream_data *stream_data,
        const uint8_t *name,
        size_t namelen,
        const uint8_t *value,
        size_t valuelen
);