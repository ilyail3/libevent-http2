#pragma once

#include <cstdint>
#include <nghttp2/nghttp2.h>
#include <cstring>
#include <zconf.h>
#include <evhttp.h>
#include "http_misc.h"
#include "http_stream_data.h"




static http2_stream_data *create_http2_stream_data(http2_session_data *session_data, int32_t stream_id);

static void delete_http2_stream_data(http2_session_data *session_data, http2_stream_data *stream_data);