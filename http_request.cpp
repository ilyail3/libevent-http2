//
// Created by ilya on 7/6/16.
//
#include "http_request.h"

static http2_stream_data *create_http2_stream_data(http2_session_data *session_data, int32_t stream_id)
{
    http2_stream_data *stream_data;

    stream_data = (http2_stream_data *)malloc(sizeof(http2_stream_data));
    memset(stream_data, 0, sizeof(http2_stream_data));
    stream_data->stream_id = stream_id;
    stream_data->fd = -1;
    stream_data->readleft = 0;
    stream_data->nvlen = 0;
    stream_data->request_body = nullptr;
    stream_data->request_args = nullptr;
    stream_data->request_path = nullptr;
    stream_data->unparsed_uri = nullptr;
    stream_data->percent_encode_uri = nullptr;
    stream_data->method[0] = '\0';
    stream_data->scheme[0] = '\0';
    stream_data->authority[0] = '\0';
    stream_data->upstream_req = nullptr;

    add_stream(session_data, stream_data);

    return stream_data;
};

static void delete_http2_stream_data(http2_session_data *session_data, http2_stream_data *stream_data)
{

    if (stream_data->fd != -1) {
        close(stream_data->fd);
    }
    free(stream_data->unparsed_uri);

    if(stream_data->percent_encode_uri != nullptr)
        free(stream_data->percent_encode_uri);

    if (stream_data->request_args != nullptr) {
        free(stream_data->request_path);
        free(stream_data->request_args);
    }
    if (stream_data->request_body != NULL) {
        stream_data->request_body->len = 0;
        stream_data->request_body->pos = 0;
        stream_data->request_body->last = 0;

        free(stream_data->request_body->data);
        free(stream_data->request_body);
    }
    if (stream_data->upstream_req != NULL) {
        evhttp_request_free(stream_data->upstream_req);
    }

    free(stream_data);
};