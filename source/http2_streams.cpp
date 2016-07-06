//
// Created by ilya on 7/6/16.
//
#include <cstring>
#include <zconf.h>
#include <cctype>
#include "http2_streams.h"

void add_stream(http2_session_data *session_data,
                http2_stream_data *stream_data) {
    stream_data->next = session_data->root.next;
    session_data->root.next = stream_data;
    stream_data->prev = &session_data->root;
    if (stream_data->next) {
        stream_data->next->prev = stream_data;
    }
}

void remove_stream(http2_session_data *session_data _U_,
                   http2_stream_data *stream_data) {
    stream_data->prev->next = stream_data->next;
    if (stream_data->next) {
        stream_data->next->prev = stream_data->prev;
    }
}


http2_stream_data *create_http2_stream_data(http2_session_data *session_data, int32_t stream_id) {
    http2_stream_data *stream_data;
    stream_data = (http2_stream_data *) malloc(sizeof(http2_stream_data));
    memset(stream_data, 0, sizeof(http2_stream_data));
    stream_data->stream_id = stream_id;
    stream_data->fd = -1;

    stream_data->request_path = nullptr;
    stream_data->method = nullptr;
    stream_data->request_body = nullptr;

    add_stream(session_data, stream_data);
    return stream_data;
}

void delete_http2_stream_data(http2_stream_data *stream_data) {
    if (stream_data->fd != -1) {
        close(stream_data->fd);
    }

    free(stream_data->request_path);
    free(stream_data->method);

    free(stream_data);
}

/* Returns int value of hex string character |c| */
static uint8_t hex_to_uint(uint8_t c) {
    if ('0' <= c && c <= '9') {
        return (uint8_t) (c - '0');
    }
    if ('A' <= c && c <= 'F') {
        return (uint8_t) (c - 'A' + 10);
    }
    if ('a' <= c && c <= 'f') {
        return (uint8_t) (c - 'a' + 10);
    }
    return 0;
}

/* Decodes percent-encoded byte string |value| with length |valuelen|
   and returns the decoded byte string in allocated buffer. The return
   value is NULL terminated. The caller must free the returned
   string. */
static char *percent_decode(const uint8_t *value, size_t valuelen) {
    char *res;

    res = (char *) malloc(valuelen + 1);
    if (valuelen > 3) {
        size_t i, j;
        for (i = 0, j = 0; i < valuelen - 2;) {
            if (value[i] != '%' || !isxdigit(value[i + 1]) ||
                !isxdigit(value[i + 2])) {
                res[j++] = (char) value[i++];
                continue;
            }
            res[j++] =
                    (char) ((hex_to_uint(value[i + 1]) << 4) + hex_to_uint(value[i + 2]));
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


const char PATH[] = ":path";
const char METHOD[] = ":method";

void handle_header(
        http2_stream_data *stream_data,
        const uint8_t *name,
        size_t namelen,
        const uint8_t *value,
        size_t valuelen
) {
    if (namelen == sizeof(PATH) - 1 && memcmp(PATH, name, namelen) == 0) {
        size_t j;

        for (j = 0; j < valuelen && value[j] != '?'; ++j);
        stream_data->request_path = percent_decode(value, j);
    }
    else if (namelen == sizeof(METHOD) - 1 && memcmp(METHOD, name, namelen) == 0) {
        size_t j;

        for (j = 0; j < valuelen && value[j] != '?'; ++j);
        stream_data->method = percent_decode(value, j);
    }
}