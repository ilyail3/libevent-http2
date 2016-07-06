#pragma once

#include "http2_session_data.h"

http2_session_data *create_http2_session_data(
        app_context *app_ctx,
        int fd,
        struct sockaddr *addr,
        int addrlen
);

void delete_http2_session_data(http2_session_data *session_data);