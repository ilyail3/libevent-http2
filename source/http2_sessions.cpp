//
// Created by ilya on 7/6/16.
//

#include <netdb.h>
#include <cstring>
#include <netinet/tcp.h>
#include <event2/bufferevent_ssl.h>
#include <cstdio>
#include <openssl/ssl.h>
#include "http2_sessions.h"
#include "ssl_config.h"
#include "http2_streams.h"

http2_session_data *create_http2_session_data(app_context *app_ctx,
                                                     int fd,
                                                     struct sockaddr *addr,
                                                     int addrlen) {
    int rv;
    http2_session_data *session_data;
    SSL *ssl;
    char host[NI_MAXHOST];
    int val = 1;

    ssl = create_ssl(app_ctx->ssl_ctx);
    session_data = (http2_session_data *) malloc(sizeof(http2_session_data));
    memset(session_data, 0, sizeof(http2_session_data));
    session_data->app_ctx = app_ctx;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &val, sizeof(val));
    session_data->bev = bufferevent_openssl_socket_new(
            app_ctx->evbase, fd, ssl, BUFFEREVENT_SSL_ACCEPTING,
            BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    rv = getnameinfo(addr, (socklen_t) addrlen, host, sizeof(host), NULL, 0,
                     NI_NUMERICHOST);
    if (rv != 0) {
        session_data->client_addr = strdup("(unknown)");
    } else {
        session_data->client_addr = strdup(host);
    }

    return session_data;
}

void delete_http2_session_data(http2_session_data *session_data) {
    http2_stream_data *stream_data;
    SSL *ssl = bufferevent_openssl_get_ssl(session_data->bev);
    fprintf(stderr, "%s disconnected\n", session_data->client_addr);
    if (ssl) {
        SSL_shutdown(ssl);
    }
    bufferevent_free(session_data->bev);
    nghttp2_session_del(session_data->session);
    for (stream_data = session_data->root.next; stream_data;) {
        http2_stream_data *next = stream_data->next;
        delete_http2_stream_data(stream_data);
        stream_data = next;
    }
    free(session_data->client_addr);
    free(session_data);
}
