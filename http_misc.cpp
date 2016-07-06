//
// Created by ilya on 7/6/16.
//
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "http_misc.h"

#define MRB_HTTP2_H2_PROTO "h2"
#define MRB_HTTP2_H2_16_PROTO "h2-16"
#define MRB_HTTP2_H2_14_PROTO "h2-14"

static void add_stream(http2_session_data *session_data, http2_stream_data *stream_data)
{
    stream_data->next = session_data->root.next;
    session_data->root.next = stream_data;
    stream_data->prev = &session_data->root;

    if (stream_data->next) {
        stream_data->next->prev = stream_data;
    }
}

static void remove_stream(http2_session_data *session_data, http2_stream_data *stream_data)
{
    stream_data->prev->next = stream_data->next;

    if (stream_data->next) {
        stream_data->next->prev = stream_data->prev;
    }
}

static bool check_selected_proto(const unsigned char *proto, unsigned int len)
{
  if (sizeof(MRB_HTTP2_H2_PROTO) == len && memcmp(MRB_HTTP2_H2_PROTO, proto, len) == 0)
    return true;
  if (sizeof(MRB_HTTP2_H2_16_PROTO) == len && memcmp(MRB_HTTP2_H2_16_PROTO, proto, len) == 0)
    return true;
  if (sizeof(MRB_HTTP2_H2_14_PROTO) == len && memcmp(MRB_HTTP2_H2_14_PROTO, proto, len) == 0)
    return true;

  return false;
}


static bool check_http2_npn_or_alpn(SSL *ssl)
{
  const unsigned char *next_proto = NULL;
  unsigned int next_proto_len = 0;

  SSL_get0_next_proto_negotiated(ssl, &next_proto, &next_proto_len);

  if (next_proto == NULL)
    SSL_get0_alpn_selected(ssl, &next_proto, &next_proto_len);

  if (next_proto == NULL || !check_selected_proto(next_proto, next_proto_len))
    return true;

  /* one more check */
  if (!check_http2_npn_or_alpn(ssl))
    return false;

  return true;
}

static SSL_CTX *http2_create_ssl_ctx(mrb_state *mrb, http2_config *config, const char *key_file,
                                         const char *cert_file)
{
    const unsigned char sid_ctx[] = "mruby-http2";
    SSL_CTX *ssl_ctx;
    EC_KEY *ecdh;

    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    ssl_ctx = SSL_CTX_new(SSLv23_server_method());

    if (!ssl_ctx) {
        ERR_error_string(ERR_get_error(), NULL);
    }
    SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
    SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_ECDH_USE);
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_options(ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

    // in reference to nghttp2
    if (SSL_CTX_set_cipher_list(ssl_ctx, DEFAULT_CIPHER_LIST) == 0) {
        mrb_raisef(mrb, E_RUNTIME_ERROR, "SSL_CTX_set_cipher_list failed: %S",
                   mrb_str_new_cstr(mrb, ERR_error_string(ERR_get_error(), NULL)));
    }
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_session_id_context(ssl_ctx, sid_ctx, sizeof(sid_ctx) - 1);
    SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_SERVER);

    ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ecdh) {
        mrb_raisef(mrb, E_RUNTIME_ERROR, "EC_KEY_new_by_curv_name failed: %S",
                   mrb_str_new_cstr(mrb, ERR_error_string(ERR_get_error(), NULL)));
    }
    SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
    EC_KEY_free(ecdh);

    if (config->dh_params_file) {
        set_dhparams(mrb, config, ssl_ctx);
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        mrb_raisef(mrb, E_RUNTIME_ERROR, "Could not read private key file %S", mrb_str_new_cstr(mrb, key_file));
    }
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1) {
        mrb_raisef(mrb, E_RUNTIME_ERROR, "Could not read certificate file %S", mrb_str_new_cstr(mrb, cert_file));
    }
    SSL_CTX_set_next_protos_advertised_cb(ssl_ctx, npn_advertise_cb, (void *)npn_proto);
#if MRB_HTTP2_USE_ALPN
    SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_cb, (void *)alpn_proto);
#endif
    TRACER;
    return ssl_ctx;
}

static http2_session_data *create_http2_session_data(app_context *app_ctx, int fd,
                                                     struct sockaddr *addr, int addrlen)
{
    int rv;
    http2_session_data *session_data;
    SSL *ssl;
    // char host[NI_MAXHOST];
    int val = 1;


    ssl = mrb_http2_create_ssl(mrb, app_ctx->ssl_ctx);

    session_data = (http2_session_data *)mrb_malloc(mrb, sizeof(http2_session_data));
    memset(session_data, 0, sizeof(http2_session_data));

    session_data->app_ctx = app_ctx;
    // return NULL when connection_record option diabled
    session_data->conn = mrb_http2_conn_rec_init(mrb, config);

    if (config->tcp_nopush) {
#ifdef TCP_CORK
        setsockopt(fd, IPPROTO_TCP, TCP_CORK, (char *)&val, sizeof(val));
#endif

#ifdef TCP_NOPUSH
        setsockopt(fd, IPPROTO_TCP, TCP_NOPUSH, (char *)&val, sizeof(val));
#endif
    }

    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));

    TRACER;
    session_data->bev = bufferevent_socket_new(app_ctx->evbase, fd, BEV_OPT_DEFER_CALLBACKS | BEV_OPT_CLOSE_ON_FREE);

    tune_packet_buffer(session_data->bev, config);

    if (ssl) {
        TRACER;

#if MRB_HTTP2_USE_ALPN
        if (!check_http2_npn_or_alpn(ssl))
      return NULL;
#endif

        session_data->bev =
                bufferevent_openssl_filter_new(app_ctx->evbase, session_data->bev, ssl, BUFFEREVENT_SSL_ACCEPTING,
                                               BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    }

    bufferevent_enable(session_data->bev, EV_READ | EV_WRITE);

    rv =
            getnameinfo(addr, addrlen, session_data->client_addr, sizeof(session_data->client_addr), NULL, 0, NI_NUMERICHOST);
    if (rv != 0) {
        memcpy(session_data->client_addr, "(unknown)", sizeof("(unknown)"));
    }
    if (session_data->conn) {
        session_data->conn->client_ip = session_data->client_addr;
    }
    session_data->upstream_base = NULL;
    session_data->upstream_conn = NULL;

    if (config->server_status) {
        server->worker->session_requests_per_worker++;
        server->worker->connected_sessions++;
    }

    return session_data;
}
