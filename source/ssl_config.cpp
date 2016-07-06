//
// Created by ilya on 7/6/16.
//
#include <cstdio>
#include <openssl/tls1.h>
#include <openssl/ec.h>
#include <openssl/ssl.h>
#include <err.h>
#include <openssl/err.h>
#include <nghttp2/nghttp2.h>
#include "unused.h"

#include "ssl_config.h"


static unsigned char next_proto_list[256];
static size_t next_proto_list_len;

static int next_proto_cb(
        SSL *s _U_,
        const unsigned char **data,
        unsigned int *len,
        void *arg _U_
) {
    *data = next_proto_list;
    *len = (unsigned int) next_proto_list_len;
    return SSL_TLSEXT_ERR_OK;
}

/* Create SSL object */
SSL *create_ssl(SSL_CTX *ssl_ctx) {
    SSL *ssl;
    ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        errx(1, "Could not create SSL/TLS session object: %s",
             ERR_error_string(ERR_get_error(), NULL));
    }
    return ssl;
}

/* Create SSL_CTX. */
SSL_CTX *create_ssl_ctx(
        const char *key_file,
        const char *cert_file
) {
    SSL_CTX *ssl_ctx;
    EC_KEY *ecdh;

    ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ssl_ctx) {
        errx(1, "Could not create SSL/TLS context: %s",
             ERR_error_string(ERR_get_error(), NULL));
    }

    SSL_CTX_set_options(ssl_ctx,
                        SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                        SSL_OP_NO_COMPRESSION |
                        SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

    ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ecdh) {
        errx(1, "EC_KEY_new_by_curv_name failed: %s",
             ERR_error_string(ERR_get_error(), NULL));
    }
    SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
    EC_KEY_free(ecdh);

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        errx(1, "Could not read private key file %s", key_file);
    }
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1) {
        errx(1, "Could not read certificate file %s", cert_file);
    }

    next_proto_list[0] = NGHTTP2_PROTO_VERSION_ID_LEN;
    memcpy(&next_proto_list[1], NGHTTP2_PROTO_VERSION_ID,
           NGHTTP2_PROTO_VERSION_ID_LEN);
    next_proto_list_len = 1 + NGHTTP2_PROTO_VERSION_ID_LEN;

    SSL_CTX_set_next_protos_advertised_cb(ssl_ctx, next_proto_cb, NULL);
    return ssl_ctx;
}

