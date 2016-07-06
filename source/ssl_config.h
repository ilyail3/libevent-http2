#pragma once

#include <openssl/ossl_typ.h>

SSL *create_ssl(SSL_CTX *ssl_ctx);
SSL_CTX *create_ssl_ctx(const char *key_file, const char *cert_file);