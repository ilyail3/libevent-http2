#pragma once

#include <openssl/ossl_typ.h>
#include <cstdint>






typedef struct app_context {
    SSL_CTX *ssl_ctx;
    struct event_base *evbase;
} app_context;
