#ifndef _SSL_UTILS_H_
#define _SSL_UTILS_H_

#include <openssl/err.h>
#include <openssl/ssl.h>

int sslutil_init_ssl(SSL *ssl, const char *certpath, const char *keypath);

#endif
