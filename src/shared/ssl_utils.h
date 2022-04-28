#ifndef _SSL_UTILS_H_
#define _SSL_UTILS_H_

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;

int sslutil_init_ssl(SSL *ssl, const char *certpath, const char *keypath);

#endif
