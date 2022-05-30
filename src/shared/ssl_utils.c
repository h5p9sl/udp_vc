#include "ssl_utils.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

int sslutil_init_ssl(SSL *ssl, const char *certpath, const char *keypath) {

  int fail(const char *err_str, FILE *err_out) {
    ERR_print_errors_fp(err_out);
    fputs(err_str, err_out);
    return -1;
  }

  if (SSL_use_certificate_file(ssl, certpath, SSL_FILETYPE_PEM) != 1)
    return fail("SSL_CTX_use_certificate_file failed", stderr);
  if (SSL_use_PrivateKey_file(ssl, keypath, SSL_FILETYPE_PEM) != 1)
    return fail("SSL_CTX_use_PrivateKey_file failed", stderr);
  if (SSL_check_private_key(ssl) != 1)
    return fail("SSL_CTX_check_private_key failed", stderr);

  return 0;
}
