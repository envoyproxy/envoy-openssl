#include <openssl/ssl.h>
#include <ossl/openssl/ssl.h>


const SSL_METHOD *TLS_server_method(void) {
  return ossl_TLS_server_method();
}

const SSL_METHOD *TLS_client_method(void) {
  return ossl_TLS_client_method();
}

/*
 * On error, it returns a negative value. On success, it returns the length of
 * the result and outputs it via outp as follows:
 * 
 * If outp is NULL, the function writes nothing. This mode can be used to size
 * buffers. 
 * 
 * If outp is non-NULL but *outp is NULL, the function sets *outp to a newly
 * allocated buffer containing the result. The caller is responsible for
 * releasing *outp with OPENSSL_free. This mode is recommended for most callers.
 * 
 * If outp and *outp are non-NULL, the function writes the result to *outp,
 * which must have enough space available, and advances *outp just past the
 * output.
 */
int i2d_X509(X509 *x509, uint8_t **outp) {
  ossl_BIO *bio = ossl_BIO_new(ossl_BIO_s_mem());
  int length = -1;

  if (ossl_i2d_X509_bio(bio, x509)) { // 1=success,0=failure
    char *buf = NULL;
    length = ossl_BIO_get_mem_data(bio, &buf);

    if (outp) {
      if (*outp == NULL) {
        *outp = ossl_OPENSSL_memdup(buf, length);
      }
      else {
        ossl_OPENSSL_strlcpy((char*)*outp, buf, length);
      }
    }
  }

  ossl_BIO_free(bio);

  return length;
}

SSL_SESSION *SSL_SESSION_new(const SSL_CTX *ctx) {
  return ossl_SSL_SESSION_new();
}