#include <openssl/pem.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/b9ec9dee569854ac3dee909b9dfe8c1909a6c751/include/openssl/pem.h#L350
 * https://www.openssl.org/docs/man3.0/man3/PEM_X509_INFO_read_bio.html
 */
extern "C" STACK_OF(X509_INFO) *PEM_X509_INFO_read_bio(BIO *bp, STACK_OF(X509_INFO) *sk, pem_password_cb *cb, void *u) {
  auto ret {ossl.ossl_PEM_X509_INFO_read_bio(bp, reinterpret_cast<ossl_STACK_OF(ossl_X509_INFO)*>(sk), cb, u)};
  return reinterpret_cast<STACK_OF(X509_INFO)*>(ret);
}
