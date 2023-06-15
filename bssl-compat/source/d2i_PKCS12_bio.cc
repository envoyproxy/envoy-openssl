#include <openssl/pkcs8.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/225e8d39b50757af56e61cd0aa7958c56c487d54/include/openssl/pkcs8.h#L152
 * https://www.openssl.org/docs/man3.0/man3/d2i_PKCS12_bio.html
 */
extern "C" PKCS12* d2i_PKCS12_bio(BIO *bio, PKCS12 **out_p12) {
  return ossl.ossl_d2i_PKCS12_bio(bio, out_p12);
}
