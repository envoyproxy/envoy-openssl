#include <openssl/pkcs8.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/225e8d39b50757af56e61cd0aa7958c56c487d54/include/openssl/pkcs8.h#L236
 * https://www.openssl.org/docs/man3.0/man3/PKCS12_free.html
 */
extern "C" void PKCS12_free(PKCS12 *p12) {
  ossl.ossl_PKCS12_free(p12);
}
