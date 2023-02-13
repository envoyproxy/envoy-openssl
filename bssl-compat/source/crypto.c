#include <openssl/crypto.h>
#include <ossl/openssl/crypto.h>
#include <ossl/openssl/evp.h>


int FIPS_mode(void) {
  return ossl_FIPS_mode();
}
