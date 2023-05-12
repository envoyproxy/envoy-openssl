#include <openssl/crypto.h>
#include <ossl/openssl/evp.h>


int FIPS_mode(void) {
  return ossl_EVP_default_properties_is_fips_enabled(NULL);
}
