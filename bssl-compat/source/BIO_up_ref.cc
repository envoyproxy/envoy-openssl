#include <openssl/bio.h>
#include <ossl/openssl/bio.h>


/*
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/BIO_up_ref.html
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/bio.h#L101
 */
extern "C" int BIO_up_ref(BIO *bio) {
  return ossl_BIO_up_ref(bio);
}

