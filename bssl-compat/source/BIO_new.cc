#include <openssl/bio.h>
#include <ossl.h>
#include "bio_meth_map.h"


/*
 * OSSL: https://github.com/openssl/openssl/blob/ac3cef223a4c61d6bee34527b6d4c8c6432494a7/include/openssl/bio.h#L549
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/BIO_new.html
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/bio.h#L82
 *
 * The OpenSSL docs say nothing about the reference count of the new BIO, whereas the BoringSSL
 * docs say that it will have a reference count of one. Checking the OpenSSL source shows that
 * it does also initialise the reference count to 1.
 */
extern "C" BIO *BIO_new(const BIO_METHOD *bsslMethod) {
  return ossl.ossl_BIO_new(bio_meth_map_lookup(bsslMethod));
}
