#include <openssl/bio.h>
#include <ossl/openssl/bio.h>


// BIO_reset resets |bio| to its initial state, the precise meaning of which
// depends on the concrete type of |bio|. It returns one on success and zero
// otherwise.
int BIO_reset(BIO *bio) {
  return ossl_BIO_reset(bio);
}
