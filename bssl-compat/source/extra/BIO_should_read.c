#include <openssl/bio.h>
#include <ossl/openssl/bio.h>


// BIO_should_read returns non-zero if |bio| encountered a temporary error
// while reading (i.e. EAGAIN), indicating that the caller should retry the
// read.
int BIO_should_read(const BIO *bio) {
  return ossl_BIO_should_read(bio);
}
