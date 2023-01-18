#include <openssl/bio.h>
#include <ossl/openssl/bio.h>


// BIO_should_write returns non-zero if |bio| encountered a temporary error
// while writing (i.e. EAGAIN), indicating that the caller should retry the
// write.
int BIO_should_write(const BIO *bio) {
  return ossl_BIO_should_write(bio);
}
