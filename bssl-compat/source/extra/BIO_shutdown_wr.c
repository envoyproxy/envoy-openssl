#include <openssl/bio.h>
#include <ossl/openssl/bio.h>


// BIO_shutdown_wr marks |bio| as closed, from the point of view of the other
// side of the pair. Future |BIO_write| calls on |bio| will fail. It returns
// one on success and zero otherwise.
int BIO_shutdown_wr(BIO *bio) {
  return ossl_BIO_shutdown_wr(bio);
}
