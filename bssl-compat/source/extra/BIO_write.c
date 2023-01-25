#include <openssl/bio.h>
#include <ossl/openssl/bio.h>


// BIO_write writes |len| bytes from |data| to |bio|. It returns the number of
// bytes written or a negative number on error.
int BIO_write(BIO *bio, const void *data, int len) {
  return ossl_BIO_write(bio, data, len);
}
