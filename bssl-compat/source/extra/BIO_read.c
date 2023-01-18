#include <openssl/bio.h>
#include <ossl/openssl/bio.h>


// BIO_read attempts to read |len| bytes into |data|. It returns the number of
// bytes read, zero on EOF, or a negative number on error.
int BIO_read(BIO *bio, void *data, int len) {
  return ossl_BIO_read(bio, data, len);
}
