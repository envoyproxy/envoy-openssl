#include <openssl/bio.h>
#include <ossl/openssl/bio.h>


// BIO_ctrl_get_read_request returns the number of bytes that the other side of
// |bio| tried (unsuccessfully) to read.
size_t BIO_ctrl_get_read_request(BIO *bio) {
  return ossl_BIO_ctrl_get_read_request(bio);
}
